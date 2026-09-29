# Disaster recovery (Stages 10-11)

These are runbooks for a **deployment-hardened prototype** on synthetic data. The backup
and restore procedure below **has been restored successfully in tests**
(`tests/test_backup_restore.py`) on a local PostgreSQL 16.

It has **not** been exercised on managed cloud databases, with point-in-time recovery,
across regions, or at production data volumes. Measure those before relying on them.

## 1. What must be recoverable

| Component | Durable? | Source of truth | Backup |
|---|---|---|---|
| PostgreSQL | **yes** | events, assessments, reviews, labels, policies, deployments, model registry (paths + SHA-256), calibrations, API keys (hashes), audit log | `pg_dump` + verified restore (section 2); PITR/WAL archiving recommended |
| Model artefacts (`MODEL_DIRECTORY`) | **yes** | the files whose SHA-256 is recorded in `model_versions` | copy with the database backup (same point in time); read-only in service |
| Secrets | **yes** | the secret manager / `deploy/staging/secrets` | managed by the secret store, never in the DB dump |
| Redis | **no** | rate-limit buckets, replay claims (short-lived) | none needed (section 4) |
| Logs | platform | stderr | platform retention |

**Order of dependency.** The database and model artefacts must come from the **same
point in time**. A model row whose file is missing or different fails verification (by
design), and the service then refuses to start or falls back to MANUAL_REVIEW.

## 2. Backup and restore procedure (PostgreSQL)

```bash
# 1. Back up (custom format, compressed) + the model directory, same moment:
pg_dump --format=custom --no-owner --file backup-$(date +%F).dump "$PG_CONN"
tar -C /srv/fraud-ai -czf models-$(date +%F).tgz models
chmod 600 backup-*.dump models-*.tgz          # both contain sensitive data

# 2. Verify EVERY backup by restoring it into a scratch database and comparing:
python scripts/backup_restore_check.py \
    --source-url "$DATABASE_URL" --admin-url "$ADMIN_URL" --dump /secure/backup.dump
```

`backup_restore_check.py` works in four steps:

1. It fingerprints every table: a row count plus an order-independent content digest.
2. It dumps the database and restores the dump into a scratch database with
   `pg_restore --exit-on-error`.
3. It compares every table between source and restored copy.
4. It checks the invariants on the restored copy:
   * the active deployment hash-verifies;
   * the audit chain verifies;
   * the model registry resolves.

`tests/test_backup_restore.py` does all of the above, then **destroys** the restored
database, restores it again and re-verifies. It checks assessments, review items and
outcomes, policies (with hashes), the model registry and artefact digests, API-key records
and the audit chain. It passes.

**A backup counts as good only after it has been restored and verified.**

**To restore for real:**

1. Stop the service.
2. Create an empty database and run `pg_restore --exit-on-error --no-owner -d <new> backup.dump`.
3. Restore the model directory from the same moment.
4. Point `DATABASE_URL` at the new database.
5. Run `fraud-ai db migrate` (a no-op if the dump was already at head).
6. Run `fraud-ai audit verify`, then `fraud-ai deployment show`.
7. Start the service. Start-up validation refuses to serve if anything does not verify.

**Migration recovery.** A failed migration leaves the database at the **last good
revision**, with no half-applied tables (`tests/test_migration_recovery.py`, SQLite and
PostgreSQL). Recovery has three steps:

1. Fix the cause.
2. Re-run `fraud-ai db migrate`.
3. Take a backup before every migration in shared environments.

**Least-privilege backups (Stage 11).** Take dumps as `fraud_backup`, which has SELECT on
every table and sequence and no write privilege at all. Restore as an administrator or
`fraud_migrator`. `tests/test_pg_privileges.py::test_backup_role_dump_restores_completely`
does exactly that: a `fraud_backup` dump restores into a scratch database with every table
identical, and the backup role cannot write.

After restoring, also run `fraud-ai audit verify-anchor` (Stage 11). The restored chain
must match the external anchors up to the backup time; anchors newer than the backup
correctly report the missing events.

## 3. Database loss

* **Detection:** readiness fails (`database: failed`) and every request gets 503
  `DATABASE_UNAVAILABLE`. Alerts `FraudAIReadinessFailing` and `FraudAIDatabaseErrorSpike`
  fire.
* **Impact:** no scoring. Callers must treat 503 as "not decided" and use their own
  conservative path; they must **never** treat it as ALLOW.
* **Recovery:** restore the latest verified backup (section 2). Events received after the
  backup are lost unless the merchant re-sends them. They are idempotent by `event_id` and
  Idempotency-Key, so re-sending is safe.
* **Data between backup and failure:** PITR/WAL archiving reduces the gap. It is not set
  up by this project.

## 4. Redis loss

* **Detection:** `shared_state: failed`, 503 `STATE_UNAVAILABLE`, `fraud_state_errors_total`,
  alert `FraudAIRedisErrorSpike`.
* **Impact while down:** authenticated requests are refused (fail closed). Nothing is
  allowed without a rate-limit or replay check.
* **Recovery:** restart or replace Redis; no restore is needed. The service recovers
  without a restart (verified in the staging stack).
* **After recovery**, the state is empty:
  * **rate-limit buckets** reset, so clients briefly get a full burst;
  * **replay claims** are lost. A signed request captured in the last
    `SIGNATURE_MAX_AGE` seconds (300 s) could be replayed once. Idempotency-Key and
    per-event uniqueness in PostgreSQL still prevent duplicate assessments, reviews and
    step-up follow-ups. To close even that window, keep the service refusing traffic for
    `SIGNATURE_MAX_AGE` seconds after Redis comes back empty.

## 5. Model artefact loss or corruption

* **Detection:**
  * readiness `primary_model: failed`, after re-verification on change or every 300 s;
  * `fraud_model_verification_failures_total`;
  * alert `FraudAIModelArtifactVerificationFailure`;
  * a fresh worker falls back to `MANUAL_REVIEW` (`fallback_used`).
* **Never** "fix" a digest mismatch by updating the recorded SHA-256. A mismatch means the
  file is not the trained model: tampering or corruption.
* **Recovery:**
  1. Restore the directory from the backup taken with the database.
  2. Check that `fraud-ai service status` reports `primary_model: ok` (full SHA-256
     verification).
  3. Restart the workers.
  4. If the artefact cannot be recovered, activate a policy whose models still verify
     (`fraud-ai deployment activate`, promotion rules apply), or retrain and go through
     promotion again.

## 6. Signing-key compromise (`SERVICE_SIGNING_MASTER_KEY`)

The master key derives every key's request-signing secret. Its compromise lets an attacker
sign requests for any key whose bearer token they also hold.

1. Generate a new master key.
2. Deploy it with `SERVICE_SIGNING_KEY_VERSION` incremented.
   * **Do not** keep the compromised key as `SERVICE_SIGNING_PREVIOUS_KEY`. A grace period
     is for planned rotation, not compromise.
   * If a short overlap is unavoidable, set `SERVICE_SIGNING_PREVIOUS_KEY_EXPIRES_AT` to
     minutes, not hours.
3. Hand each integration its new secret: `fraud-ai service-key signing-secret <key-id>`.
4. Watch `fraud_api_signatures_verified_total{key_version}` and
   `fraud_api_signature_failures_total`.
5. Review `fraud-ai audit list` and access logs for the exposure window.
6. Rotate the API keys too (section 7) if bearer tokens may also have leaked.

## 7. API-key compromise

1. Revoke it immediately: `fraud-ai service-key revoke <key-id>`. Revocation is immediate
   in every worker, because it is checked in the database on each request.
2. Issue a replacement: `fraud-ai service-key create …` (or, for a planned change,
   `fraud-ai service-key rotate <key-id> --grace-hours 0`).
3. Check `service-key list` (last used, status) and `audit list` for what the key did.
4. Review the assessments made with the key. Assessments are immutable; mistaken outcomes
   are corrected through reviews and labels, never by editing history.

## 8. Payment provider outage

* **Impact:**
  * a step-up request fails (provider unavailable or timeout);
  * the original assessment stays as it was (`STEP_UP_AUTHENTICATION` or review);
  * **nothing becomes ALLOW** (`test_provider_failures_are_never_an_allow`);
  * callbacks that arrive late are still verified and applied only to pending requests.
* **Actions:**
  * the merchant falls back to WebAuthn step-up or manual review;
  * watch `fraud_api_stepup_results_total`;
  * after recovery, pending requests can be polled (`GET /v1/step-up/payment/{id}`).
* **Webhook-secret compromise:**
  1. Rotate `PAYMENT_AUTH_WEBHOOK_SECRET` at the provider and here.
  2. Review the step-up results in the exposure window.

## 9. Pseudonymisation-key loss or compromise

* **Loss:** new events can no longer be linked to existing hashed identifiers, which
  degrades features. The key **must** be backed up in the secret store; it is not in the
  database dump.
* **Compromise:** hashed IPs (a small space) become brute-forceable. There is no
  re-keying tool yet (Stage 11). The mitigation today is keeping raw IP storage off and
  limiting database access.

## 10. Stage 11 key compromise

* **Model signing key.** Anyone holding it can sign a malicious artefact, and pickles run
  code (TRUST_CHAIN.md §4).
  1. Remove its public key from `MODEL_SIGNING_PUBLIC_KEYS` everywhere and restart. Every
     model it signed now fails closed (not loaded; conservative fallback).
  2. Generate a new key (`fraud-ai keys generate --purpose model`).
  3. Re-sign only artefacts whose provenance you can re-establish: files restored from a
     trusted backup, or retrained.
  4. Check with `fraud-ai models verify-signature`.
* **Audit anchor key.** A thief can forge anchors but cannot change the database.
  1. Rotate the key and anchor again with the new one.
  2. Distrust anchors created during the exposure window.
  3. Compare them against an independent copy of the anchor store.
* **Release signing key.** Rotate it, re-issue the manifests that matter, and treat
  manifests signed in the exposure window as unverified.
* **Operator identity (`OPERATOR_ID`) misuse.**
  1. Review `fraud-ai policy approvals <version>` and `audit list` for `policy.approved` and
     `policy.activated`.
  2. Roll back to a known-good policy by activating it again. This itself needs two
     approvals in production.
  3. Tighten `OPERATOR_ALLOWLIST`.
* **`fraud_migrator` credential.** It owns the schema and could drop triggers or rewrite
  history.
  1. Rotate the password immediately.
  2. Run `audit verify-anchor`.
  3. Check that the triggers still exist (`\dS audit_events`).
  4. Re-run `fraud-ai db grant-roles`.

## 11. Drills

Before relying on any of this outside a test environment:

* run section 2 against the real database size and time it;
* practise sections 6 and 7 in staging (`tests/test_hardening.py` covers the mechanics);
* record each drill with its date and results in the release notes (RELEASE_CHECKLIST.md).
