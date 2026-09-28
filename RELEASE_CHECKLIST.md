# Release checklist (Stage 10)

Use this for any build that leaves a developer machine (staging or a test deployment).
Every item needs its **evidence**: the command output or CI run link, recorded in the
release notes. Passing this checklist still does **not** make the system production-ready,
and it is not a PCI DSS, GDPR or SOC 2 assessment.

## 1. Code and tests

- [ ] CI `lint` green: `ruff check .`, `ruff format --check fraud_ai tests migrations`,
      `mypy`.
- [ ] CI `test` green on SQLite **and** PostgreSQL + Redis, including
      `test_multiprocess`, `test_backup_restore`, `test_migration_recovery`, `test_chaos`
      and `test_staging_e2e`. Coverage ≥ 95 %.
- [ ] No test skipped, disabled or quarantined to get green.
- [ ] Migration head recorded (currently `0008`); `fraud-ai db migrate` on a copy of the
      target database succeeds; a backup was taken before migrating.

## 2. Security

- [ ] `python scripts/security_checks.py pip-audit`: 0 unignored findings. Any ignore in
      `security/pip-audit-ignore.txt` has a reason and a review date.
- [ ] `python scripts/security_checks.py bandit`: no MEDIUM/HIGH; every `# nosec` has a
      reason.
- [ ] `python scripts/security_checks.py secrets`: 0 new findings. Baseline changes were
      reviewed line by line.
- [ ] gitleaks over the full history: no leaks.
- [ ] SBOM generated for this commit (`sbom/fraud-ai.cdx.json` or the CI artefact).
- [ ] Container built with PyTorch (the real image, **not** `WITH_TORCH=0`);
      `scripts/container_checks.sh <image>` OK.
- [ ] Trivy HIGH/CRITICAL list reviewed. Each finding is fixed, or recorded with "no fix
      available / not reachable because …". **Nothing is hidden or silenced.**
- [ ] THREAT_MODEL.md reviewed for changes in this release.

## 3. Configuration

- [ ] `ENVIRONMENT=staging` (or `production`) and `fraud-ai config check` pass with the
      real settings.
- [ ] Secrets come from the secret store / `*_FILE`. None are default-looking, and none
      are shared with another environment.
- [ ] `STATE_BACKEND=redis` for more than one worker or instance; Redis requires a
      password and is not publicly reachable.
- [ ] `SERVICE_REQUIRE_SIGNATURES=true`; `TRUSTED_PROXIES` contains only the TLS proxy.
- [ ] Payment provider: the fake is **only** in staging, with
      `PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true`, and marked as a fake in the release
      notes. Stripe uses test-mode keys only.
- [ ] `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` × workers × instances fit PostgreSQL
      `max_connections` with a margin.
- [ ] `POLICY_REQUIRE_PROMOTION` on; the active policy reached `candidate` through
      `policy promote`, and its evidence is recorded.

## 4. Operations

- [ ] Backup taken **and restored successfully**: `scripts/backup_restore_check.py` output
      attached. The model directory was backed up at the same time.
- [ ] `/v1/ready` 200 on every instance; alerts from `deploy/monitoring/alerts.yml`
      loaded and routed.
- [ ] `fraud-ai audit verify` OK; the `service.configuration` event for this start is
      present.
- [ ] Retention: `fraud-ai retention plan` reviewed; destructive runs remain opt-in.
- [ ] Performance: `scripts/check_regression.py benchmarks/baseline.json <new>` on a
      comparable machine shows no flagged regression, or the regression is explained.
- [ ] End-to-end: `scripts/staging_e2e.py` against the deployed staging URL passed.
- [ ] DISASTER_RECOVERY.md drills for this release recorded (date, result).

## 5. Communication

- [ ] Release notes state: synthetic evaluation only; no fraud-reduction or savings
      claims; no compliance claims; known limitations (HARDENING.md section 22).
