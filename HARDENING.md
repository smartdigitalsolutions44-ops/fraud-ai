# Deployment hardening (Stages 10-11)

This stage prepares fraud-ai for **real deployment testing** (staging, load and failure
testing on non-production infrastructure). The result is a **deployment-hardened
prototype**. It is not production-ready.

**Not claimed:**

* production readiness;
* PCI DSS, GDPR or SOC 2 compliance;
* real-world fraud reduction or financial savings.

All data, models, benchmarks and decisions here are **synthetic**.

Stage 11 (trust, integrity, privacy and real-integration gaps) is in §23-§26; the trust
mechanisms are described in [TRUST_CHAIN.md](TRUST_CHAIN.md) and privacy in
[PRIVACY.md](PRIVACY.md). The result is a **security-hardened prototype**. It is still not
production-ready.

Related documents:

* [THREAT_MODEL.md](THREAT_MODEL.md): assets, threats, mitigations, remaining risk;
* [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md): backup, restore and incident runbooks;
* [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md): what must be green before a release;
* [DEPLOYMENT.md](DEPLOYMENT.md) and [SERVICE_SECURITY.md](SERVICE_SECURITY.md).

---

## 1. Shared state (Redis)

Several workers or instances must share two kinds of short-lived state:

* **rate-limit buckets;**
* **single-use claims:** signed-request and callback replay protection.

Durable history stays in PostgreSQL, never in Redis. That covers assessments, reviews,
labels, audit events, policy and model history.

`fraud_ai/state/` defines one protocol, `SharedState`, with two backends:

| Backend | `STATE_BACKEND` | Use |
|---|---|---|
| `MemoryState` | `memory` (default) | one process: development, tests, a single worker |
| `RedisState` | `redis` + `REDIS_URL` | several workers/instances (**required** in staging/production with more than one worker) |

Every Redis operation is **atomic on the server**:

* **token bucket:** a Lua script. It uses the server's `TIME` (no client clock skew) and
  sets an idle TTL, so abandoned buckets disappear.
* **claim:** `SET key 1 NX PX ttl`. Exactly one caller wins. The key expires with the
  signature's validity window.
* **lock:** `SET NX PX`; released only by its owner, through a compare-and-delete script.

Other properties:

* **Keys** are prefixed with `REDIS_KEY_PREFIX` and hashed. No API key, signature or
  personal data is stored in clear.
* **Timeouts:** `REDIS_TIMEOUT`, default 0.5 s.
* **Errors fail closed.** Any Redis error or timeout raises `StateUnavailableError`. The
  request is then refused with **503 `STATE_UNAVAILABLE`**; it is never allowed without a
  rate-limit or replay check. Readiness reports `shared_state: failed`.
* **Metrics:** `fraud_state_operation_seconds{op}` and `fraud_state_errors_total{op}`.

**Redis loss is harmless for durability.** Losing Redis only resets rate-limit buckets and
replay claims. Replayed requests still hit the database idempotency and uniqueness rules
(see DISASTER_RECOVERY.md). Redis runs without persistence in the staging stack.

## 2. Distributed rate limiting and replay protection

**Rate limiting.** `SharedStateRateLimiter` runs one bucket per API key and route, and one
per client address for unauthenticated callbacks. It uses the same `RATE_LIMIT` and
`RATE_LIMIT_BURST` as before.

Test evidence:

* `tests/test_state.py::test_distributed_rate_limit_across_processes`: several OS
  processes on one Redis bucket together admit exactly `burst` requests.
* `tests/test_multiprocess.py`: against 3 uvicorn workers, 150 concurrent requests admit
  100–112. That is the burst plus the refill during the burst; the rest get 429.

**Replay protection.** With the Redis backend, a verified signature is claimed under
`sha256(key id | signature)` for its remaining validity window (`remember_shared`).
Exactly one worker accepts it; the others return 401.

Tests:

* `tests/test_state.py::test_signature_accepted_by_one_worker_is_rejected_by_another`;
* `tests/test_state.py::test_distributed_replay_claim_across_processes` (a race: 1 winner);
* `tests/test_multiprocess.py`: 10 concurrent copies of one signed request give 1 × 200
  and 9 × 401;
* after a worker is SIGKILLed and restarted, the old signature is still refused. The claim
  lives in Redis, not in the worker.

With the memory backend, the Stage 9 database table `request_replay_tokens` is still used
(correct for one process).

## 3. API keys: expiry, use tracking, rotation

Migration `0008` adds `expires_at`, `last_used_at` and `rotated_from_key_id` to
`service_api_keys`.

**Status** is `active`, `expired` or `revoked`, derived by `ServiceApiKey.status_at(now)`.

**Expired keys fail exactly like unknown or revoked keys.** They get the same 401
`UNAUTHENTICATED` body and the same constant-time hash work. The reason is never returned;
the service logs only the key id. See `test_expired_keys_fail_like_unknown_keys`.

`last_used_at` is updated at most once a minute per key, so every request does not write.
A failed update never fails the request.

**Rotation:**

```bash
fraud-ai service-key rotate <key-id> [--grace-hours 24] [--expires-in-days 90]
```

* The command prints the new credential **once**.
* The old key is set to expire after the grace period, default
  `SERVICE_KEY_ROTATION_GRACE_HOURS=24`, so integrators can switch.
* The old secret is never printed again. Only its salted hash was ever stored.
* The new key records `rotated_from_key_id`.
* Both `rotate` and `revoke` write audit events.

## 4. Signing-key rotation

* **Versions.** Request signatures are derived from a master key per key version,
  `SERVICE_SIGNING_KEY_VERSION` (default `1`).
* **Rotation.** Move the old master key to `SERVICE_SIGNING_PREVIOUS_KEY`, with its
  `..._PREVIOUS_KEY_VERSION` and `..._PREVIOUS_KEY_EXPIRES_AT`, and install a new current
  key.
* **Verification.** Signatures verify against the current key and, until the expiry,
  against the previous one. Clients may send `X-Fraud-Key-Version` to select one.
* **Metrics.** `fraud_api_signatures_verified_total{key_version}` shows when old-key traffic
  has stopped.
* **Validation.** The previous key needs a version and an expiry, and must differ from the
  current key in both secret and version.
* **Handing out secrets.**
  `fraud-ai service-key signing-secret <key-id> [--previous]` prints a key's derived secret
  for either master key.
* **Fail closed.** If `SERVICE_REQUIRE_SIGNATURES=true` but no signing key is configured,
  every request gets **503 `SIGNING_UNAVAILABLE`**. It is never accepted unsigned.

## 5. Secret management

Each secret is read from the environment **or** from a file named by `NAME_FILE`, for
example `/run/secrets/...`. The secrets are:

* `PSEUDONYMISATION_KEY`;
* `SERVICE_SIGNING_MASTER_KEY` and `SERVICE_SIGNING_PREVIOUS_KEY`;
* `PAYMENT_AUTH_WEBHOOK_SECRET` and `STRIPE_API_KEY`;
* `REDIS_URL` and `DATABASE_URL`.

Setting both `NAME` and `NAME_FILE` is refused.

Rules for a secret file:

* a regular file of at most 16 KiB, not empty;
* one trailing newline is stripped;
* group- or world-readable files are logged as a warning.

Secrets are `SecretStr` and never logged. The configuration audit event records only
whether each secret is *present*.

**Cloud secret managers.** No cloud SDK is bundled, and none of these integrations was
tested. Use the platform's native injection into files or environment variables:

* **AWS:** Secrets Manager or SSM Parameter Store. Use ECS/EKS secret injection, or the
  Secrets Store CSI driver mounting files, then `NAME_FILE=`.
* **Azure:** Key Vault through the CSI driver (files), or App Service/Container Apps Key
  Vault references (environment).
* **GCP:** Secret Manager through Cloud Run secret volumes/env, or the CSI driver on GKE.

`fraud_ai/config/secrets.py` defines a `SecretsProvider` protocol, implemented by
`EnvSecretsProvider` and `FileSecretsProvider`. An SDK-backed provider could be added there
later without touching the rest of the code.

## 6. Configuration profiles and fail-closed start-up

`ENVIRONMENT` is one of `development`, `test`, `staging` or `production`.

**Settings validation**, for every command:

* staging and production require PostgreSQL;
* the fake payment provider is refused in production. Staging accepts it only with
  `PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true`.
* Stripe accepts only test-mode keys;
* the previous-signing-key rules (section 4) apply;
* the Redis backend needs `REDIS_URL`.

**Service start-up validation** (`Settings.service_problems()` and
`fraud_ai/service/startup.py`) runs in every worker before it serves anything.

In staging and production it refuses:

* a non-https WebAuthn origin;
* placeholder or default-looking secrets. "Default-looking" means:
  * a word such as `changeme`, `example`, `password`, `secret` or `fraud_ai_dev`;
  * fewer than 12 characters;
  * or fewer than 8 distinct characters.
* a default-looking database or Redis password;
* CORS `*` or non-https origins;
* several workers with the per-process memory state.

Production also refuses:

* the reference LLM template, unless `ALLOW_REFERENCE_LLM=true`;
* unsigned requests (`SERVICE_REQUIRE_SIGNATURES` must be true).

Readiness must also pass, in **every** profile:

* database;
* migrations at head;
* an active, hash-verified policy;
* the primary model artefact present and SHA-256-verified;
* Redis, when configured;
* the signing key, when signatures are required.

After validation the worker:

1. loads and verifies the active, shadow-policy and shadow models into its own cache;
2. writes a `service.configuration` audit event when the configuration fingerprint changed.

Any failure raises `ServiceConfigurationError` and the worker never serves. See
`test_startup_fails_closed` and the container smoke test in section 12.

To check a configuration without starting anything, run `fraud-ai config check`.

Other profile defaults:

* JSON logs in staging and production;
* `POLICY_REQUIRE_PROMOTION` on in staging and production.

**Known behaviour.** With `--workers > 1`, uvicorn's supervisor keeps restarting a worker
that refuses to start. Nothing is served and the container health check stays unhealthy,
but the parent process does not exit. Orchestrators should alert on readiness and
restarts. This was observed in the staging stack before its database was bootstrapped.

## 7. Readiness hardening

`GET /v1/ready` returns these checks:

* `database` (with `fraud_db_ping_seconds`);
* `migrations`;
* `active_policy`;
* `primary_model`;
* `shared_state` (`ok`, `failed` or `not_required`);
* `signing_key`;
* `llm` (always `not_required`: scoring never needs it).

**Primary-model re-verification.** The primary artefact is fully re-verified and loaded
when its files change (names, sizes, mtimes) or every `READINESS_REVERIFY_SECONDS` (300 s).
Failures are counted in `fraud_model_verification_failures_total`, and the check reads
`failed`. See `test_readiness_detects_artifact_deletion_and_corruption`.

## 8. Fail-closed matrix

| Failure | Scoring (`POST /v1/score`) | Other routes | Readiness | Evidence |
|---|---|---|---|---|
| PostgreSQL down | 503 `DATABASE_UNAVAILABLE` | 503 `DATABASE_UNAVAILABLE` | 503 (`database: failed`) | `test_chaos::test_database_unavailable`; staging stack |
| Pool exhausted (`DB_POOL_TIMEOUT`) | 503 `DATABASE_UNAVAILABLE` | 503 | 503 while exhausted | `test_chaos::test_connection_pool_exhaustion` |
| Slow DB (beyond `SERVICE_REQUEST_TIMEOUT`) | 503 `SCORING_TIMEOUT` with `fallback_decision: MANUAL_REVIEW` | – | – | `test_chaos::test_slow_database_times_out_to_review` |
| Redis down (`STATE_BACKEND=redis`) | 503 `STATE_UNAVAILABLE` | 503 `STATE_UNAVAILABLE` | 503 (`shared_state: failed`) | `test_state::test_redis_outage_fails_closed`; staging stack |
| Signing key missing, signatures required | 503 `SIGNING_UNAVAILABLE` | 503 | 503 (`signing_key`) | `test_chaos::test_signing_key_missing_fails_closed` |
| Model artefact deleted/corrupted (fresh worker) | 200, `MANUAL_REVIEW`, `fallback_used: true` | – | 503 (`primary_model: failed`) | `test_chaos::test_*_artifact_in_a_fresh_process_falls_back` |
| Artefact changed while running | cached verified model keeps scoring | – | 503 after re-verification | `test_hardening_world` |
| Payment provider down/timeout | step-up request fails; assessment unchanged | – | – | `test_service_flows`, `test_stripe_provider` |
| Payment callback: bad signature / expired / replayed | 401, nothing changes | – | – | `test_service_flows`, `test_stripe_provider` |
| Payment callback: unknown reference | 404, nothing changes | – | – | `test_service_flows` |
| Payment callback: non-terminal event | 200 `accepted: false, status: ignored`, no state change | – | – | `test_stripe_provider` |
| Worker killed | supervisor restarts it; replay and idempotency invariants hold | – | – | `test_multiprocess` |
| LLM unavailable | scoring unaffected | investigate: 503 | `llm: not_required` | Stage 7 tests; staging E2E |
| Invalid configuration | service does not start | – | – | `test_startup_fails_closed` |

No row ever produces an ALLOW. Fallback decisions are counted in
`fraud_api_fallbacks_total{category}`.

## 9. Retention jobs

`fraud_ai/retention.py` and the CLI:

```bash
fraud-ai retention plan                # what would be removed (counts only)
fraud-ai retention run                 # dry run (default)
fraud-ai retention run --execute --yes # destructive; also needs RETENTION_ALLOW_DELETE=true or an interactive confirmation
fraud-ai retention status              # last runs (from the audit log)
```

| Category | Action | Default |
|---|---|---|
| `replay_tokens` | delete expired replay tokens | always (useless after expiry) |
| `idempotency` | delete completed Idempotency-Key records, and in-progress placeholders older than 1 h | 7 days |
| `webauthn_challenges` | delete expired challenges not referenced by any attempt | 7 days |
| `payment_requests` | delete terminal payment requests not referenced by any attempt | disabled (0) |
| `failed_attempts` | delete non-terminal failed attempts without a follow-up | disabled (0) |
| `raw_ip` | set raw IP to NULL (keyed hash kept) | 30 days |
| `log_files` | not applicable (logs go to stderr) | – |

**Never deleted:**

* events and risk assessments;
* model, calibration and prediction history;
* policies, deployments and lifecycle events;
* fraud labels, review items and review outcomes;
* investigations;
* audit events.

There is no code path that deletes them (`PROTECTED_TABLES`). Every run, dry or not, is
audited (`retention.run`) with its per-category counts.

## 10. Audit log

The `audit_events` table (migration 0008) is append-only and hash-chained.

**Record format.** Each record holds:

* a sequence number;
* the action and the actor (`cli:<os-user>`, `api_key:<key-id>`, `service:startup`);
* the target and a timestamp;
* JSON details;
* the previous record's hash;
* a SHA-256 over the canonical JSON of all of these.

**Recorded actions:**

* `service_key.created`, `service_key.revoked` and `service_key.rotated`;
* `policy.activated` (who activated it, also stored on the deployment) and
  `policy.promoted`;
* `review.resolved`, through the API or the CLI;
* `retention.run`;
* `service.configuration`.

**Immutability.** Database triggers refuse `UPDATE` and `DELETE`: a plpgsql function on
PostgreSQL, `RAISE(ABORT)` on SQLite. A PostgreSQL advisory lock serialises appends, so
the chain has no forks.

**Verification.** `fraud-ai audit verify` recomputes the chain. It reports edited rows,
broken links and sequence gaps. `fraud-ai audit list` shows the events.

**No secrets.** Detail keys that look secret (`*_secret`, `password`, `token`, `api_key`,
`signature`, …) are refused outright. Values pass through log redaction.

**Limit.** A database superuser can drop the triggers and rewrite the chain consistently.
Ship the chain head, or the events themselves, to an external write-once store
(recommended for Stage 11; see THREAT_MODEL.md).

## 11. Policy activation safety and promotion

`deployment activate` refuses:

* a missing model;
* an artefact that fails verification;
* a model trained on another feature catalogue;
* **active or shadow models whose `feature_version` differs from the primary's**;
* a missing or mismatched calibration;
* a changed rule set;
* when promotion is required (staging/production default), a policy that is not a
  promoted `candidate`.

The activating actor is stored (`policy_deployments.activated_by`) and audited.

Promotion is explicit, one step at a time, and never automatic:

```bash
fraud-ai deployment activate <current> --shadow-policy <new>   # run <new> in shadow
fraud-ai policy promote <new> --to shadow --note "..."          # must be a shadow of the active deployment
fraud-ai policy promote <new> --to evaluation --note "..."      # stores a simulation summary as evidence
fraud-ai policy promote <new> --to candidate --approve --note "..."  # explicit approval + note
fraud-ai deployment activate <new>                               # separate, explicit step
fraud-ai policy history <new>
```

Promotion rules:

* stages cannot be skipped;
* a `rejected` policy is final;
* the active policy cannot be promoted;
* every step is stored in `policy_lifecycle_events` and audited.

**First deployment.** The very first deployment has nothing to shadow. It is activated
with `POLICY_REQUIRE_PROMOTION=false` (or the library call) and is audited.

This whole flow was exercised in the staging stack (section 12). Simulation evidence is
**synthetic** and is labelled so.

## 12. Staging deployment

`deploy/staging/docker-compose.staging.yml` runs:

* PostgreSQL 16;
* Redis 7, with a password and no persistence;
* a one-shot migration;
* fraud-ai, with 2 workers, `STATE_BACKEND=redis` and required signatures;
* a Caddy TLS proxy (`tls internal`, published on 127.0.0.1 only);
* optionally, a separate LLM service (profile `llm`).

Secrets are files generated by `deploy/staging/generate-secrets.sh`:

* read through `*_FILE`;
* 0400 and owned by uid 10001 when the script runs as root;
* git-ignored.

The containers run with `read_only`, `cap_drop: [ALL]`, `no-new-privileges` and an
internal-only data network. The fake payment provider is enabled explicitly and marked as
a development fake.

**Run on this machine** with the torch-less verification image (section 16), synthetic data:

| Step | Result |
|---|---|
| migrate | 0008 applied |
| start without a policy/model | refused (fail closed), health check unhealthy |
| in-stack bootstrap (seed, train GB + LR, 2 policies, first deployment) | OK |
| `/v1/ready` through TLS | 200, every check `ok` (incl. `shared_state`, `signing_key`); HSTS and `nosniff` present |
| `scripts/staging_e2e.py` through the proxy | **ok**: signed policy read; scoring (2 step-ups, 1 review); payment step-up + signed callback → `ALLOW_WITH_MONITORING` follow-up; replayed callback 401; review resolved; investigation 503 (no LLM configured); metrics. 429s were honoured via `Retry-After`. |
| promotion in-stack | activation without promotion refused; shadow → evaluation → candidate (`--approve` required) → activate; `audit verify` OK (7 events) |
| Redis stopped | ready 503 (`shared_state: failed`); API 503 `STATE_UNAVAILABLE`; recovered on restart without a service restart |
| PostgreSQL stopped | ready 503; API 503 `DATABASE_UNAVAILABLE`; recovered on restart |
| logs | JSON; no database/Redis URL, secret or credential found |
| memory | fraud-ai (2 workers, torch-less) 391 MiB; PostgreSQL 72 MiB; Redis 4 MiB; Caddy 12 MiB |

The pytest `tests/test_staging_e2e.py` runs the same script in-process. It uses a staging
profile, PostgreSQL with a non-default role, Redis and 2 workers, and includes the
**WebAuthn** step-up with a test-only software authenticator. It passed; CI runs it.

## 13. Performance (PostgreSQL)

**Setup:** synthetic traffic on a 4-vCPU / 15 GB cloud container, with PostgreSQL 16 and
Redis 7 on the same machine. `scripts/pg_load_benchmark.py` drives uvicorn workers with
16 clients, no keep-alive, and signed requests. Raw output is in
`benchmarks/stage10_pg_load.json`.

**These numbers are not an SLA.** They are a baseline for detecting regressions.

| Workers | req/s | p50 | p95 | p99 | errors | peak DB conns | pool saturation | DB stage p50 | startup |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 20.4 | 31 ms | 120 ms | 134 ms | 0 | 3 | 0.20 | 53 ms | 4.7 s |
| 4 | **45.5** | 42 ms | 164 ms | 228 ms | 0 | 6 | 0.10 | 69 ms | 5.7 s |
| 8 | 42.8 | 64 ms | 262 ms | 2876 ms | 0 | 10 | 0.08 | 93 ms | 10.7 s |
| 16 | 33.9 | 94 ms | 829 ms | 7175 ms | 0 | 18 | 0.07 | 120 ms | 20.6 s |

Reading:

* **Scoring is CPU-bound.** Feature extraction, the models, and the GIL within each worker
  set the limit. The best result was **about 4 workers per 4 CPUs**.
* **More workers only add contention.** Throughput falls, p99 grows to seconds, and
  start-up takes longer: each worker loads and verifies its own model cache.
* **The pool is not the bottleneck.** Peak connections are about 1–1.3 per worker.
* A run with `OMP_NUM_THREADS=1` gave 47.7, 51.2 and 34.5 req/s at 4, 8 and 16 workers.
  That is slightly better at 8 workers but not a different picture.
* **The SQLite comparison is only indicative** (Stage 9, same machine). Direct calls gave
  48–55 req/s; HTTP gave about 39–50 req/s with one writer. PostgreSQL's value is
  multi-process correctness and durability, not raw single-node speed.

**Pool tuning** (measured, not guessed). 8 workers, 16 clients, `DB_POOL_TIMEOUT=2`:

| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | req/s | error rate | saturation |
|---|---|---|---|
| 1 / 0 | 49.2 | **3.5 %** (503, and 422 follow-ups on the failed requests) | 1.25 |
| 2 / 0 | 54.2 | **1.7 %** | 0.62 |
| 5 / 0 | 51.6 | 0 | 0.25 |
| 5 / 10 (default) | 49.4 | 0 | 0.08 |
| 10 / 10 | 50.9 | 0 | 0.06 |

**Recommendation:** keep `DB_POOL_SIZE=5`, `DB_MAX_OVERFLOW=5..10` per worker, and size
PostgreSQL `max_connections` above `instances × workers × (pool + overflow)`, plus a
migration and admin margin. Pool exhaustion fails closed (503), never open. The staging
stack uses 5/5.

**Model cache** (`scripts/model_cache_benchmark.py`, `benchmarks/stage10_model_cache.json`):

* verified load: gradient boosting 14–18 ms, logistic regression about 3.5 ms, GRU about
  1.5 s. The GRU cost is mostly the PyTorch import, +467 MB RSS.
* SHA-256 verification of an artefact: ≤ 0.5 ms;
* per worker: RSS about 173 MB before loading and about 650 MB after. Under load it was
  about 850 MB per worker with the GRU;
* each worker holds its **own** cache; models are never shared between processes;
* memory planning: `workers × ~850 MB` with PyTorch models, or about 200 MB per worker
  with the scikit-learn models only.

**Regression baseline.** `benchmarks/baseline.json` holds 20 metrics.
`scripts/check_regression.py` flags only large regressions:

* latency: more than +35 % **and** more than +5 ms;
* throughput: more than −25 %;
* memory: more than +30 % **and** more than +50 MB.

Timing noise therefore does not fail anything. CI does not run benchmarks; they need a
quiet, comparable machine.

## 14. Multi-process and chaos results

`tests/test_multiprocess.py` (3 uvicorn workers, PostgreSQL + Redis) passed:

| Invariant | Result |
|---|---|
| signed-request replay (10 concurrent copies) | 1 accepted, 9 × 401 |
| Idempotency-Key (concurrent duplicates) | one decision, one assessment row |
| review creation (8 redeliveries of a review-worthy event) | 1 review item |
| WebAuthn challenge consumption (6 concurrent verifies) | 1 success, 5 × 409; 1 follow-up assessment |
| distributed rate limit (150 concurrent) | 100–112 admitted, the rest 429 |
| model cache | each worker loads and verifies its own; all ready |
| worker SIGKILL | restarted; invariants hold; old signature still refused |

Chaos tests are in section 8. All 6 in `tests/test_chaos.py` pass, plus the Redis, provider
and worker cases elsewhere.

## 15. Dependency, code and secret scanning; SBOM

All four checks run through one entry point, `scripts/security_checks.py`, and CI job
`security`.

* **Dependency audit** (`pip-audit` over the service's pinned dependency closure: 70
  packages, extras `postgres` and `stripe`):
  * the first run found `idna 3.11` (PYSEC-2026-215) and `urllib3 2.6.3`
    (PYSEC-2026-141/142);
  * both were upgraded (`idna>=3.15` as a dependency; `urllib3>=2.7.0` in the `stripe`
    extra) and are installed as idna 3.20 and urllib3 2.8.0;
  * re-audit: **0 findings**; the ignore list `security/pip-audit-ignore.txt` is empty.
  * **Upgrade plan:** run the audit in CI on every push; fix by raising floors; any ignore
    needs a written reason.
* **Static analysis** (`bandit`, configured in `pyproject.toml`; tests, migrations and
  scripts excluded; B101 `assert` skipped):
  * the first run gave 11 LOW findings and no MEDIUM/HIGH;
  * each was triaged. Most were constant enum labels named `PASSWORD*` (B105), the
    fixed-argv llama.cpp subprocess (B404/B603), and non-cryptographic `random` in the
    synthetic-data generator (B311).
  * each is suppressed at the line with a reason;
  * the result is **0 findings**.
* **Secret scanning:**
  * `detect-secrets` scans tracked and untracked files against a reviewed
    `.secrets.baseline` of 32 entries. Every entry was reviewed: placeholders, test-only
    values, hashes, the CI throwaway password, and PEM header constants.
  * `gitleaks` 8.21.2 scanned the **whole git history** and the working tree. Its first
    runs found only synthetic test values and a compiled `.pyc`. `.gitleaks.toml`
    allow-lists exactly those, and both scans are now clean.
  * credential-shaped test literals (for example Stripe-style keys) were replaced by
    concatenated or obviously fake values.
* **SBOM:** CycloneDX JSON, `sbom/fraud-ai.cdx.json`, 70 components. It is generated
  deterministically from the same closure with `security_checks.py sbom`, and CI uploads it
  as an artefact.

## 16. Container image

**The real image could not be built here.** It installs CPU-only PyTorch from
`download.pytorch.org`, which this build environment blocks (HTTP 403). The CUDA wheels
from PyPI do not fit the disk.

The Dockerfile now has two build arguments:

* `TORCH_INDEX_URL`, for a mirror;
* `WITH_TORCH=0`, a **verification variant without PyTorch**. It serves only the
  scikit-learn models; a neural active model fails start-up, as verified. It is never to
  be deployed as the real image.

**Built and tested:** `docker build --build-arg WITH_TORCH=0 .` (BuildKit).

Changes in this stage:

* wheels are **bind-mounted** into the install step, not copied. Before, they left an
  86 MB dead layer in the image.
* `pip`, `setuptools` and `wheel` are **removed** from the runtime image. Nothing installs
  packages at runtime, and they carried the image's only Python-level HIGH findings.
* the image includes the `stripe` extra.

**Size** (verification variant):

* 732 MB on disk, 163 MB compressed;
* the base `python:3.11-slim` is about 120 MB compressed;
* largest contributors: scipy (113 MB + 30 MB libs), scikit-learn (51 MB), numpy (45 MB
  + 28 MB libs), SQLAlchemy (29 MB), stripe (25 MB), cryptography (16 MB), psycopg
  (20 MB);
* the real image adds CPU PyTorch, **estimated** (not measured here) at 0.7–1 GB more on
  disk.

**`scripts/container_checks.sh`** passes:

* uid/gid 10001, non-root;
* `/v1/health` HEALTHCHECK present;
* no `.git`, `.env`, databases, model or LLM artefacts;
* no private-key material. Public CA bundles are expected;
* no secrets in the image environment or layer history;
* starts with `--read-only --cap-drop ALL --security-opt no-new-privileges`;
* the root filesystem is not writable.

**Smoke tests:**

* `db migrate` in the container against PostgreSQL;
* the service serving `/v1/ready` = 200 with a gradient-boosting policy;
* a torch model in the active set refused at start-up;
* the production profile with placeholder secrets refusing to start, listing 4 problems.

**Trivy** 0.58.1 (vulnerability DB of 2026-09-27) on the verification image:

| Layer | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| Debian 13.7 base packages | 0 | **44** (8 unique CVEs) | 53 | 57 (+2 unknown) |
| Python packages | 0 | 0 | 0 | 0 |

Before `pip`, `setuptools` and `wheel` were removed, the Python layer had 2 HIGH findings:
`jaraco.context` CVE-2026-23949 and `wheel` CVE-2026-24049, both vendored in setuptools.
It also had 6 MEDIUM findings: pip ×5 and setuptools ×1.

**Every remaining HIGH has no fixed Debian package yet:**

* CVE-2025-69720 in ncurses;
* CVE-2026-16742 in the systemd libraries (systemd-homed);
* CVE-2026-54369 in libacl1;
* CVE-2026-76642, CVE-2026-78408, CVE-2026-78409 and CVE-2026-78410 in util-linux (mount,
  nsenter);
* CVE-2026-9538 in perl-base (Archive::Tar DoS).

None is reachable through the service's own code path: it does not mount, run `nsenter`,
use homed or process tar archives. They are **reported, not hidden**. The release gate
(RELEASE_CHECKLIST.md) requires rebuilding on a patched base as fixes appear, and
re-assessing. A distroless or minimal base would remove most of them; that is recommended
for Stage 11.

## 17. Backup, restore and migration recovery

See DISASTER_RECOVERY.md.

`tests/test_backup_restore.py` passes. It runs `scripts/backup_restore_check.py`:

1. seed PostgreSQL;
2. `pg_dump -Fc`;
3. restore into a scratch database and compare **every table** row for row;
4. check the invariants: assessments, reviews, policies and their hashes, model registry
   and artefact digests, API keys, the audit chain;
5. destroy the database, restore again, and re-verify.

`tests/test_migration_recovery.py` injects a failing migration. On both SQLite and
PostgreSQL, the database is left at the last good revision with no half-applied tables,
and a later retry succeeds. SQLite needed explicit transactional DDL in `migrations/env.py`.

## 18. Observability

New Prometheus metrics. The label values are bounded: route templates, codes, key
versions, policy versions and decisions. **No labels hold personal data, key ids, IPs or
user ids.**

| Metric | Labels |
|---|---|
| `fraud_api_signature_failures_total` | `code` |
| `fraud_api_signatures_verified_total` | `key_version` |
| `fraud_api_state_unavailable_total` | `what` |
| `fraud_state_operation_seconds`, `fraud_state_errors_total` | `op` |
| `fraud_db_ping_seconds`, `fraud_db_query_seconds` | – |
| `fraud_db_pool_checked_out` | – |
| `fraud_model_verification_seconds`, `fraud_model_verification_failures_total` | – |
| `fraud_model_cache_loads`, `fraud_model_cache_load_failures` | – |
| `fraud_api_fallbacks_total` | `category` |
| `fraud_api_policy_decisions_total` | `policy_version`, `decision` |

Metrics are per worker process: scrape each worker, or aggregate with the platform.

**Example alert rules** are in `deploy/monitoring/alerts.yml`. Their thresholds are
illustrative. They cover:

* readiness failing;
* a 503 spike and Redis errors;
* a fallback-rate spike and a review backlog;
* an intervention rate doubled week over week;
* sustained signature and auth failures;
* artefact verification failure.

**Logging hardening** (`redact_log_text`, applied to every log record):

* masked: API-key secrets, bearer tokens, `v1=` signatures;
* masked: Stripe-style `sk_`/`rk_`/`whsec_` secrets, and payment-intent and setup-intent
  client secrets;
* masked: `tok_`/`pm_`/`src_`/`card_` references;
* masked: passwords in URLs;
* IPv4 addresses become `[REDACTED-IP]`.

JSON log format is the default in staging and production. Tests:
`test_logs_are_redacted`, `test_json_logs_are_structured`, and
`test_stored_metadata_is_not_rewritten_by_log_rules` (log rules never alter stored data).

## 19. Data privacy inventory

This is an inventory of what is stored, why, and for how long. **It is not a compliance
assessment.** No GDPR compliance is claimed. A real deployment needs a DPIA, a lawful basis,
a records-of-processing entry and subject-rights procedures, and none of these exist.

| Data | Where | Form | Purpose | Retention now |
|---|---|---|---|---|
| user reference, session id | `users`, events, assessments | merchant-supplied ids; home country | scoring, history features | indefinite (no policy yet) |
| IP address | `network_identities` | keyed HMAC; raw IP **only** if `STORE_RAW_IP=true` | velocity/network features | hash indefinite; raw IP 30 days (`retention_raw_ip_days`) |
| device identifiers | `devices`, `user_devices` | keyed HMAC | device features | indefinite |
| billing/shipping address | `addresses` | keyed HMAC + country, region, postal prefix | geo features | indefinite |
| card data | `payment_methods` | provider token reference, brand, last 4 digits, funding, issuer country, keyed fingerprint hash; **never PAN, CVV or PIN** | payment features, step-up | indefinite |
| amounts, merchant data | `transactions` | clear | scoring | indefinite |
| event metadata | `events` | redacted before storage: sensitive keys (passwords, secrets, card numbers, CVV, PIN, OTP, …), `key=value` secrets and card-number-like values. Free-text emails/phone numbers are **not** redacted | audit of inputs | indefinite |
| WebAuthn credentials | `webauthn_credentials` | public key, credential id, sign count | step-up | until removed |
| payment step-up requests | `payment_auth_requests` | provider reference, status | step-up | configurable, off by default |
| API keys | `service_api_keys` | salted SHA-256 of the secret | authentication | indefinite (revoked kept for audit) |
| audit events | `audit_events` | actor ids (OS user, key id), no secrets, IPs redacted | accountability | indefinite, immutable |
| LLM investigations | `investigations` | redacted evidence and output | analyst assistance | indefinite |
| logs | stderr | redacted; no raw IPs | operations | platform-defined |

**Known privacy gaps** (for Stage 11):

* no retention policy for events, assessments or investigations;
* no erasure or subject-access tooling;
* free-text metadata could carry emails or phone numbers; storage redaction does not detect them;
* pseudonymisation-key rotation would break linkage to existing hashes;
* the `llamacpp-process` LLM runtime passes the prompt as a process argument, which other
  local users can see in the process list. Use `llamacpp-server` or `ollama` on shared
  hosts.

## 20. CI pipeline

`.github/workflows/ci.yml` has four jobs:

* **`lint`:** `ruff check`, `ruff format --check` and `mypy`.
* **`test`:** SQLite, PostgreSQL 16 (a service container) and Redis. It creates a
  non-default staging role for the staging E2E, and gates coverage at ≥ 95 %.
* **`security`:** pip-audit, bandit, detect-secrets against the baseline, gitleaks over
  the full history, and the CycloneDX SBOM as an artefact.
* **`container`:** a real image build, `container_checks.sh`, and a Trivy HIGH/CRITICAL
  report. The report does not fail the job: HIGH/CRITICAL findings go to the release
  review, and are never hidden.

Benchmarks are deliberately not in CI.

**Not validated.** The workflow has not run on GitHub from this environment, which has no
Actions runner. It is written to match the commands verified locally.

## 21. Final security review

Findings from the review, and what happened to each:

| # | Finding | Action |
|---|---|---|
| 1 | Signatures required but no key configured accepted unsigned requests | **fixed**: 503 `SIGNING_UNAVAILABLE` |
| 2 | Database error during authentication surfaced as a 500 | **fixed**: sanitised 503 `DATABASE_UNAVAILABLE` |
| 3 | Readiness did not count a missing artefact directory | **fixed** |
| 4 | Failed SQLite migration left half-applied tables | **fixed**: transactional DDL |
| 5 | Vulnerable `idna` / `urllib3` | **fixed**: upgraded, floors pinned |
| 6 | Image carried an 86 MB dead wheel layer and pip/setuptools/wheel (2 HIGH) | **fixed**: bind mount, installers removed |
| 7 | Staging compose secrets unreadable by uid 10001 (bind mounts keep host owner) | **fixed**: generator chowns to 10001, 0400 |
| 8 | `policy promote --to evaluation` ran a full simulation before checking stage order | **fixed**: `check_transition` first |
| 9 | Credential-shaped literals in tests | **fixed** |
| 10 | Request signature v1 covers timestamp + body, not method/path | **open (low)**: a signature is single-use (replay claim), so it cannot be reused on another route; a v2 covering method + path is recommended |
| 11 | Model artefacts: digest verified, then `joblib.load` (unpickling) reads the file again | **open (low)**: time-of-check/time-of-use needs write access to the model directory; mount it read-only (compose does) |
| 12 | `/v1/ready` is unauthenticated and names its checks | **accepted**: no secrets or versions; restrict at the proxy if needed |
| 13 | Superuser can bypass audit triggers | **open**: external anchoring recommended (Stage 11) |
| 14 | Unpatched Debian base CVEs (section 16) | **open**: no fix available; rebuild when patched |

Also reviewed, with no issue found:

* no f-string or `.format` SQL: all queries use bound parameters;
* `torch.load(weights_only=True)`;
* no `eval`/`exec`/`yaml.load`;
* no `shell=True`;
* the only subprocess is fixed-argv llama.cpp;
* no outbound HTTP except the local LLM endpoint (loopback or private only) and the Stripe
  SDK;
* constant-time comparisons for keys and signatures;
* payment callbacks verified before parsing their state.

## 22. Known limitations

* The real (PyTorch) image was not built or scanned here; only the torch-less verification
  variant was.
* **The Stripe adapter was never run against Stripe.** It is written against the stripe
  SDK 15.x and tested with a stubbed client and SDK-generated webhook signatures. No
  sandbox credentials were available, and no call to Stripe was faked as a success. See
  AUTHENTICATION.md.
* Benchmarks come from one 4-vCPU machine with everything local and synthetic events.
  Networked PostgreSQL and Redis will add latency.
* The CI workflow has not run on GitHub yet.
* There is no cloud secret-manager SDK integration: platform injection only, and untested.
* Audit anchoring, erasure tooling and data-retention policies for core records are missing.
* The uvicorn supervisor crash-loops on a worker that refuses start-up, instead of exiting.

---

# Stage 11: trust, integrity, privacy and real integration

## 23. What changed, and what it costs

| Area | Change |
|---|---|
| Request signatures | **v2**: binds method, canonical path and query, timestamp and body digest. `SIGNATURE_MIN_VERSION` gives downgrade protection (default v2 in production) |
| Model artefacts | **Ed25519 signatures** over every file; required by default in staging/production. **Read-once verified load** from in-memory bytes (no symlinks, `fstat`-checked, 1 GiB cap) |
| Audit | **External signed anchors** (separate audit key, create-only files); `audit anchor` / `audit verify-anchor` |
| Policy activation | **Two-person rule**: distinct `OPERATOR_ID`s, approval TTL, pinned to the definition hash, DB unique constraint, append-only with triggers |
| Database | **Least-privilege roles**: `fraud_migrator` owns; `fraud_service` has no DROP/ALTER/TRUNCATE/trigger control and no UPDATE/DELETE on history (one column-level exception: `risk_assessments.latency_ms` telemetry); `fraud_readonly`; `fraud_backup` |
| Privacy | `privacy inventory`; free-text PII rules (reject/sanitise); dry-run `privacy erasure-plan`; four opt-in core retention classes |
| Releases | **Signed release manifest** (separate release key); `release verify` |
| Keys | One Ed25519 key set per purpose, disjoint (validated), with domain-separated messages; `keys generate` |
| Migration | `0009`: `model_artifact_signatures`, `policy_approvals` (both append-only) |

**Overhead**, measured with `scripts/trust_benchmark.py` on a local 4-vCPU container
(`benchmarks/stage11_trust_overhead.json`; synthetic; not an SLA):

| What | Cost | When |
|---|---|---|
| request signing + verification, v1 | median 9.5 µs (p95 13 µs) | per signed request |
| request signing + verification, **v2** | median 13.0 µs (p95 20 µs) | per signed request: **+≈4 µs**, noise against about 30-90 ms of scoring |
| artefact read-once (GB 209 KB / GRU 40 KB / LR 54 KB) | 0.25-0.34 ms | per model load only |
| digest over the in-memory bytes | 0.05-0.15 ms | per model load only |
| **Ed25519 signature check** | about 0.2 ms | per model load only (start-up, cache miss, readiness re-verification); **never per request** |
| full verified load (read + digest + signature + deserialise) | GB 11 ms, GRU 3.6 ms (PyTorch already imported), LR 2.6 ms | per model load only |
| `audit anchor` over 2,000 events | 43 ms | operator/cron |
| `audit verify-anchor` over 2,000 events | 62 ms | operator/cron |
| `policy approve` / activation gate | 7-9 ms / 1.7 ms | operator actions |

## 24. Security status matrix

Evidence levels:

* **Implemented:** the code exists.
* **Local:** automated tests on this machine (SQLite and/or PostgreSQL 16 plus Redis 7).
* **Staging:** exercised on the docker-compose staging stack (PostgreSQL, Redis, Caddy TLS,
  2 workers) or by the staging-profile E2E test.
* **External:** exercised against a system outside this environment (GitHub Actions,
  Stripe).

| Control | Implemented | Tested locally | Tested staging | Tested externally | Remaining gap |
|---|---|---|---|---|---|
| Signature v2 + downgrade protection | yes | yes (`test_signature_v2`, `test_security_regressions`) | yes: stack through TLS (method/path/body/replay fail, v1 → `SIGNATURE_VERSION_REJECTED`) and staging E2E | GitHub CI run 36579194568: tests green | path-rewriting proxies must be accounted for; integrators still on v1 during migration |
| Signed model artefacts | yes | yes (`test_model_signing`) | yes: stack refused unsigned models, loaded signed ones; staging E2E | **yes:** CI smoke on the full PyTorch image refused unsigned models, then loaded the signed GB/GRU/LR (GRU 1.38 s) | model key custody; sklearn models are pickles |
| Read-once verified load | yes | yes (swap-after-read test, symlink/subdir refusal) | indirectly (every load) | CI smoke on the full PyTorch image (every load) | an attacker with write access *and* the signing key |
| External audit anchors | yes (file store) | yes, SQLite + PostgreSQL (rewrite, truncation, forged/missing/wrong-key anchors) | yes: stack anchor, then a DBA-style rewrite **detected** | no | the store is a local directory unless pointed at WORM storage; unanchored tail |
| Two-person activation | yes | yes (`test_trust_chain`) | yes: stack CLI flow and staging E2E (double approval refused) | no | `OPERATOR_ID` is configuration, not authentication |
| Approval expiry | yes | yes | TTL shown in the stack (72 h) | no | none known |
| Least-privilege DB roles | yes (`db create-roles`, `db grant-roles`) | yes, real PostgreSQL (`test_pg_privileges`, 26 checks) | no: the stack still uses one DB user | GitHub CI (`test_pg_privileges` against the runner's PostgreSQL 16) | the migrator credential and superusers remain all-powerful; the stack should adopt the roles |
| Backup with the restricted role | yes | yes (`fraud_backup` dump → restore → identical) | no | no | not timed at real volumes |
| Privacy inventory | yes | yes (schema-checked) | no | no | not a legal assessment |
| Free-text PII rules | yes | yes | indirectly (review note in the E2E) | no | heuristic: names and unusual formats are not detected |
| Erasure plan (dry run) | yes | yes | no | no | no erasure execution (deliberate) |
| Core retention classes | yes (off by default) | yes | no | no | no retention *policy* chosen for core records |
| Signed release manifest | yes | yes (`test_release`) | no | no | no image signing or provenance |
| Key separation | yes | yes (settings refusal, domain separation) | yes (staging keys) | no | key custody is procedural |
| Real Stripe test mode | adapter only | contract tests | no | **no: REAL STRIPE TEST NOT PERFORMED** (no test credentials) | everything real about Stripe |
| Full PyTorch image | Dockerfile | torch-less variant only (the CPU wheel index is blocked here) | torch-less variant | **yes (GitHub CI):** built, checked, smoke-tested with the GRU, Trivy-scanned: 1,395 MB, 0 CRITICAL, 44 HIGH (8 unique, none fixable) | 773 MB of the image is PyTorch; base-OS HIGHs without an upstream fix |
| GitHub CI | workflow | n/a | n/a | **Stage 10 run: lint + tests green; security (setuptools) and container (Trivy action tag) failed, both fixed**; **Stage 11: run 36579194568 all four jobs green** (§26) | no branch protection or required checks configured; runs are not reproducible builds |

## 25. Stripe, PyTorch image, base image, CI

* **Stripe: REAL STRIPE TEST NOT PERFORMED.** No Stripe test-mode credentials were available
  in this environment (`STRIPE_API_KEY` unset). No external call was faked as a success.
  * **Local contract tests** (`tests/test_stripe_provider.py`): all pass, against a stub
    client, with webhook signatures generated and verified by the SDK itself.
  * **Versions:** SDK `stripe` 15.6.1, pinned API version `2026-08-26.dahlia`.
  * **Before relying on it:** run AUTHENTICATION.md §3's checklist against a Stripe test
    account.
* **Full PyTorch image.** Building it here is still impossible: the CPU wheel index
  `download.pytorch.org` is blocked (HTTP 403). The **GitHub Actions** runner can reach it:
  the Stage 10 CI run installed `torch-2.14.0+cpu`. The container job now:
  * builds the real image;
  * runs `container_checks.sh`;
  * runs `container_smoke.sh`: migrate; bootstrap GB + **GRU** + LR; unsigned models must
    refuse start-up; sign; the service must be ready read-only as uid 10001, with the GRU
    loaded;
  * builds the sklearn-only variant for size comparison;
  * runs Trivy on both images;
  * uploads everything as artefacts.

  The results are in §26.
* **Image minimisation research** (measured here, torch-less, with Trivy 0.58.1 and the
  2026-09-28 DB):

  | Base | Disk | Compressed | CRITICAL | HIGH (unique CVEs) | HIGH fixable | Smoke test |
  |---|---|---|---|---|---|---|
  | `python:3.11-slim` (Debian 13), **current** | 732 MB | 163 MB | 0 | 44 (8) | 0 | passes |
  | `gcr.io/distroless/python3-debian12` (research: `deploy/research/Dockerfile.distroless`) | 625 MB | 137 MB | **2** (sqlite, zlib) | **51 (28)** | **19** | passes (`PYTHON_BIN=python3`) |

  **Decision: keep the slim base.** Distroless saves 107 MB, but today it carries
  *more* and *fixable-but-unfixed* findings, because its Debian 12 packages lag. Switching
  would be for appearance only. Revisit when a distroless Debian 13 image is available.
  Splitting the GRU into a separate sequence-model worker is **not** justified yet:
  * the size difference is the PyTorch wheel, in both designs;
  * the per-worker memory cost (about +470 MB with the GRU) is already known;
  * the service calls the sequence model in-process on the scoring path, so a split would
    add a network hop and a new failure mode to every event.
* **CI.** The Stage 10 push ran on GitHub Actions (run 36363585987):
  * `lint`: green;
  * `test`: green in 43 min, including PostgreSQL and Redis;
  * `security`: failed at pip-audit. `setuptools` 79.0.1 (PYSEC-2026-3447) is pulled in by
    torch. **Fixed:** a `setuptools>=83` floor;
  * `container`: failed at set-up because `aquasecurity/trivy-action@0.28.0` does not
    resolve. **Fixed:** Trivy now runs from the `aquasec/trivy:0.58.1` image.

  Artefacts are now uploaded: coverage (XML and HTML), SBOM, security summaries, container
  scan and smoke results. Nothing secret is uploaded; the smoke test's keys live in a temp
  directory that is deleted.

## 26. Stage 11 CI run

Three runs after the Stage 11 push, each fixing what the previous one found. Nothing was
skipped, disabled or ignored to get green.

| Run | Commit | Result | Cause and fix |
|---|---|---|---|
| 36511027891 | 20f11cb | container job failed at the image checks (then cancelled by the next push) | `torch/bin/test_interpreter_async.pt` is a test fixture shipped in the PyTorch wheel, flagged as a model file. `container_checks.sh` now excludes `torch/bin/*.pt` (only that path). The PostgreSQL health check named a missing database: fixed (`-d`). |
| 36513383020 | b342be2 | lint, security, **test green**; container job failed **after** `SMOKE OK` | the clean-up could not delete files the container wrote as uid 10001. Clean-up now removes them from a root container of the same image. |
| **36579194568** | **b2e0ed4** | **all four jobs green** | – |

Results of run 36579194568:

* **lint:** ruff, ruff format --check and mypy strict clean.
* **test:** 1056 passed, 0 skipped, in 42 min (SQLite, PostgreSQL 16, Redis, least-privilege
  roles, restricted backup, staging E2E, multiprocess); coverage 97.39 % (gate 95 %).
  The `duplicate key` errors in the PostgreSQL service log are from the replay and
  idempotency race tests, which provoke them on purpose.
* **security:** pip-audit 0 findings, bandit 0, detect-secrets 0 new, gitleaks (full
  history) clean, CycloneDX SBOM uploaded.
* **container:**
  * the **full PyTorch release image** (CPU wheel) built in 61 s;
  * `container_checks.sh`: uid 10001, no secrets, `.git`, databases or keys; read-only start;
  * `container_smoke.sh`:
    * migrate `<empty> → 0009`;
    * bootstrap GB + **GRU** + LR;
    * **unsigned models refused start-up**;
    * all three signed with a throwaway Ed25519 key, each verified;
    * the service became ready read-only, with all capabilities dropped, as uid 10001;
    * the model cache warmed GB 0.002 s, **GRU 1.381 s**, LR 0.007 s.

  Image sizes (`docker image inspect`, uncompressed):

  | Image | Size | Largest packages (MB) |
  |---|---|---|
  | `fraud-ai:ci` (release, CPU PyTorch) | **1,395 MB** | torch 773, scipy 113, sympy 80, sklearn 51, numpy 45 |
  | `fraud-ai:ci-notorch` (comparison only) | 518 MB | – |

  Trivy 0.58.1, HIGH/CRITICAL, on both images:

  | Image | CRITICAL | HIGH | Unique CVEs | With a fixed version | In Python packages |
  |---|---|---|---|---|---|
  | `fraud-ai:ci` | 0 | 44 | 8 | 0 | 0 |
  | `fraud-ai:ci-notorch` | 0 | 44 | 8 | 0 | 0 |

  **All 44 are in Debian 13.7 base packages**, and none has a fixed version upstream.
  They are in util-linux (4 CVEs: mount helpers, nsenter, bind mounts), acl, ncurses,
  systemd-homed and perl Archive::Tar (`fix_deferred`).
  **PyTorch adds no HIGH/CRITICAL finding.**

  Reachability: the service runs no mount, nsenter, homed or tar operation. The container
  runs read-only, non-root, with all capabilities dropped and `no-new-privileges`.
  **They are not suppressed:** CI prints them on every run, and they must be re-checked
  when Debian ships fixes (rebuild the image to pick them up).

Not verified by CI:
* image signing or provenance;
* branch protection or required checks;
* a scheduled rebuild for new base-image fixes.

