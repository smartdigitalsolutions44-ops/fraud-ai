# Deployment (Stages 9-11)

How to run the fraud service locally, in a container, and as the Stage 10 staging stack.
This is **not** a production runbook. The platform is a *deployment-hardened prototype* on
synthetic data. See:

* [HARDENING.md](HARDENING.md): what was hardened and measured;
* [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md): backups and incidents;
* [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md): what must be green before a release.

## 1. Local development (no container)

```bash
pip install -e ".[dev]"
fraud-ai db init
fraud-ai seed --users 300 --days 180 --fraud-multiplier 2 --live-days 7 --live-output live.jsonl
fraud-ai train gradient-boosting ; fraud-ai train logistic
fraud-ai policy propose risk-policy-1.0.0 --primary gradient-boosting-1.0.0
fraud-ai deployment activate risk-policy-1.0.0 --yes
fraud-ai service-key create --name local-dev --scope score:write --scope assessment:read
fraud-ai service status          # readiness plus the security-relevant configuration
fraud-ai service run             # http://127.0.0.1:8080 (localhost HTTP is fine for dev)
```

`fraud-ai service run` refuses an uninitialised or outdated database. It runs uvicorn
with:

* `proxy_headers=False`, so forwarding headers are handled only by `TRUSTED_PROXIES`;
* the `Server` and `Date` headers disabled;
* access logs off (they would contain client addresses).

SQLite is fine for one developer process. The service serialises writes on it (see
[SERVICE_SECURITY.md](SERVICE_SECURITY.md) §8). Use PostgreSQL for concurrent or
multi-worker runs.

## 2. Container (Docker + PostgreSQL)

```bash
export POSTGRES_PASSWORD=$(python -c "import secrets; print(secrets.token_urlsafe(24))")
export PSEUDONYMISATION_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export SERVICE_SIGNING_MASTER_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
docker compose up --build
docker compose run --rm fraud-ai service-key create --name checkout --scope score:write
```

### The image (`Dockerfile`)

* **Base and build:** `python:3.11-slim`, multi-stage. The wheels are built in the first
  stage; the runtime installs them offline (`--no-index`).
* **Dependencies:** CPU-only PyTorch; no compilers in the final image.
* **User:** non-root (uid/gid 10001, no shell, no home).
* **Contents:** the package plus `migrations/`, and nothing else. `.dockerignore` is an
  allow-list. It excludes:
  * `.git`, `.env*`, databases and keys;
  * `data/`, `models/` and evaluation output;
  * LLM weights (`*.gguf`), tests and scratch files.
* **No LLM:** no runtime and no model is installed. Scoring never needs one.
* **Read-only root filesystem compatible:**
  * `PYTHONDONTWRITEBYTECODE=1`;
  * `DATA_DIRECTORY=/tmp/fraud-ai`;
  * nothing is written outside `/tmp` (compose mounts it as tmpfs).
* **`HEALTHCHECK`:** `GET /v1/health` (liveness). Orchestrators should use `/v1/ready`
  for traffic.
* **Behind a TLS-intercepting proxy:** pass its CA as a BuildKit secret, which is never
  stored in a layer:
  `docker build --secret id=ca_bundle,src=/path/ca.crt .`
* **Build arguments (Stage 10):**
  * `TORCH_INDEX_URL`: a CPU PyTorch mirror.
  * `WITH_TORCH=0`: a torch-less **verification** variant. It serves scikit-learn models
    only, and a neural active model fails start-up. Never deploy it as the real image.
* **Stage 10 image changes:**
  * wheels are bind-mounted, not copied, so no dead layer is left;
  * `pip`, `setuptools` and `wheel` are removed from the runtime image;
  * the `stripe` extra is included.
* **Checks:** `scripts/container_checks.sh <image>` (non-root, no secrets or artefacts,
  read-only start). Size and Trivy results are in [HARDENING.md](HARDENING.md) §16.

### Compose (`docker-compose.yml`)

* **Services:**
  * `postgres:16-alpine`, with a health check;
  * a one-shot `migrate` (`fraud-ai db migrate`);
  * `fraud-ai`, which starts only after the migration succeeded.
* **Secrets:** none has a default. Compose refuses to start until
  `POSTGRES_PASSWORD`, `PSEUDONYMISATION_KEY` and `SERVICE_SIGNING_MASTER_KEY` are set.
* **Hardening:** `read_only: true`, tmpfs `/tmp`, `cap_drop: [ALL]` and
  `no-new-privileges`.
* **Exposure:** the port is published on **127.0.0.1 only**.
* **Models** are mounted read-only from `./models`. The registry stores artefact paths,
  so train with `MODEL_DIRECTORY=/models` (for example
  `docker compose run --rm -v ./models:/models fraud-ai train gradient-boosting`), or keep
  the same absolute path. Artefacts are SHA-256-verified before use (readiness checks the
  primary one).

## 2a. Staging stack (Stage 10)

```bash
sudo deploy/staging/generate-secrets.sh     # random secrets; 0400, owned by uid 10001
docker compose -f deploy/staging/docker-compose.staging.yml up -d --build
docker compose -f deploy/staging/docker-compose.staging.yml run --rm migrate \
    service-key create --name staging-e2e --scope score:write ... --show-signing-secret
python scripts/staging_e2e.py --base-url https://staging.fraud-ai.test:8443 ...
```

**Services:**

* PostgreSQL 16;
* Redis 7 (password, no persistence);
* a migration job;
* fraud-ai: 2 workers, `STATE_BACKEND=redis`, required signatures, JSON logs, promotion
  required;
* a Caddy TLS proxy on `127.0.0.1:8443`;
* optionally, an LLM service (profile `llm`).

**Configuration:**

* **secrets** are files read through `*_FILE`;
* **networks:** the data network is internal;
* **fake provider:** the development fake payment provider is enabled explicitly
  (`PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true`).

The service refuses to start until a policy and its models exist. Bootstrap one first:
seed, train and create policies, activate the first deployment, then promote later
policies through `policy promote`. Run the bootstrap on the `migrate` service, with the
models directory mounted writable.

The run on this machine is recorded in [HARDENING.md](HARDENING.md) §12. The E2E passed,
promotion worked, and it failed closed with Redis or PostgreSQL stopped.

## 2b. Stage 11 trust setup

Keys (one per purpose; generate them on a signing host, never on service hosts):

```bash
fraud-ai keys generate --purpose model   --out /secure/model.pem    # -> MODEL_SIGNING_PUBLIC_KEYS
fraud-ai keys generate --purpose audit   --out /secure/audit.pem    # -> AUDIT_ANCHOR_PUBLIC_KEYS
fraud-ai keys generate --purpose release --out /secure/release.pem  # -> RELEASE_SIGNING_PUBLIC_KEYS
```

Models: sign after training, before proposing or activating a policy.
`MODEL_SIGNATURES_REQUIRED` is on by default in staging and production, and policy
evaluation loads the models too.

```bash
fraud-ai models sign gradient-boosting-1.0.0 --key /secure/model.pem
fraud-ai models verify-signature gradient-boosting-1.0.0
```

Two-person activation (`POLICY_APPROVALS_REQUIRED=2`, the default in production). Each
operator's CLI environment sets its own `OPERATOR_ID`:

```bash
OPERATOR_ID=alice fraud-ai policy approve risk-policy-1.1.0 --note "..."
OPERATOR_ID=bob   fraud-ai policy approve risk-policy-1.1.0 --note "..."
OPERATOR_ID=bob   fraud-ai deployment activate risk-policy-1.1.0 --yes
```

Audit anchors: run from cron, into storage the DBA cannot write:

```bash
fraud-ai audit anchor --key /secure/audit.pem --store /mnt/worm/anchors
fraud-ai audit verify-anchor --store /mnt/worm/anchors
```

Release manifest:

```bash
fraud-ai release manifest --out release.json --sbom sbom/fraud-ai.cdx.json \
    --image-digest "$(docker image inspect --format '{{.Id}}' fraud-ai:release)" --key /secure/release.pem
fraud-ai release verify release.json --sbom sbom/fraud-ai.cdx.json
```

Least-privilege PostgreSQL (`fraud_ai/database/roles.py`):

```bash
# as an administrator; the passwords come from FRAUD_*_PASSWORD(_FILE), never argv
DATABASE_URL=<admin url> fraud-ai db create-roles --database fraud_ai
DATABASE_URL=<fraud_migrator url> fraud-ai db migrate
DATABASE_URL=<fraud_migrator url> fraud-ai db grant-roles     # after EVERY migration
# service: DATABASE_URL=<fraud_service url>; backups: pg_dump as fraud_backup
```

**Staging stack (Stage 11).** `generate-secrets.sh` also creates a staging-only model key
with `openssl`. The private key goes to `signing/` (0700/0600, owned by uid 10001, never
mounted into the service); the public key goes to `deploy/staging/.env`. The stack sets
`SIGNATURE_MIN_VERSION=v2`, `MODEL_SIGNATURES_REQUIRED=true` and
`POLICY_APPROVALS_REQUIRED=2`. The procedure used on this machine:

1. Bootstrap with `scripts/bootstrap_world.py` under `MODEL_SIGNATURES_REQUIRED=false` (the
   offline training environment), or pass `--sign-key`.
2. The service **refuses** the unsigned models.
3. Sign with the one-off `migrate` service, mounting `signing/` read-only.
4. Restart the service.
5. Run the E2E and the two-person flow.

The results are in HARDENING.md §24. The stack still connects as a single database user;
adopting the least-privilege roles there is a Stage 12 item.

## 3. TLS and reverse proxies (required outside localhost)

The service speaks plain HTTP. **In any shared or production-like environment, terminate
TLS in front of it**, for example with nginx, Envoy, Caddy or a cloud load balancer:

* TLS 1.2+ only, with modern ciphers and a valid certificate;
* forward to the service on a private network or loopback only;
* set `TRUSTED_PROXIES` to the proxy's address or CIDR **and nothing else**. Only then are
  `X-Forwarded-For` and `Forwarded` honoured;
* the proxy must *overwrite*, not append to, client-supplied forwarding headers;
* set `SERVICE_HSTS=true` once TLS is in place;
* keep request-size and timeout limits at the proxy as well.

WebAuthn needs a secure context:

* `WEBAUTHN_ORIGIN` must be the exact `https://` origin of your page;
* `WEBAUTHN_RP_ID` must be its registrable domain;
* in staging and production the service refuses to start with a non-https origin.

## 4. Configuration

| Variable | Default | Notes |
|---|---|---|
| `SERVICE_HOST` / `SERVICE_PORT` | `127.0.0.1` / `8080` | the image sets `0.0.0.0` inside the container |
| `TRUSTED_PROXIES` | empty | comma-separated IPs/CIDRs; empty means forwarding headers are ignored |
| `REQUEST_SIZE_LIMIT` | `65536` | bytes (1 KiB-10 MiB) |
| `RATE_LIMIT` / `RATE_LIMIT_BURST` | `120/minute` / `30` | per API key and route |
| `SERVICE_REQUEST_TIMEOUT` | `10` | seconds; a scoring timeout gives 503 with the `MANUAL_REVIEW` fallback |
| `SERVICE_SIGNING_MASTER_KEY` | unset | at least 32 characters; enables request signing |
| `SERVICE_REQUIRE_SIGNATURES` | `false` | needs the master key |
| `SIGNATURE_MAX_AGE` | `300` | seconds (10-3600) |
| `SERVICE_CORS_ORIGINS` | empty | CORS disabled |
| `SERVICE_EXPOSE_OPENAPI` | `false` | `/v1/openapi.json` and `/v1/docs` |
| `SERVICE_HSTS` | `false` | enable only behind TLS |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_NAME` / `WEBAUTHN_ORIGIN` | `localhost` / `fraud-ai (development)` / `http://localhost:8080` | https is required outside development/test |
| `WEBAUTHN_CHALLENGE_TTL` | `120` | seconds |
| `STEP_UP_MAX_ATTEMPTS` | `3` | per assessment |
| `PAYMENT_AUTH_PROVIDER` | unset | `fake` (development only; refused in staging/production) |
| `PAYMENT_AUTH_WEBHOOK_SECRET` | unset | at least 32 characters; required with a provider |
| `PAYMENT_AUTH_TIMEOUT` | `5` | seconds |
| `LOCAL_LLM_TIMEOUT` | `120` | the investigate endpoint's own timeout is this plus 10 s |
| `STATE_BACKEND` / `REDIS_URL` | `memory` / unset | `redis` is required for more than one worker in staging/production; see HARDENING.md §1 |
| `REDIS_KEY_PREFIX` / `REDIS_TIMEOUT` | `fraud-ai:` / `0.5` | a Redis error or timeout gives 503 (fail closed) |
| `SERVICE_SIGNING_KEY_VERSION` | `1` | plus `SERVICE_SIGNING_PREVIOUS_KEY[_VERSION,_EXPIRES_AT]` during a rotation |
| `SERVICE_KEY_ROTATION_GRACE_HOURS` | `24` | old API key lifetime after `service-key rotate` |
| `READINESS_REVERIFY_SECONDS` | `300` | periodic full re-verification of the primary artefact |
| `PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING` | `false` | production never allows the fake |
| `STRIPE_API_KEY` / `STRIPE_RETURN_URL` | unset | `PAYMENT_AUTH_PROVIDER=stripe`; test-mode keys only |
| `POLICY_REQUIRE_PROMOTION` | on in staging/production | activation needs a promoted `candidate` |
| `ALLOW_REFERENCE_LLM` | `false` | production refuses the reference template otherwise |
| `LOG_FORMAT` | `json` in staging/production | `text` or `json` |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` / `DB_POOL_TIMEOUT` / `DB_POOL_RECYCLE` | `5` / `10` / `30` / `1800` | per worker; measured in HARDENING.md §13 |
| `RETENTION_*` | see HARDENING.md §9 | `RETENTION_ALLOW_DELETE=false` by default |
| `NAME_FILE` | – | any secret from a file instead of the environment |

Plus the Stage 1-8 settings in [README.md](README.md). `.env.example` lists all of them
without values for secrets.

## 5. Operations

* **Probes:** liveness is `/v1/health`. Readiness is `/v1/ready`, which reports:
  * the database and migrations;
  * the active policy and the primary model artefact (re-verified);
  * shared state (Redis) and the signing key;
  * never the LLM.
* **Start-up** fails closed on any configuration or readiness problem (HARDENING.md §6).
  `fraud-ai config check` validates settings without starting anything.
* **Metrics:** `/v1/metrics` (scope `metrics:read`), in Prometheus text format.
* **Keys:**
  * `fraud-ai service-key create [--expires-in-days N] | list | revoke | rotate | scopes | signing-secret`;
  * `rotate` issues a successor and lets the old key expire after the grace period;
  * the signing master key rotates through `SERVICE_SIGNING_PREVIOUS_KEY` (HARDENING.md §4).
* **Audit and retention:** `fraud-ai audit list | verify`;
  `fraud-ai retention plan | run | status`.
* **Scaling:**
  * PostgreSQL plus Redis support several workers or replicas (`tests/test_multiprocess.py`);
  * about 4 workers per 4 CPUs was the measured optimum;
  * the model cache is per process, about 850 MB per worker with PyTorch models.
* **Benchmark:** `python scripts/service_benchmark.py` compares HTTP with direct scoring
  (synthetic; see [REALTIME_SCORING.md](REALTIME_SCORING.md) §14).
* **Load (Stage 10):** `python scripts/pg_load_benchmark.py` (PostgreSQL + Redis,
  1/4/8/16 workers, pool sweep) and `python scripts/model_cache_benchmark.py`. Compare
  against `benchmarks/baseline.json` with `scripts/check_regression.py`.

## 6. Not covered (Stage 12 and beyond)

* encryption at rest and PITR/WAL archiving;
* least-privilege roles in the compose stacks (the roles exist and are tested);
* WORM anchor storage wired in; image signing and provenance (cosign, SLSA);
* a cloud secret-manager SDK integration (platform injection via `*_FILE` is supported);
* mTLS, a WAF and DDoS protection;
* a penetration test;
* any compliance programme (PCI DSS, GDPR, SOC 2, ISO or similar). **None is claimed.**
