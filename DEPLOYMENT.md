# Deployment (Stage 9)

How to run the fraud service locally and in a staging-like container setup. This is
**not** a production runbook. The platform is a research system on synthetic data, and
production would at least need the Stage 11 hardening in [ROADMAP.md](ROADMAP.md).

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

Plus the Stage 1-8 settings in [README.md](README.md). `.env.example` lists all of them
without values for secrets.

## 5. Operations

* **Probes:** liveness is `/v1/health`. Readiness is `/v1/ready`, which reports the
  database, migrations, the active policy and the primary model artefact, and never the
  LLM.
* **Metrics:** `/v1/metrics` (scope `metrics:read`), in Prometheus text format.
* **Keys:**
  * `fraud-ai service-key create | list | revoke | scopes`;
  * rotate by creating a new key, deploying it, then revoking the old one;
  * rotating `SERVICE_SIGNING_MASTER_KEY` changes every signing secret, so coordinate it
    with the integrators.
* **Scaling:**
  * PostgreSQL plus several uvicorn workers or replicas are supported by the unique
    constraints;
  * rate limits are per process until a shared `RateLimiter` (for example Redis) is
    plugged in;
  * the model cache is per process.
* **Benchmark:** `python scripts/service_benchmark.py` compares HTTP with direct scoring
  (synthetic; see [REALTIME_SCORING.md](REALTIME_SCORING.md) §14).

## 6. Not covered (Stage 11 and beyond)

* database roles and least privilege, encryption at rest, backups;
* key expiry, automatic rotation and a secret-manager integration;
* retention jobs (idempotency rows, replay tokens beyond their pruning, step-up records);
* mTLS, a WAF, DDoS protection and a shared rate limiter;
* image signing, SBOMs, dependency and container scanning;
* a threat-model review and a penetration test;
* any compliance programme (PCI DSS or similar). **None is claimed.**
