# fraud-ai

A locally runnable fraud-prevention software platform written in Python. It is not a web
application: Stage 9 adds a machine-to-machine HTTP API, not a website.

The current release covers **Stages 1 to 11**:

* **Stage 1:** the software core, the event architecture, the fraud database (PostgreSQL in
  production, SQLite for local use), migrations, synthetic data and the CLI.
* **Stage 2:** point-in-time feature engineering, feature snapshots and training-dataset
  construction.
* **Stage 3:** baseline fraud models (logistic regression, random forest, gradient
  boosting), trained on time-ordered splits, evaluated with threshold analysis, versioned,
  reproducible, and scored into `model_predictions`.
* **Stage 4:** the evaluation framework, which covers:
  * bootstrap confidence intervals and walk-forward evaluation;
  * calibration and cost-sensitive threshold analysis;
  * scenario, cohort and error analysis;
  * paired model comparison, a drift baseline and reproducible JSON reports.

* **Stage 5:** neural models on PyTorch:
  * a feed-forward fraud classifier trained on the same split as the baselines, with
    early stopping, hyperparameter experiments and safe, hash-verified checkpoints;
  * an experimental autoencoder anomaly score (not a fraud probability);
  * complementarity analysis against gradient boosting.

* **Stage 6:** sequence models over each user's ordered, point-in-time event history:
  * a GRU, a small causal Transformer and a hybrid (GRU plus static features);
  * versioned and fingerprinted sequence definitions, with leakage-tested extraction;
  * complementarity and stealthy-takeover analysis against gradient boosting.

* **Stage 7:** local, offline analyst assistance:
  * a local LLM (Ollama or llama.cpp) *explains* stored model outputs from a
    privacy-checked evidence packet;
  * every statement cites evidence, and output is validated before it is stored;
  * the LLM never scores, decides, blocks, approves, or changes labels, thresholds or
    rules.

* **Stage 8:** real-time scoring and risk-decision orchestration:
  * an idempotent hot path: event contract → ingestion (with arrival time) →
    point-in-time features → cached, verified models → calibration → versioned rules →
    a versioned, immutable risk policy → an immutable assessment;
  * shadow models and policies that are recorded but never decide;
  * explicit, conservative fallbacks for every failure;
  * a manual-review queue, a policy simulator and comparison, and monitoring with drift
    warnings;
  * the LLM stays outside the decision path.

* **Stage 9:** a secure service and authentication integration layer:
  * a versioned machine-to-machine API (`fraud-api-1.0.0`, FastAPI) over the unchanged
    Stage 8 engine;
  * API keys (hashed, scoped, revocable), HMAC request signatures with persisted replay
    protection, `Idempotency-Key`, per-key rate limits, size limits and strict
    validation;
  * sanitised errors, security headers, CORS off by default, and Prometheus metrics;
  * step-up execution with standard WebAuthn passkeys (py_webauthn) or an *external*
    payment-authentication provider adapter (a development fake only, not 3-D Secure).
    Every result creates a new, immutable follow-up assessment; scores are never changed;
  * Docker and docker-compose files.

* **Stage 10:** deployment hardening for real deployment *testing*. The result is a
  deployment-hardened prototype, not a production system. It adds:
  * Redis shared state for distributed rate limiting and replay protection (atomic,
    fail closed);
  * API-key expiry and rotation, and signing-key versions with a grace period;
  * `*_FILE` secrets;
  * fail-closed start-up and configuration profiles, and stronger readiness;
  * a hash-chained, immutable audit log;
  * retention jobs and explicit policy promotion (shadow → evaluation → candidate);
  * a Stripe **test-mode** adapter (never run against Stripe; no credentials);
  * PostgreSQL load and pool benchmarks, multi-process and chaos tests, and a verified
    backup/restore;
  * dependency, static, secret and container scans, and an SBOM;
  * CI, a staging stack, a threat model, disaster-recovery runbooks and a release
    checklist.

  See [HARDENING.md](HARDENING.md), [THREAT_MODEL.md](THREAT_MODEL.md),
  [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) and
  [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

* **Stage 11:** trust, integrity and privacy. The result is a *security-hardened
  prototype*, still not production-ready. It adds:
  * request-signature v2 with downgrade protection;
  * Ed25519-signed model artefacts, loaded from verified bytes;
  * external signed audit anchors;
  * two-person policy activation with approval expiry;
  * least-privilege PostgreSQL roles;
  * privacy inventory, free-text PII rules and a dry-run erasure plan;
  * a signed release manifest;
  * CI building and scanning the full PyTorch image.

  See [TRUST_CHAIN.md](TRUST_CHAIN.md) and [PRIVACY.md](PRIVACY.md). The real Stripe test was
  **not** performed (no test credentials).

Decisions are **internal policy outputs** (`ALLOW`, `ALLOW_WITH_MONITORING`,
`STEP_UP_AUTHENTICATION`, `MANUAL_REVIEW`, `TEMPORARY_BLOCK`). No payment or authentication
system is called by the engine itself, and there are no permanent bans. Step-up runs only
through the Stage 9 adapters, and the platform never authenticates cardholders. Policy bands are synthetic-derived
experimental defaults, and all bundled data is synthetic. Evaluation results
describe synthetic data only; they are not real-world detection rates or savings. See
[ARCHITECTURE.md](ARCHITECTURE.md), [FEATURES.md](FEATURES.md), [MODELS.md](MODELS.md),
[EVALUATION.md](EVALUATION.md), [NEURAL_MODELS.md](NEURAL_MODELS.md),
[SEQUENCE_MODELS.md](SEQUENCE_MODELS.md), [LLM_ANALYST.md](LLM_ANALYST.md),
[REALTIME_SCORING.md](REALTIME_SCORING.md), [RISK_POLICY.md](RISK_POLICY.md),
[API.md](API.md), [SERVICE_SECURITY.md](SERVICE_SECURITY.md),
[AUTHENTICATION.md](AUTHENTICATION.md), [DEPLOYMENT.md](DEPLOYMENT.md) and
[ROADMAP.md](ROADMAP.md).

> Not production-ready. No payment-security certification, PCI DSS, GDPR, SOC 2 or ISO
> compliance is claimed, and there are no real-world fraud-reduction or savings figures:
> everything is measured on synthetic data.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,postgres]"
cp .env.example .env        # optional; the defaults work for local SQLite
```

Python 3.11+ is required. The CLI finds migrations in the source checkout, so use an
editable install (`-e`).

## Run

```bash
fraud-ai db init                 # create the schema (SQLite at data/fraud_ai.db by default)
fraud-ai db status               # connection, revision and row counts
fraud-ai seed --users 60         # deterministic synthetic data via the ingestion pipeline
fraud-ai demo-data stats         # per-scenario statistics
fraud-ai ingest-event scripts/sample_events.jsonl   # ingest JSON / JSON-lines events (- = stdin)
fraud-ai db migrate              # apply future migrations
fraud-ai system-status           # component health

# Stage 2 - features (always point-in-time: nothing after the event is used)
fraud-ai features catalog                        # every feature: type, category, missing semantics
fraud-ai features show <event-id>                # compute a vector (optionally --as-of)
fraud-ai features snapshot --start 2026-08-01 --end 2026-09-01   # persist hashed snapshots
fraud-ai features validate                       # re-verify snapshots (integrity + recompute)
fraud-ai dataset build --start 2026-06-01 --end 2026-08-01 \
    --label-cutoff 2026-09-01 --output out/ds    # features.jsonl + labels.jsonl + manifest
python scripts/benchmark_features.py --users 100 # extraction throughput

# Stage 3 - baseline models (synthetic data: results say nothing about real fraud rates)
fraud-ai seed --users 300 --days 180            # enough history for a time-ordered split
fraud-ai train all                              # LR + random forest + gradient boosting
fraud-ai compare-models                         # same split, same dataset, side by side
fraud-ai models show gradient-boosting-1.0.0    # reproducibility record + threshold analysis
fraud-ai evaluate reproduce gradient-boosting-1.0.0   # re-evaluate; checks results reproduce
fraud-ai score <event-id> --model gradient-boosting-1.0.0   # store a prediction (no decision)
python scripts/benchmark_models.py --database-url sqlite:///data/fraud_ai.db

# Stage 4 - evaluation (JSON artefacts under evaluation/<model-id>/)
M=gradient-boosting-1.0.0
fraud-ai evaluate confidence $M --bootstrap 1000 --seed 0   # 95% bootstrap CIs
fraud-ai evaluate walk-forward $M --period-days 30          # retrain per fold, as-of labels
fraud-ai evaluate calibration $M                            # sigmoid / isotonic, fitted on validation
fraud-ai evaluate scenarios $M                              # per-scenario + cohort FPR checks
fraud-ai evaluate errors $M --limit 50                      # pseudonymised FP / FN
fraud-ai evaluate costs $M --fraud-loss 500 --review-cost 5 --friction 10
fraud-ai evaluate compare                                   # paired tests, agreement, ensembles
fraud-ai evaluate drift-baseline --model $M                 # PSI / Jensen-Shannon reference
fraud-ai evaluate report $M                                 # every per-model artefact at once
fraud-ai seed --users 300 --fraud-multiplier 2              # prevalence experiments
python scripts/evaluation_benchmark.py --users 1000         # larger synthetic benchmark

# Stage 5 - neural models (PyTorch, CPU by default; compared with the baselines, not trusted)
fraud-ai neural experiments --quick                         # small grid, validation PR-AUC only
fraud-ai train neural-network --hidden 128,64,32 --dropout 0.3
fraud-ai neural training-history neural-network-1.0.0       # per-epoch losses and PR-AUC
fraud-ai neural inspect neural-network-1.0.0                # architecture, params, importance
fraud-ai evaluate report neural-network-1.0.0               # every Stage 4 report
fraud-ai anomaly train-autoencoder                          # EXPERIMENTAL anomaly score
fraud-ai anomaly evaluate 1.0.0 --compare-with gradient-boosting-1.0.0
fraud-ai evaluate complementarity gradient-boosting-1.0.0 neural-network-1.0.0 --anomaly 1.0.0
python scripts/neural_benchmark.py --seed-users 1000        # full Stage 5 benchmark

# Stage 6 - sequence models (the user's events strictly before the scored event)
fraud-ai sequence inspect <event-id>                        # the point-in-time sequence
fraud-ai sequence build <event-id> --output seq.json        # deterministic JSON + digest
fraud-ai train gru ; fraud-ai train transformer ; fraud-ai train hybrid
fraud-ai sequence compare                                   # fraud caught only by each model
fraud-ai sequence stealth-report                            # stealthy/temporal takeovers
python scripts/sequence_benchmark.py --seed-users 1000      # full Stage 6 benchmark

# Stage 7 - local analyst assistant (explanations only; never scores or decides)
fraud-ai llm status                                         # runtime, versions, health
fraud-ai llm models                                         # models installed locally
fraud-ai score <event-id> --model gradient-boosting-1.0.0   # investigations never rescore
fraud-ai investigate <event-id>                             # cited, validated explanation
fraud-ai investigate <event-id> --runtime reference         # offline template (not an LLM)
fraud-ai investigate show <investigation-id> --evidence     # provenance + evidence packet
fraud-ai investigate validate <investigation-id>            # re-check a stored explanation
fraud-ai llm benchmark --model gradient-boosting-1.0.0 --runtime reference \
    --runtime ollama:qwen2.5:7b-instruct --score-latest 1500 --score-labelled 300
# Stage 8 - real-time scoring (decisions are internal policy outputs; nothing is executed)
fraud-ai seed --users 300 --days 180 --fraud-multiplier 2 \
    --live-days 7 --live-output live.jsonl                  # history + held-out live stream
fraud-ai train gradient-boosting ; fraud-ai train neural-network ; fraud-ai train logistic
fraud-ai policy propose risk-policy-1.0.0 --primary gradient-boosting-1.0.0 \
    --secondary neural-network-1.0.0                        # EXPERIMENTAL bands, stored inactive
fraud-ai policy simulate risk-policy-1.0.0                  # test split; changes nothing
fraud-ai policy compare risk-policy-1.0.0 risk-policy-1.1.0 # same events, paired
fraud-ai deployment activate risk-policy-1.0.0 --shadow-model logistic-regression-1.0.0
fraud-ai realtime replay live.jsonl                         # score in arrival order
fraud-ai realtime score event.json                          # live: arrival = now
fraud-ai review list ; fraud-ai review show <id> ; fraud-ai review resolve <id> --outcome fraud
fraud-ai monitoring summary                                 # decisions, latency, drift warnings
python scripts/realtime_benchmark.py --users 300            # full-path latency benchmark
# Stage 9 - machine-to-machine service (TLS in front of it outside localhost)
fraud-ai service-key create --name checkout --scope score:write --scope assessment:read \
    --scope stepup:write                                    # the credential is shown ONCE
fraud-ai service-key list ; fraud-ai service-key revoke <key-id> ; fraud-ai service-key scopes
fraud-ai service status                                     # readiness + security config
fraud-ai service run                                        # http://127.0.0.1:8080/v1/...
fraud-ai service openapi --output openapi.json
python scripts/service_benchmark.py                         # HTTP vs direct, 1/4/8/16 workers
docker compose up --build                                   # fraud-ai + PostgreSQL (see DEPLOYMENT.md)

# Stage 10 - hardening (see HARDENING.md)
fraud-ai config check                                       # would the service start with these settings?
fraud-ai service-key create --name c --scope score:write --expires-in-days 90
fraud-ai service-key rotate <key-id> --grace-hours 24       # successor shown ONCE; old key expires
fraud-ai audit list ; fraud-ai audit verify                 # hash-chained admin audit log
fraud-ai retention plan ; fraud-ai retention run            # dry run unless --execute --yes
fraud-ai policy promote <version> --to shadow|evaluation|candidate [--approve] --note "..."
python scripts/security_checks.py pip-audit|bandit|secrets|sbom
python scripts/pg_load_benchmark.py --help                  # PostgreSQL + Redis load test
docker compose -f deploy/staging/docker-compose.staging.yml up -d   # staging stack (DEPLOYMENT.md §2a)

# Stage 11 - trust chain and privacy (see TRUST_CHAIN.md, PRIVACY.md)
fraud-ai keys generate --purpose model --out /secure/model.pem
fraud-ai models sign <model> --key /secure/model.pem ; fraud-ai models verify-signature <model>
OPERATOR_ID=alice fraud-ai policy approve <version> --note "..."   # two-person rule
fraud-ai audit anchor --key /secure/audit.pem --store /mnt/worm ; fraud-ai audit verify-anchor --store /mnt/worm
fraud-ai release manifest --out release.json --key /secure/release.pem ; fraud-ai release verify release.json
fraud-ai privacy inventory ; fraud-ai privacy erasure-plan <customer-ref>   # dry run
fraud-ai db create-roles --database fraud_ai ; fraud-ai db grant-roles      # PostgreSQL least privilege
python -m fraud_ai --help        # equivalent entry point
```

### PostgreSQL

```bash
sudo -u postgres scripts/dev_postgres.sh '<password>'
export DATABASE_URL='postgresql+psycopg://fraud_ai:<password>@localhost:5432/fraud_ai'
fraud-ai db init
```

## Configuration (environment variables)

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | `development`, `test`, `staging`, `production` |
| `DATABASE_URL` | `sqlite:///<DATA_DIRECTORY>/fraud_ai.db` | PostgreSQL is required in staging/production |
| `LOG_LEVEL` | `INFO` | |
| `DATA_DIRECTORY` | `data` | |
| `MODEL_DIRECTORY` | `models` | |
| `EVALUATION_DIRECTORY` | `evaluation` | Stage 4 report artefacts |
| `PSEUDONYMISATION_KEY` | a generated dev key file | Required outside development/test; at least 32 characters |
| `STORE_RAW_IP` | `false` | Store raw IPs alongside their keyed hash |
| `LOCAL_LLM_RUNTIME` | unset | Stage 7: `ollama`, `llamacpp-server`, `llamacpp-process` or `reference` |
| `LOCAL_LLM_MODEL`, `LOCAL_LLM_ENDPOINT` | unset; the runtime's localhost default | The endpoint must be local or private; proxies are never used |
| `LOCAL_LLM_TIMEOUT` | `120` | Seconds |
| `LOCAL_LLM_BINARY`, `LOCAL_LLM_MODEL_PATH` | `llama-cli`, unset | llama.cpp process mode |
| `LOCAL_LLM_TEMPERATURE`, `LOCAL_LLM_TOP_P`, `LOCAL_LLM_SEED` | `0`, `1`, `0` | Deterministic by default |
| `LOCAL_LLM_CONTEXT_WINDOW`, `LOCAL_LLM_MAX_TOKENS` | `8192`, `1200` | |
| `SERVICE_HOST`, `SERVICE_PORT` | `127.0.0.1`, `8080` | Stage 9 service; put TLS in front outside localhost |
| `TRUSTED_PROXIES` | empty | Only these IPs/CIDRs may set forwarding headers |
| `REQUEST_SIZE_LIMIT`, `RATE_LIMIT`, `RATE_LIMIT_BURST` | `65536`, `120/minute`, `30` | Per API key and route |
| `SERVICE_SIGNING_MASTER_KEY`, `SERVICE_REQUIRE_SIGNATURES`, `SIGNATURE_MAX_AGE` | unset, `false`, `300` | HMAC request signing |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN` | `localhost`, dev name, `http://localhost:8080` | https is required outside dev/test |
| `PAYMENT_AUTH_PROVIDER`, `PAYMENT_AUTH_WEBHOOK_SECRET`, `PAYMENT_AUTH_TIMEOUT` | unset, unset, `5` | `fake` = development fake; `stripe` = test-mode adapter |
| `STATE_BACKEND`, `REDIS_URL` | `memory`, unset | Stage 10: `redis` for several workers/instances |
| `SERVICE_SIGNING_KEY_VERSION`, `SERVICE_SIGNING_PREVIOUS_KEY*` | `1`, unset | Signing-key rotation |
| `POLICY_REQUIRE_PROMOTION` | on in staging/production | Promotion before activation |
| `LOG_FORMAT` | `json` in staging/production | |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` | `5`, `10` | Per worker (PostgreSQL) |
| `NAME_FILE` | – | Read any secret from a file |

All Stage 9 and 10 settings are listed in [DEPLOYMENT.md](DEPLOYMENT.md) §4 and
`.env.example`.

## Develop

```bash
scripts/check.sh                 # ruff, ruff format --check, mypy --strict, pytest
TEST_POSTGRES_URL='postgresql+psycopg://fraud_ai:<password>@localhost:5432/fraud_ai_test' pytest
```

Without `TEST_POSTGRES_URL`, the PostgreSQL variants of the database tests are skipped.
