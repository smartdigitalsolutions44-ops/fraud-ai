# fraud-ai command reference

The full command-line interface of the `fraud-ai` backend, by stage, plus its configuration.
For the one-command local run of SENTINEL (Demo, Dev and StagingLike modes) see
[LOCAL_SETUP.md](LOCAL_SETUP.md); for the project overview see [README.md](README.md).

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

# Stage 12 - operational controls and the demo (see HARDENING.md §27-39, DEMO.md)
deploy/staging/stack.sh up                                        # full staging stack
fraud-ai db check-privileges --expect service                     # probe the connected role
fraud-ai operators keygen --id alice --out alice.pem              # an operator's own key
fraud-ai policy approve <version> --note "..." --operator-key alice.pem
fraud-ai audit anchor-now ; fraud-ai audit anchor-status --max-age-minutes 30
fraud-ai keys status ; fraud-ai keys rotate --purpose audit --operator-key sec.pem
fraud-ai privacy export <customer-ref> --out subject.json --operator-key sec.pem
fraud-ai release verify-image image-evidence.json --key image.pub --commit <sha>
DEMO_MODE=true fraud-ai demo start ; fraud-ai demo run            # the 9-step walkthrough

# Stages 13-14 - the SENTINEL analyst console (LOCAL_SETUP.md, sentinel-console/README.md)
./scripts/setup-local.sh && ./scripts/sentinel-start.sh           # demo world + service + console on :3000
./scripts/sentinel-status.sh ; ./scripts/sentinel-stop.sh         # Windows: the .ps1 equivalents
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
