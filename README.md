# fraud-ai

A locally runnable fraud-prevention software platform written in Python. It is not a web
application.

The current release covers **Stages 1 and 2**:

* **Stage 1:** the software core, the event architecture, the fraud database (PostgreSQL in
  production, SQLite for local use), migrations, synthetic data and the CLI.
* **Stage 2:** point-in-time feature engineering, feature snapshots and training-dataset
  construction. No model is trained yet.

See [ARCHITECTURE.md](ARCHITECTURE.md), [FEATURES.md](FEATURES.md) and
[ROADMAP.md](ROADMAP.md).

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
| `PSEUDONYMISATION_KEY` | a generated dev key file | Required outside development/test; at least 32 characters |
| `STORE_RAW_IP` | `false` | Store raw IPs alongside their keyed hash |
| `LOCAL_LLM_MODEL`, `LOCAL_LLM_ENDPOINT` | unset | Stage 7; the endpoint must be local or private |

## Develop

```bash
scripts/check.sh                 # ruff, ruff format --check, mypy --strict, pytest
TEST_POSTGRES_URL='postgresql+psycopg://fraud_ai:<password>@localhost:5432/fraud_ai_test' pytest
```

Without `TEST_POSTGRES_URL`, the PostgreSQL variants of the database tests are skipped.
