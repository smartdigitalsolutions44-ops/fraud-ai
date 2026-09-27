# fraud-ai

A locally runnable fraud-prevention software platform written in Python. It is not a web
application.

The current release covers **Stages 1 to 8**:

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

Decisions are **internal policy outputs** (`ALLOW`, `ALLOW_WITH_MONITORING`,
`STEP_UP_AUTHENTICATION`, `MANUAL_REVIEW`, `TEMPORARY_BLOCK`). No payment or authentication
system is called, and there are no permanent bans. Policy bands are synthetic-derived
experimental defaults, and all bundled data is synthetic. Evaluation results
describe synthetic data only; they are not real-world detection rates or savings. See
[ARCHITECTURE.md](ARCHITECTURE.md), [FEATURES.md](FEATURES.md), [MODELS.md](MODELS.md),
[EVALUATION.md](EVALUATION.md), [NEURAL_MODELS.md](NEURAL_MODELS.md),
[SEQUENCE_MODELS.md](SEQUENCE_MODELS.md), [LLM_ANALYST.md](LLM_ANALYST.md),
[REALTIME_SCORING.md](REALTIME_SCORING.md), [RISK_POLICY.md](RISK_POLICY.md) and
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

## Develop

```bash
scripts/check.sh                 # ruff, ruff format --check, mypy --strict, pytest
TEST_POSTGRES_URL='postgresql+psycopg://fraud_ai:<password>@localhost:5432/fraud_ai_test' pytest
```

Without `TEST_POSTGRES_URL`, the PostgreSQL variants of the database tests are skipped.
