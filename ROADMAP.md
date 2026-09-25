# Roadmap

Each stage builds only on what the previous stages have made trustworthy. We do not jump
ahead: models are only as good as the data and features beneath them.

## Stage 1: Database and event architecture ✅ (this commit)

* Python package with a `fraud-ai` CLI and `python -m fraud_ai`.
* Typed configuration from environment variables; production safety guards.
* Internal event model (envelope plus strict per-type payloads, schema versioning).
* Event processor: idempotent, atomic per event, pseudonymising, history-keeping.
* PostgreSQL/SQLite schema with Alembic migration `0001`.
* Model-version registry, prediction storage, risk policy/rules boundary, and a
  privacy-checked LLM evidence packet (interfaces plus reference logic; no ML).
* Deterministic synthetic scenarios for future ML experimentation.
* Security rules: no PAN/CVV/PIN/password storage, keyed hashing, log redaction.

## Stage 2: Feature engineering

* Implement every feature in `fraud_ai/features/catalog.py` as **point-in-time** SQL/Python
  (only data with timestamps ≤ the scored event).
* A versioned feature vector (`feature_version`) and feature snapshots referenced by
  `model_predictions.feature_snapshot_reference`.
* Leakage tests: the features for an event must not change when later events are added.
* `fraud-ai features build` / `features inspect` commands.
* The first concrete rule set for the rules engine, expressed over features.

## Stage 3: Baseline fraud models

* Logistic regression, random forest and gradient-boosted trees implementing `FraudModel`.
* Time-based train/validation/test splits (no random shuffling across time).
* Artefacts in `MODEL_DIRECTORY`, registered in `model_versions` with dataset and feature
  versions.
* `fraud-ai train` and `fraud-ai score`.

## Stage 4: Evaluation framework

* Precision/recall at operating points, PR-AUC, ROC-AUC, calibration, and cost-weighted
  metrics (fraud loss versus customer friction).
* Per-scenario breakdowns. In particular, false-positive rates on `new_home_address`,
  `legitimate_vpn` and `shared_network`.
* Model comparison across versions from stored predictions.
* `fraud-ai evaluate`.

## Stage 5: Neural-network fraud model

* A feed-forward network (Dense, ReLU, Dropout, Dense, ReLU, sigmoid) implementing the same
  `FraudModel` interface, evaluated with the Stage 4 framework against the baselines.
* It is adopted only if it measurably beats them; no special trust.

## Stage 6: Anomaly detection

* An autoencoder or isolation-based anomaly scores for behaviour without labels.
* Sequence models over per-user event histories.
* Anomaly scores become features/signals, not decisions.

## Stage 7: Local offline LLM

* An `ExplanationProvider` for a local runtime (Ollama / llama.cpp) at `LOCAL_LLM_ENDPOINT`.
* Input is `EvidencePacket` only; output is stored in `risk_assessments.explanation`.
* Analyst assistance: `fraud-ai investigate <event>`.
* It never changes the score or the decision.

## Stage 8: Real-time scoring engine

* Event → features → model → rules → risk decision within a latency budget.
* A service interface (for example an internal API or queue consumer), backpressure and
  idempotency.
* Monitoring: score drift, feature drift, and decision distribution.

## Stage 9: Analyst desktop interface (only if required)

* A client of the core platform for case review and labelling, which feeds `fraud_labels`.

## Stage 10: Deployment and security hardening

* PostgreSQL roles and least privilege, encryption at rest, and key rotation for
  pseudonymisation.
* Data-retention policies (e.g. raw IP expiry), audit logging, and dependency scanning.
* Container images and reproducible builds; a threat model and penetration test.
