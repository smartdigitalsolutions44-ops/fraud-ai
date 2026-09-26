# Roadmap

Each stage builds only on what the previous stages have made trustworthy. We do not jump
ahead: models are only as good as the data and features beneath them.

## Stage 1: Database and event architecture ✅

* Python package with a `fraud-ai` CLI and `python -m fraud_ai`.
* Typed configuration from environment variables; production safety guards.
* Internal event model (envelope plus strict per-type payloads, schema versioning).
* Event processor: idempotent, atomic per event, pseudonymising, history-keeping.
* PostgreSQL/SQLite schema with Alembic migration `0001`.
* Model-version registry, prediction storage, risk policy/rules boundary, and a
  privacy-checked LLM evidence packet (interfaces plus reference logic; no ML).
* Deterministic synthetic scenarios for future ML experimentation.
* Security rules: no PAN/CVV/PIN/password storage, keyed hashing, log redaction.

## Stage 2: Feature engineering ✅

* 107 point-in-time features in 11 categories, `fraud-features-1.0.0`, with
  machine-readable definitions, a pinned fingerprint and the generated FEATURES.md.
* An explicit missing-data model (`unknown`, `not_observed`, `not_applicable`), with no
  sentinel values.
* Deterministic SHA-256 hashing; `feature_snapshots` (migration `0002`) that are
  idempotent, drift-detecting and tamper-evident.
* Leakage tests:
  * the canonical 10:00/11:00 test;
  * label leakage (chargebacks that arrive later);
  * a full-history versus truncated-history property test;
  * cache corruption;
  * mutation checks.
* Batch extraction and a training-dataset builder with a documented label availability
  policy. Labels are returned separately.
* CLI: `features catalog|show|snapshot|validate`, `dataset build`.
* Deferred: a concrete rule set for the rules engine. Rules are policy and should be
  written against the Stage 4 evaluation results, not guessed.

## Stage 3: Baseline fraud models ✅

* Logistic regression, random forest and histogram gradient boosting (scikit-learn only)
  behind the `FraudModel` contract.
* A leakage-guarded `ModelMatrix` and deterministic, serialised preprocessing that keeps
  the three missing reasons distinct.
* Time-ordered (fraction or date) train/validation/test splits.
* Class weighting by default.
* Metrics, threshold analysis, a validation-selected threshold, overfitting warnings and
  non-LLM inspection (coefficients, impurity and permutation importance).
* Versioned, SHA-256-verified artefacts under `models/`; reproducibility metadata in
  `model_versions` (migration `0003`); a training manifest with library versions and the
  seed.
* `score_event` → `model_predictions`, linked to the exact feature snapshot, idempotent,
  with conflicts refused.
* Synthetic data expanded so that fraud is spread over time and overlaps legitimate
  behaviour:
  * stealthy takeovers;
  * new-account card fraud versus legitimate new customers;
  * friendly fraud;
  * large legitimate purchases and phone upgrades.
* CLI: `train logistic|random-forest|gradient-boosting|all`, `models list|show|activate`,
  `evaluate`, `compare-models`, `score`.

## Stage 4: Evaluation framework

* Stage 3 already reports PR-AUC, ROC-AUC, precision, recall, F1, FPR and FNR, a
  threshold analysis and overfitting warnings. Stage 4 adds:
  * bootstrap confidence intervals;
  * calibration curves and recalibration;
  * cost-weighted metrics (fraud loss versus customer friction);
  * rolling-origin (walk-forward) evaluation;
  * statistical tests between models on the same split.
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
