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
  privacy-checked LLM evidence packet (interfaces plus reference logic; no ML; replaced
  in Stage 7).
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

## Stage 4: Evaluation framework ✅

Details are in [EVALUATION.md](EVALUATION.md). All evidence is synthetic.

* **Confidence intervals.** Seeded, stratified bootstrap intervals for PR-AUC, ROC-AUC,
  precision, recall, F1, FPR and FNR.
* **Walk-forward evaluation.** Expanding-window retraining with *as-of* training labels
  (later chargebacks never leak into earlier folds), with fold stability statistics.
* **Calibration.** Uncalibrated vs sigmoid vs isotonic, fitted on validation only. The
  report gives Brier, log loss, ECE and reliability buckets. Calibrators are persisted in
  `model_calibrations` (migration `0004`), where a constraint makes "fitted on test"
  impossible.
* **Costs.** Configurable expected cost per threshold, plus a low / review / high band
  analysis. Decision support only: no threshold is applied.
* **Scenarios and cohorts.** Scenario-level metrics with small-sample notes, and
  operational-cohort FPR checks (no demographic inference).
* **Error analysis.** Pseudonymised false-positive and false-negative reports.
* **Model comparison.** A paired PR-AUC bootstrap and McNemar test, agreement groups, and
  ensemble research (never persisted). No winner is ever declared.
* **Drift baseline.** PSI and Jensen–Shannon distance for eight tracked features.
* **Synthetic generator.** Giveaway signals removed, with a guard test against
  single-feature separation. Configurable fraud prevalence and a 1,000-user benchmark
  script.
* **CLI:** `fraud-ai evaluate confidence|walk-forward|calibration|scenarios|errors|costs|
  compare|drift-baseline|report|reproduce`.
* **Deferred:**
  * applying a calibrator in scoring (it needs an explicit adoption decision);
  * a live drift service (done in Stage 8 as monitoring warnings);
  * account-clustered bootstrap intervals.

## Stage 5: Neural-network fraud models ✅

Details are in [NEURAL_MODELS.md](NEURAL_MODELS.md). All evidence is synthetic.

* **Feed-forward network** (PyTorch, CPU-first) behind the same `FraudModel` contract.
  * It uses the Stage 3 preprocessing and the baselines' exact split.
  * Weighted `BCEWithLogitsLoss`; focal loss available.
  * AdamW; early stopping on validation PR-AUC with the best checkpoint restored.
  * Deterministic seeds.
  * `state_dict`-only artefacts, verified by hash before loading.
* **Model factory.** Training, scoring, walk-forward and evaluation handle every kind the
  same way.
* **Hyperparameter experiment runner** (36 configurations plus a loss comparison),
  selected on validation only.
* **Experimental autoencoder anomaly score.** It is not a fraud probability: scoring and
  comparisons refuse it.
* **Complementarity analysis:** disagreement groups, whether one model catches another's
  misses, and combinations. Research only.
* **CLI:**
  * `train neural-network`;
  * `neural experiments|training-history|inspect`;
  * `anomaly train-autoencoder|evaluate`;
  * `evaluate complementarity`.
* **Result on the 1,000-user synthetic world:**
  * gradient boosting remains stronger: PR-AUC +0.054 [−0.004, +0.115], McNemar p = 0.006;
  * the network does not recover gradient boosting's misses;
  * the anomaly score is a weak fraud signal but a useful drift indicator.

  No model or ensemble is adopted.

## Stage 6: Sequence models ✅

Details are in [SEQUENCE_MODELS.md](SEQUENCE_MODELS.md). All evidence is synthetic.

* **Point-in-time user event sequences** (`fraud-sequence-1.0.0`, default window of 16
  events plus the scored event, chosen on validation performance and cost).
  * They are read only from the append-only `events` table.
  * The definition is fingerprinted, the dataset records a digest of its sequences, and
    extraction is mutation-tested for leakage.
* **Models:** a GRU, a causal Transformer (2 layers, 4 heads) and a hybrid (GRU plus the
  static features).
  * They share one PyTorch training loop with the Stage 5 network, and go through the same
    registry, scoring and Stage 4 evaluation.
* **Generator:** temporal takeover attacks (A–E) and legitimate lookalikes.
* **Analysis:** complementarity overlap (caught only by each model) and a
  stealthy-takeover report.
* **CLI:** `sequence build|inspect|compare|stealth-report`, `train gru|transformer|hybrid`.
* **Result on the 1,000-user synthetic world:**
  * gradient boosting remains stronger: GB − GRU +0.053 [+0.019, +0.098];
  * the hybrid overlaps gradient boosting on PR-AUC, at a 1.4% FPR;
  * the GRU catches one stealthy takeover that gradient boosting misses.

  No sequence model is adopted.
* **Deferred:**
  * more worlds and seeds for the small-data walk-forward hint;
  * categorical embeddings for the static model.

## Stage 7: Local offline LLM analyst assistance ✅

* **Explanation only.** A local LLM explains *stored* outputs to a human analyst. It never
  scores, decides, blocks or approves, and never changes labels, thresholds or rules.
  `investigate` never rescores.
* **Evidence packet (`analyst-evidence-1.0.0`).**
  * Built from stored predictions, calibrators, the point-in-time snapshot, the Stage 6
    sequence summary and the labels known now.
  * Typed, deterministic and SHA-256-hashed, with stable ids `E1…` and controlled
    limitations `L1…`.
  * No identifiers, no free text, and not the synthetic scenario.
* **Privacy gate before generation.** It refuses:
  * sensitive names;
  * emails, IPs, cards, tokens, UUIDs and hex ids;
  * street addresses and phone numbers;
  * instruction-shaped values.

  Model output is scanned again.
* **Versioned prompt (`analyst-prompt-1.0.0`).** It separates instructions from data.
* **Structured, validated output (`investigation-explanation-1.0.0`).** The validator
  checks:
  * citations;
  * numbers against the cited evidence;
  * that "confirmed fraud" rests on a fraud label;
  * decision language;
  * privacy and length.

  Ten explicit failure modes, and no fallback to prose.
* **Runtimes.** `LocalLLMClient` for Ollama, a llama.cpp server, a llama.cpp process, and a
  deterministic reference template (not an LLM). Endpoints are local only and proxies are
  bypassed. Temperature 0 and seed 0 by default.
* **Storage.** `investigations` (migration `0005`): append-only and versioned per event,
  with packet and hash, versions, runtime, model, parameters, validation, latency and
  tokens. `investigate validate` re-checks a stored explanation and detects evidence
  changes.
* **CLI.**
  * `llm status`, `llm models`, `llm benchmark`;
  * `investigate <event-id>`, `investigate show`, `investigate validate`.
* **Evaluation.** Eleven synthetic case types, measured on explanation quality and safety
  (schema, citations, unsupported claims, privacy, decision language, coverage, latency),
  never on fraud metrics.
* **Measured.** On the 1,000-user synthetic world: 30 cases covering 10 of the 11 types.
  * The reference template scored valid 1.0, invalid citations 0, unsupported claims 0,
    privacy violations 0 and evidence coverage 0.72.
  * No real local model was available in the build environment (Ollama and llama.cpp
    were reported unavailable), so there is no LLM measurement yet (see
    [LLM_ANALYST.md](LLM_ANALYST.md) §12).
* **Deferred:**
  * a real multi-model comparison (needs installed models);
  * a boolean-contradiction check;
  * analyst feedback on explanations.

## Stage 8: Real-time scoring and risk-decision orchestration ✅

* **Hot path.** `FraudScoringService.score_event` runs contract → ingest (arrival time) →
  verified active deployment → information-cutoff check → point-in-time snapshot →
  sequence → cached, verified models → predictions → calibration → rules → policy →
  shadow → immutable assessment and review item. The LLM is not in the path.
* **Event contract `realtime-event-1`.** `event_id` and `schema_version` are required,
  the session is required for decision points, and future events are refused. Arrival
  time comes from the service clock; recorded values are accepted in replay only.
* **Arrival-time semantics.** Decisions are made at ingestion and frozen. Late events
  are flagged (`LATE_EVENT`) and cannot rewrite issued decisions. Out-of-arrival-order use
  of information falls back to review. Reassessment writes a new version.
* **Idempotency.** A unique idempotency key and a unique (event, version) pair: a
  redelivery returns the stored decision, and concurrent duplicates are tested on SQLite
  and PostgreSQL.
* **Policies (`risk-policy-schema-1.0.0`).** Immutable and hashed. Each pins the model
  set and calibration and holds the bands, rule-severity minimums, escalations, block
  corroboration and fallbacks, none of which may allow. Deployments are append-only;
  activation is explicit and validated.
* **Rules `fraud-rules-1.0.0`.** Six rules; VPN alone never matches.
* **Decisions.** `ALLOW`, `ALLOW_WITH_MONITORING`, `STEP_UP_AUTHENTICATION` (a
  placeholder request), `MANUAL_REVIEW` and `TEMPORARY_BLOCK` (expires; always reviewed).
  There is no permanent ban.
* **Shadow mode.** Models and policies are scored and recorded, never used. Tested:
  identical decisions with, without and with broken shadows.
* **Operations:**
  * the review queue (append-only outcomes);
  * `policy propose`, `simulate` and `compare` (Stage 4 costs; validation for bands, test
    for simulation);
  * monitoring: decisions, fallbacks, latency percentiles, the queue, shadow
    disagreement, and drift warnings (features, predictions, decision rates, prevalence,
    anomaly);
  * structured JSON decision logs.
* **Migration `0006`.**
* **Results:** synthetic; see [REALTIME_SCORING.md](REALTIME_SCORING.md) §11 and
  [RISK_POLICY.md](RISK_POLICY.md) §6.
* **Deferred:**
  * a queue consumer or network service boundary with backpressure;
  * a cross-user information-cutoff check;
  * review outcomes feeding labels;
  * profiling-driven caching.

## Stage 9: External authentication and payment integration (next; not started)

Recommended design, built on the Stage 8 action requests:

* **Adapters behind interfaces, not in the hot path.**
  * A `StepUpProvider` (WebAuthn/passkeys, OTP via an authentication service, 3-D Secure
    for payments).
  * A `PaymentGatewayAdapter` (authorise / hold / release).
  * Both consume the stored `action` request asynchronously through an **outbox** table
    written in the same transaction as the assessment. This gives exactly-once delivery
    and no dual writes.
* **Outcomes are new events.** A step-up passed or failed, or a gateway result, comes
  back as a new typed event (for example `STEP_UP_COMPLETED`). It is ingested like any
  other event and may lead to a reassessment (a new version). An issued decision is never
  mutated.
* **Safety.**
  * A temporary block becomes a gateway *hold* with an expiry. It is never a permanent
    refusal.
  * Idempotency keys are passed to providers.
  * Timeouts map to explicit, conservative outcomes.
  * Provider failures are recorded like Stage 8 failures.
* **Security.**
  * Provider credentials come only from a secrets manager, never from code or `.env`
    in production.
  * Webhooks are signature-verified with replay protection.
  * No card data enters the platform: provider tokens only, as today.
* **Testing.**
  * Contract tests against provider sandboxes or recorded fixtures.
  * The Stage 8 failure matrix is extended to provider failures.
  * Shadow mode for new providers: requests are logged, not sent.
* **Still no real-world claims.** The strength of authentication and the fraud reduction
  have to be measured with real traffic and real labels, which the synthetic platform
  cannot do.

## Stage 10: Analyst desktop interface (only if required)

* A client of the core platform for case review and labelling, which feeds `fraud_labels`.

## Stage 11: Deployment and security hardening

* PostgreSQL roles and least privilege, encryption at rest, and key rotation for
  pseudonymisation.
* Data-retention policies (e.g. raw IP expiry), audit logging, and dependency scanning.
* Container images and reproducible builds; a threat model and penetration test.
