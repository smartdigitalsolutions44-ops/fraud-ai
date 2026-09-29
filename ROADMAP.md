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

## Stage 9: Secure service and authentication integration ✅

* **A versioned machine-to-machine API** (`fraud-api-1.0.0`, FastAPI and uvicorn) over the
  unchanged Stage 8 engine. The routes cover:
  * `POST /v1/score`;
  * assessments, with review and authentication status;
  * reviews (list, get, resolve);
  * policy;
  * WebAuthn and payment step-up;
  * signed provider callbacks;
  * passkey registration;
  * an analyst-triggered investigation;
  * health and readiness;
  * Prometheus metrics.

  Direct library and CLI use is unchanged.
* **Service authentication.**
  * API keys (`fak_<id>.<secret>`) are stored only as salted SHA-256, verified in
    constant time, scoped and revocable;
  * `fraud-ai service-key create | list | revoke | scopes`;
  * identical 401s for every failure, and throttling of repeated failures.
* **Request integrity:**
  * HMAC-SHA256 signatures over `timestamp.body`, with per-key secrets derived from a
    master key;
  * a timestamp window and persisted replay tokens (concurrent replays tested on SQLite
    and PostgreSQL);
  * `Idempotency-Key` (same body replays; a different body gets 409 and is not
    processed).
* **Abuse and leakage controls:**
  * token-bucket limits per key and route, behind a `RateLimiter` interface;
  * size limits, including streamed bodies;
  * the strict event contract;
  * `arrival_time` gated by `score:replay`;
  * network intelligence gated by `signals:trusted`;
  * forwarding headers only from `TRUSTED_PROXIES`;
  * sanitised structured errors, correlation ids and security headers;
  * CORS off and OpenAPI hidden by default;
  * no ids in metric labels.
* **Step-up execution:**
  * WebAuthn via py_webauthn: public keys only; hashed, single-use, TTL- and
    session-bound challenges; user verification and sign counters enforced;
  * a `PaymentAuthenticationProvider` adapter with a deterministic **development fake**
    (not 3-D Secure). It has a hard timeout; an outage is `UNAVAILABLE`, never allow.
    Callbacks are signed, replay-protected and restricted to pending → terminal.
  * Results are append-only attempts. A terminal result creates a **new**
    `step_up_followup` assessment under `step-up-followup-1.0.0`:
    * `SUCCESS` gives `ALLOW_WITH_MONITORING`;
    * the other results give `MANUAL_REVIEW` with a review item.

    Scores are copied verbatim and the original is never changed.
* **Operations:**
  * readiness covers the database, migrations, the active policy and the verified primary
    artefact, never the LLM;
  * `fraud-ai service run | status | openapi`;
  * a Dockerfile (non-root, read-only compatible, no secrets, models or LLM) and
    docker-compose with PostgreSQL;
  * `scripts/service_benchmark.py`.
* **Migration `0007`.** A shared SQLite write lock prevents SQLite write deadlocks.
* **Results:** synthetic; see [REALTIME_SCORING.md](REALTIME_SCORING.md) §14. The single
  worker HTTP overhead is about 3 ms p50.
* **Deferred:**
  * a shared (Redis) rate limiter;
  * mTLS;
  * key expiry and rotation;
  * a real payment-processor adapter (sandbox contract tests);
  * an outbox for asynchronous provider calls;
  * retention jobs;
  * passkey management endpoints (list and revoke).

## Stage 10: Deployment hardening ✅

The result is a *deployment-hardened prototype* for real deployment **testing**. It is not
production-ready, and makes no compliance, fraud-reduction or savings claims. Details are
in [HARDENING.md](HARDENING.md).

* **Shared state:**
  * Redis shared state (atomic Lua token bucket, `SET NX` claims, compare-and-delete
    locks), failing closed with 503;
  * distributed rate limiting and replay protection, with race tests across OS processes
    and a 3-worker service.
* **Keys and secrets:**
  * API-key expiry (identical 401), `last_used_at`, and `service-key rotate` with a grace
    period;
  * signing-key versions with a previous-key grace window;
  * `*_FILE` secrets, with cloud integration points documented (no SDKs).
* **Start-up and configuration:**
  * fail-closed start-up in every worker;
  * configuration profiles that refuse placeholder secrets, http origins, unsafe CORS,
    the fake provider, unsigned production, the reference LLM in production, and
    per-process state with several workers;
  * readiness with Redis, the signing key and periodic artefact re-verification.
* **Records and governance:**
  * a hash-chained, trigger-protected audit log (`fraud-ai audit list|verify`);
  * retention jobs (`retention plan|run|status`; dry run by default; core records
    protected);
  * explicit policy promotion (shadow → evaluation → candidate) and activation safety
    (feature-version compatibility, `activated_by`);
  * migration `0008`.
* **Payment sandbox:** a Stripe test-mode adapter. It is **not exercised against Stripe**
  (no credentials), and its callbacks are tested with SDK-generated signatures.
* **Measurement:**
  * PostgreSQL load at 1/4/8/16 workers: best about 45 req/s at 4 workers on 4 vCPUs;
    CPU-bound;
  * a pool sweep;
  * model-cache cost;
  * a regression baseline;
  * multi-process invariants and chaos tests;
  * verified backup/restore and migration recovery.
* **Supply chain:**
  * pip-audit (2 vulnerable packages upgraded; 0 findings);
  * bandit (0 findings);
  * detect-secrets baseline and gitleaks (history and tree clean);
  * a CycloneDX SBOM.
* **Container and deployment:**
  * the container, verified as a torch-less variant: checks, size, Trivy (0 Python
    findings; 8 unfixed Debian HIGH CVEs reported);
  * a staging stack (PostgreSQL, Redis, TLS proxy, 2 workers), with the E2E passing
    through TLS;
  * CI workflow, example alerts, THREAT_MODEL.md, DISASTER_RECOVERY.md and
    RELEASE_CHECKLIST.md.

## Stage 11: Trust, integrity, privacy and real integration ✅

The result is a *security-hardened prototype*. It is still not production-ready, and makes no
compliance or fraud-reduction claims. Details are in [TRUST_CHAIN.md](TRUST_CHAIN.md),
[PRIVACY.md](PRIVACY.md) and [HARDENING.md](HARDENING.md) §23-26.

* **Requests:** signature v2 (method, canonical path/query, timestamp, body digest) with
  downgrade protection.
* **Models:**
  * Ed25519 model signatures (`models sign` / `verify-signature`), required in
    staging/production;
  * a read-once verified load from in-memory bytes;
  * a serialisation review.
* **Audit:** external audit anchors under a separate audit key (`audit anchor` /
  `verify-anchor`); a DBA-style rewrite is detected on PostgreSQL and on the staging stack.
* **Policies:** two-person activation with operator identity and approval expiry.
* **Database:** least-privilege roles (`db create-roles` / `grant-roles`), tested on real
  PostgreSQL, including backups with the restricted backup role.
* **Privacy:**
  * `privacy inventory`;
  * free-text PII rules;
  * a dry-run `privacy erasure-plan`;
  * opt-in core retention classes.
* **Releases:** a signed release manifest (`release manifest` / `verify`).
* **Container and CI:**
  * CI builds, scans and smoke-tests the full PyTorch image: all four jobs green in run
    36579194568 (1,395 MB; GRU loaded; 0 CRITICAL, 44 HIGH without an upstream fix, all in
    Debian base packages; HARDENING.md §26);
  * the Stage 10 CI failures were fixed (a setuptools floor, Trivy);
  * base-image research: distroless measured and **not** adopted.
* **Stripe:** the real test was **not** performed (no test credentials).
* **Migration:** `0009`.

## Stage 12: Recommendation (not started)

1. **Make the controls operational, not just available:**
   * run the compose/staging stacks with the least-privilege roles;
   * anchor to real WORM storage on a schedule, alerting on stale anchors;
   * bind `OPERATOR_ID` to SSO or hardware-backed identity.
2. **Supply chain:** image signing and provenance (cosign/SLSA), verified against the
   release manifest at deploy time.
3. **Models:** a non-executable format for the scikit-learn models, or sandboxed loading.
4. **External verification:**
   * the real Stripe test-mode run;
   * a load test on networked PostgreSQL and Redis;
   * an independent penetration test.
5. **Privacy:** pseudonymisation-key rotation, and an audited erasure *execution* path once
   the legal retention rules exist.
6. **Only then**, and only if required, an analyst desktop interface as a client of the API.
