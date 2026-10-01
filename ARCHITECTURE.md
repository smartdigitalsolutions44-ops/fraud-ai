# fraud-ai architecture

## 1. What this is and why it is not a web application

`fraud-ai` is a **locally runnable Python software platform** for fraud prevention. It is a
package with a real entry point (`fraud-ai` / `python -m fraud_ai`), a persistent database,
versioned schema migrations, and a library of components that later stages extend.

It is deliberately *not* a website, dashboard, or browser application:

* **Fraud decisions are a backend concern.** The valuable parts are the historical data, the
  feature pipeline, the models and the policy engine. None of these need a browser, and
  coupling them to a UI framework would make them harder to test, version and reproduce.
* **Reproducibility.** Every model prediction must be traceable to a model version, a
  feature version and a dataset version. That is a data-engineering problem solved with a
  database, migrations and code, not with pages.
* **Local/offline operation.** The long-term design includes a local LLM and local model
  artefacts. The platform must run on an analyst's machine or a private server with no
  external services.
* **Integration shape.** In production the platform receives events from other systems
  (apps, payment gateways) and returns decisions. The natural interfaces are a library API,
  a CLI and a machine-to-machine scoring service (Stage 9) - not HTML.

The analyst UI came in Stage 13, as planned, as a *client* of this core: **SENTINEL**
(`sentinel-console/`, §18). It calls the `/v1` API through its own server and contains no
fraud logic.

## 2. Event flow

```
Incoming Event (JSON from app / gateway / batch / synthetic generator)
      │  fraud_ai.core.events.parse_event        – envelope + per-type payload schema,
      ▼                                            forbidden-data check (PAN, CVV, passwords)
Event Processor (fraud_ai.ingestion)             – idempotent on event_id, SAVEPOINT per event
      │  pseudonymise IP / device / address      – keyed HMAC (fraud_ai.security.hashing)
      │  resolve Device, UserDevice, NetworkIdentity (first/last seen, counters)
      │  append sanitised event to `events`
      │  apply to domain tables (logins, addresses, payments, transactions, labels, …)
      │  record network intel as `fraud_signals` (evidence, never verdicts)
      ▼
Fraud Database (PostgreSQL in production, SQLite locally)
      ▼
Feature Engineering (fraud_ai.features)          – point-in-time, versioned, hashed vectors
      │  every query bounded by timestamp <= as_of; the scored event never counts itself
      │  snapshots persisted in feature_snapshots (idempotent, drift-detecting)
      │  labels resolved *separately* by fraud_ai.datasets under a label-availability policy
      ▼
ML Fraud Model (fraud_ai.models)                 – P(fraud) from a verified, versioned artefact
      │  ModelMatrix (feature values only) → fitted Preprocessor → sklearn baseline
      │  prediction stored in model_predictions, linked to the exact feature snapshot
      │  (neural networks are Stage 5 and must beat these baselines)
      ▼
Rules Engine (fraud_ai.rules)                    – fraud-rules-1.0.0: explicit, versioned
      ▼                                            security conditions emitting evidence
Risk Policy (fraud_ai.risk)                      – versioned, immutable policy: calibrated
      │                                            score bands + rule minimums + fallbacks
      ▼
Decision (ALLOW / ALLOW_WITH_MONITORING / STEP_UP_AUTHENTICATION / MANUAL_REVIEW /
          TEMPORARY_BLOCK) → immutable risk_assessments (+ review_queue)
      │  orchestrated in real time by FraudScoringService (fraud_ai.realtime, Stage 8)
      ▼
Local Offline LLM (Stage 7, fraud_ai.llm)        – explains STORED outputs from evidence only
      │  privacy-checked EvidencePacket → versioned prompt → local runtime
      │  validated, cited explanation → investigations (append-only); never a decision
```

Stages 1-6 implement everything up to and including ML scoring: events, the fraud
database, point-in-time features and snapshots, training datasets, and trained, versioned
models (baselines, neural and sequence) whose probabilities are stored as predictions.
Stage 7 adds the local LLM *explanation* layer over those stored outputs. Stage 8 adds
the real-time orchestration: rules, versioned risk policies and immutable decisions,
with shadow mode, fallbacks, review and monitoring. See
[REALTIME_SCORING.md](REALTIME_SCORING.md) and [RISK_POLICY.md](RISK_POLICY.md).
Decisions are internal policy outputs; nothing calls a payment or authentication system.

### The event envelope

Every event has: `event_id`, `event_type`, `timestamp` (aware, normalised to UTC), `user_id`,
`session_id`, `device_id`, `source`, `metadata`, `schema_version`.

`metadata` is validated against a strict, event-type specific schema
(`PAYLOAD_SCHEMAS` in `fraud_ai/core/events.py`). Unknown fields are rejected so sensitive
data cannot slip in under an unexpected key. `schema_version` allows the payload contract to
evolve; the processor rejects unsupported versions rather than guessing.

Event types: `ACCOUNT_CREATED`, `LOGIN_ATTEMPT`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`,
`PASSWORD_RESET`, `NEW_DEVICE`, `ADDRESS_ADDED`, `ADDRESS_CHANGED`, `PAYMENT_METHOD_ADDED`,
`TRANSACTION_CREATED`, `TRANSACTION_APPROVED`, `TRANSACTION_DECLINED`, `CHARGEBACK`,
`FRAUD_CONFIRMED`.

## 3. The components and how they differ

| Component | Question it answers | Nature | Stage |
|---|---|---|---|
| **Database** | *What happened, and when?* | Facts. Append-mostly history, never inferred. | 1 |
| **Feature engineering** | *How does this event compare to history?* | Deterministic transforms of facts into a numerical vector, computed point-in-time. | 2 |
| **ML model** | *How likely is this to be fraud?* | A statistical estimate, P(fraud), learned from labelled history and measured with metrics. | 3–6 |
| **Neural network** | (same as ML model) | *One kind* of ML model. Not a separate layer. | 5 |
| **Rules engine** | *Does this violate security policy?* | Explicit, human-written, versioned conditions that emit evidence (`fraud-rules-1.0.0`). | 1 (engine), 8 (rule set) |
| **Risk policy** | *What do we do about it?* | A versioned, immutable policy that maps the calibrated score and rule matches to a decision, with explicit fallbacks. | 8 |
| **LLM** | *Why was this decided, in plain words?* | Explanation and analyst assistance from structured evidence. | 7 |

In one sentence each:

* **ML predicts risk.** It outputs a calibrated probability, stored with the model and feature
  versions that produced it.
* **The neural network is one possible ML model.** It implements the same `FraudModel`
  interface as logistic regression or gradient-boosted trees and competes with them on the
  same evaluation framework. It gets no special trust.
* **Rules enforce security policy.** They can raise a decision to a minimum level (e.g.
  "recent password reset ⇒ at least step-up"), but they never lower one.
* **The risk policy decides.** The decision is never a bare `if p > x: block`. It is a
  versioned, hashed `RiskPolicyDefinition`:
  * calibrated score bands;
  * rule-severity minimums;
  * escalations;
  * corroboration: a model alone never blocks;
  * conservative fallbacks per failure.

  It is applied by the pure `decide()`.
* **The LLM explains and assists investigation.** It is *not* the classifier, the risk
  engine, the rules engine or the decision maker.
  * It receives a typed, privacy-checked `EvidencePacket` built from *stored* outputs
    (predictions, features, sequence summary, labels), never raw personal data or free text.
  * It returns a cited explanation, which is stored only if it passes validation.
  * Its text never replaces or alters a score, label, threshold, rule or decision (Stage 7,
    [LLM_ANALYST.md](LLM_ANALYST.md)).

## 4. Package layout

```
fraud_ai/
  config/      typed settings from environment variables (pydantic-settings)
  core/        event envelope, payload schemas, enums, domain exceptions
  database/    SQLAlchemy models, portable types, engine/session, migration helpers
  ingestion/   EventProcessor - the single write path into the database
  features/    definitions, windows, vector + validation, point-in-time history queries,
               per-category extractors, extraction API, batch extraction, snapshots
  datasets/    label-availability policy, label resolution, training-dataset builder
  models/      FraudModel contract, leakage-guarded ModelMatrix, preprocessing, time
               splits, metrics/threshold analysis, baselines, training, scoring, registry
               neural.py / anomaly.py (PyTorch), factory (every model kind), experiments,
               grouped permutation importance
               sequence_models.py (GRU / causal Transformer / hybrid), torch_training
               (the one shared PyTorch training loop)
  sequences/   Stage 6 point-in-time event sequences: versioned definition + fingerprint,
               extraction from the append-only events table, SequenceMatrix inputs
  evaluation/  bootstrap/paired statistics, walk-forward, calibration, costs and bands,
               scenario/cohort/error analysis, comparison and ensembles, drift baseline,
               shortcut detection, complementarity, anomaly evaluation, JSON reports
  models/      FraudModel interface, model-version registry, prediction storage
  rules/       Rule / RuleSet engine and the versioned rule set fraud-rules-1.0.0
  risk/        RiskPolicyDefinition, the deterministic decide(), policy registry
               (immutable versions, append-only deployments), offline proposal /
               simulation / comparison
  realtime/    Stage 8 FraudScoringService (hot path), event contract, model cache,
               review queue, monitoring (drift, shadow), structured decision logs
  llm/         Stage 7 analyst assistance: evidence builder + typed EvidencePacket, privacy
               gate, versioned prompt, output schema + faithfulness validator, local
               runtimes (Ollama, llama.cpp server/process, reference template), the
               investigation service (append-only storage) and the explanation benchmark
  service/     Stage 9 HTTP boundary (FastAPI): app factory, ASGI middleware, /v1 routes,
               API keys, HMAC signatures + replay tokens, idempotency, rate limiting,
               network-signal integrity, metrics, sanitised errors, health/readiness
  stepup/      Stage 9 step-up execution: follow-up policy and immutable follow-ups,
               WebAuthn (py_webauthn), external payment-authentication adapter (+ dev fake)
  security/    keyed pseudonymisation, sensitive-data detection/redaction, key handling
  data/        deterministic synthetic scenario generator and seeding
  cli/         the `fraud-ai` command
  utils/       logging (with redaction), money, time
migrations/    Alembic environment and versions
tests/         pytest suite (SQLite always; PostgreSQL when TEST_POSTGRES_URL is set)
scripts/       developer scripts, benchmarks and a sample event file
Dockerfile, docker-compose.yml
               Stage 9 container image (non-root, read-only compatible) and local stack
data/, models/, evaluation/
               local runtime data, model artefacts and evaluation reports (git-ignored)
```

## 5. Database design

Tables (revisions `0001`-`0003`):

| Table | Purpose |
|---|---|
| `events` | Append-only log of every ingested event (sanitised metadata). |
| `users` | Accounts: pseudonymous `external_ref`, creation time, status. No names/emails. |
| `devices` | Application-level device history keyed by a device-identifier hash. |
| `user_devices` | Which accounts used which device; per-user trust and login counters. |
| `network_identities` | One row per IP hash: ASN, country, network type, VPN/proxy/Tor/datacenter intel, first/last seen, distinct users, login counters. |
| `network_events` | Each observation of an IP with the intel snapshot *at that time*. |
| `login_events` | Attempts, successes and failures, with device and network. |
| `addresses` | Address history (hash + coarse location); changes supersede, never overwrite. |
| `payment_methods` | Tokenised payment methods: vault token reference and safe metadata only. |
| `transactions` | Amount in integer minor units + currency, status lifecycle. |
| `security_events` | Password resets, new devices, address changes, payment method additions. |
| `fraud_signals` | Individual pieces of evidence (e.g. `vpn_detected`, value 0.93). |
| `fraud_labels` | Ground truth with `labelled_at` (when it became known) and `label_source`. |
| `model_versions` | Reproducibility record: dataset/feature versions, metrics, path, active. |
| `model_predictions` | Every model output, FK'd to the exact model version. |
| `risk_assessments` | (0006) Immutable, versioned decisions: an idempotency key, the event and arrival time, the policy/deployment/rules versions, model and shadow scores, rule results, reason codes, action request, per-stage latency and failures/fallbacks. |
| `feature_snapshots` | (0002) Exact hashed feature vector per (event, feature version, as_of). |
| `model_calibrations` | (0004) Calibrators fitted on a non-test split of a model's dataset. |
| `risk_policies` | (0006) Immutable, hashed policy versions with their derivation and drift baselines. |
| `policy_deployments` | (0006) Append-only activation history: the active policy, shadow models and shadow policies. |
| `review_queue`, `review_outcomes` | (0006) Manual-review entries and append-only outcomes; never rewrite the assessment. |
| `investigations` | (0005) Validated, cited LLM explanations: append-only, versioned per event, with the evidence packet and its hash, prompt/schema versions, runtime, model and generation parameters. Never a score or decision. |

Revision `0002` also added `transactions.decision_outcome` (the immutable authorisation
outcome; `status` is overwritten by chargebacks), `addresses.verified_at`,
`payment_methods.verified_at`, `network_events.is_mobile_network`, account-lifecycle event
types (email/phone verification and change, MFA enrol/removal, address and payment-method
verification - none carries contact details) and one query-plan-justified index.

Key decisions:

* **History, not state.** Entities have first/last-seen timestamps; `network_events` snapshots
  intel per observation so "country changed" and "ASN changed" are computable later even if
  the intel for an IP changes.
* **Point-in-time safety.** Labels carry `labelled_at`; synthetic legitimate labels are only
  "known" at the end of the observation window. Counters and "latest" attributes on entity
  rows (device/IP counters, `last_seen_at`, `user_devices.is_trusted`, current intel,
  `transactions.status`) are *current-state caches*: convenient operationally, never read
  by feature engineering, which derives everything from timestamped rows (see FEATURES.md).
* **Money is exact.** `BIGINT` minor units plus ISO 4217 code, with currency exponents
  (JPY 0, BHD 3). Floats are rejected at the event boundary.
* **Portable enums.** Enums are `VARCHAR` + named `CHECK` constraints, identical on both
  backends and trivial to extend in a migration.
* **Integrity in the database, not only in Python.** Foreign keys (enforced on SQLite via
  `PRAGMA foreign_keys`), non-negative amounts, probability ranges, `predicted_class`
  consistent with `threshold`, one active version per model (partial unique index), fraud
  labels require a fraud type, and a composite FK from predictions to model versions.
* **Timezones.** All timestamps are aware UTC (`timestamptz` on PostgreSQL; normalised on
  SQLite by a `TypeDecorator`).
* **Migrations are the source of truth** for the deployed schema; a test asserts Alembic's
  autogenerate finds zero differences between the migration and the ORM models on both
  backends.

## 6. Security and privacy decisions

* **Never stored:** full card numbers, CVV/CVC, PINs, passwords, raw authentication secrets
  or tokens. There is no column for them. Events containing them are **rejected** (not
  silently redacted), and the error reports only the JSON path, never the value.
* **Payment methods** are referenced by a vault `token_reference` with safe metadata
  (brand, last four, funding type, issuer country, hashed vault fingerprint).
* **Pseudonymisation:** IPs, device identifiers, postal addresses and payment fingerprints
  are stored as HMAC-SHA256 with a secret key, so reuse across accounts is measurable but
  values cannot be reversed or brute-forced without the key. Raw IPs are stored only when
  `STORE_RAW_IP=true`. Raw addresses are never stored.
* **Keys:** `PSEUDONYMISATION_KEY` is mandatory in staging/production. In development a
  random key is generated once into `data/.pseudonymisation_key` (mode 0600). No secrets
  exist in source code.
* **Logging** passes through a redaction filter (card numbers, `password=…`, tokens, CVV)
  as defence in depth; code is written not to log such data in the first place. Database
  URLs are always printed with the password masked.
* **Network intelligence is evidence, not proof.** VPN, proxy, Tor and datacenter flags are
  stored as signals with their source and confidence. The synthetic data includes long-term
  legitimate VPN users precisely so models learn this. The platform does **not** attempt to
  unmask users behind VPNs or proxies.
* **No invasive surveillance.** Device data is limited to an app-level identifier hash, OS
  family, client family and device type. There is no fingerprinting.
* **Real-time decisions.** Decision logs carry pseudonyms and categories only. Review
  notes with personal data are refused. Rejected events never echo values. Decisions are
  internal outputs: there are no permanent bans and no external calls.
* **LLM privacy.** Evidence values are typed tokens, numbers or booleans. Free text cannot
  be represented.
  * The privacy gate refuses the packet before generation if it finds any of:
    * sensitive names;
    * emails, IPs, card numbers, tokens, UUIDs or long hex identifiers;
    * street addresses or phone numbers;
    * instruction-shaped text.
  * The event is referenced by a one-way pseudonym.
  * Model output is scanned again before storage.
  * `LOCAL_LLM_ENDPOINT` must be localhost or a private/loopback address. HTTP to the
    runtime bypasses any configured proxy.
* **Environment guards:** staging/production require PostgreSQL and a configured key;
  synthetic seeding is refused there.
* **Synthetic data safety:** synthetic IPs come only from private, CGNAT and documentation
  ranges; ASNs from the private-use range. No real network or person is referenced.

## 7. Synthetic data

`fraud_ai.data.synthetic` generates a deterministic (seeded) event stream that is ingested
through the real `EventProcessor`. Scenarios:

| Scenario | Behaviour | Label |
|---|---|---|
| `normal` | Stable device and address, consistent spend, occasional mobile-carrier (CGNAT) IPs | legitimate |
| `legitimate_vpn` | VPN for most logins over a long history, known device/address, normal spend | legitimate |
| `shared_network` | Several accounts behind one office NAT plus shared carrier IPs | legitimate |
| `new_home_address` | Moves house: address change, new ISP, maybe new laptop, one larger purchase to the new address | legitimate |
| `account_takeover` | Varied since Stage 4: loud (failed logins, password reset, new device and network, account changes), quiet credential reuse from a domestic IP, or a hijacked session on the victim's own device; ships to a new drop address, the victim's address, or buys digital goods; then chargeback/report | fraud |
| `suspicious_velocity` | A credential-stuffing burst: many accounts, few IPs, one automation client, unknown usernames, a few successes | fraud (compromised logins) |

The `new_home_address` and `legitimate_vpn` scenarios exist so a model cannot learn "new
address = fraud" or "VPN = fraud". `users.synthetic_scenario` records the generating
scenario for analysis and must never be used as a model feature (a test enforces that the
feature catalogue does not reference it).

## 8. Feature engineering (Stage 2)

Summary (details and every feature in [FEATURES.md](FEATURES.md)):

* **Definitions are data.** `fraud_ai/features/definitions.py` declares 107 features
  (type, category, nullability, units, bounds, applicability, sources, leakage notes). A
  released feature version is immutable and its fingerprint is pinned in the tests.
* **One history layer.** `fraud_ai/features/history.py` holds every query. Each query is
  bounded by `<= :as_of`, excludes the scored event, reads no mutable caches and aggregates
  in the database. Statements are built once with bind parameters, so the number of queries
  per vector is constant (about 17 on average) whatever the account's history size.
* **Explicit missing data.** Values and missing reasons (`unknown`, `not_observed`,
  `not_applicable`) are separate; there are no sentinel values.
* **Deterministic and hashed.** Canonical JSON (fixed float precision) hashed with SHA-256
  produces identical vectors on SQLite and PostgreSQL.
* **Snapshots.**
  * `feature_snapshots` rows are unique per (event, version, as_of).
  * Persisting the same vector twice is idempotent.
  * A recomputation that disagrees raises a drift error; nothing is overwritten.
  * Loading a snapshot verifies the stored payload against its hash.
* **Labels stay outside vectors.** `fraud_ai.datasets` resolves labels separately under
  `label-policy-1`:
  * only labels known at the cutoff count;
  * negatives must have matured;
  * events with unknown or impossible labels are refused, with the reason recorded.
* **Stage 2 does not include:** trained models, fraud decisions, feature weights, or any
  claim about fraud reduction.

## 9. Baseline models (Stage 3)

Summary (details in [MODELS.md](MODELS.md)):

* **Input.** `ModelMatrix` is built from feature values only. Identifiers, timestamps,
  hashes and labels stay on the dataset examples. Metadata-shaped column names are
  rejected, as are mixed feature versions and altered catalogues.
* **Preprocessing.** It is deterministic and serialised as JSON next to the model. The
  three missing reasons survive as indicator columns or one-hot categories.
* **Time-ordered train/validation/test split.** Oldest 70% / next 15% / latest 15% by
  default, or an explicit date split. Ties never straddle a boundary.
* **Class imbalance.** Class weighting is the default; random oversampling is available
  for experiments only.
* **Metrics.** PR-AUC, ROC-AUC, precision, recall, F1, FPR, FNR and a confusion matrix, for
  every split, plus a threshold analysis and overfitting warnings. Accuracy is never
  reported.
* **Versioning.** `model_versions` (migration `0003`) records the dataset and catalogue
  fingerprints, preprocessing version, split sizes, hyperparameters, seed, library
  versions and an artefact SHA-256. The digest is verified *before* anything is
  unpickled. Existing versions are never overwritten.
* **Scoring.** `score_event` uses the point-in-time snapshot as of the event. It stores one
  prediction per (event, model version); a rescore that disagrees is an error, never an
  overwrite. The threshold only labels `predicted_class`; nothing is blocked.

## 10. Evaluation (Stage 4)

Summary (details in [EVALUATION.md](EVALUATION.md)):

* **One recorded dataset.** Evaluation rebuilds the model's recorded dataset from the
  training manifest and verifies its fingerprint. Every model in a comparison must share
  it, so all comparisons use identical examples.
* **Uncertainty is reported, not hidden.** Seeded bootstrap intervals are given for every
  headline metric. Paired tests are used for comparisons, and their conclusions never name
  a winner.
* **Time.** Walk-forward folds retrain fresh models using labels as known at each cutoff.
* **Calibration** is fitted on validation only. It is stored in `model_calibrations`
  (migration `0004`, which forbids `fitted_on = 'test'`) and is not applied to scoring.
* **Decision support, not decisions.** Cost curves and risk bands report the cheapest
  threshold under stated assumptions but never apply it. The rules and risk engines stay
  unchanged.
* **Privacy.** Error reports use one-way pseudonyms. Cohorts are operational, never
  demographic.
* **Artefacts.** Sorted JSON under `evaluation/<model-id>/`, reproducible apart from
  `generated_at`.

## 11. Neural models (Stage 5)

Summary (details in [NEURAL_MODELS.md](NEURAL_MODELS.md)):

* **Same contract, same split.** The feed-forward network implements `FraudModel` and uses
  the Stage 3 preprocessing and the baselines' exact time-ordered split. Only the
  *validation* split is offered to `train()`, for early stopping.
* **One factory.** `fraud_ai/models/factory.py` builds and loads every kind. Training,
  scoring, walk-forward retraining and evaluation contain no neural special cases.
* **Safe artefacts.**
  * `state_dict` tensors only, loaded with `weights_only=True`.
  * A SHA-256 digest is verified before anything is read, and every file is listed in
    `artifact_hashes.json`.
* **Determinism.** Seeded, deterministic algorithms and one CPU thread give bit-identical
  CPU results. The PyTorch version and device are recorded.
* **Anomaly scores are a different kind of output.** Models declare a `score_kind`, and
  `anomaly_score` models are refused by scoring, the default comparisons and fraud
  evaluation contexts. The autoencoder is research: it is never combined into a
  production score.

## 12. Sequence models (Stage 6)

Summary (details in [SEQUENCE_MODELS.md](SEQUENCE_MODELS.md)):

* **Point-in-time sequences.** A scored event's input is the user's last N events strictly
  before it, plus the event itself.
  * They are read only from the append-only `events` table, never from mutable state.
  * Each historical event is encoded with what was known at that event.
* **Versioned and verifiable.** `fraud-sequence-1.0.0` has a fingerprint over the window,
  vocabularies and feature transforms. Each dataset records a digest of its sequences, and
  evaluation refuses to run if they no longer reproduce.
* **One input object.** `SequenceMatrix` *is* a `ModelMatrix` plus aligned sequences.
  Tabular models ignore the sequences, so every model still goes through the same
  training, scoring, walk-forward and evaluation code.
* **No identity embeddings.** Vocabularies cover event, network, device, authentication
  and channel *types* only.

## 13. Local LLM analyst assistance (Stage 7)

Summary (details in [LLM_ANALYST.md](LLM_ANALYST.md)):

* **Explanation, never decision.**
  * `fraud-ai investigate <event-id>` explains an event from what the platform already
    stored.
  * The event is **never rescored**; it needs stored predictions.
  * Nothing writes to scores, labels, thresholds, rules or decisions.
* **Evidence packet.** A deterministic, SHA-256-hashed packet with stable ids (`E1…`,
  `L1…`) and controlled limitation texts. It contains no identifiers and no free text.
* **Validated output only.** The output must be schema-valid JSON in which:
  * every citation exists;
  * every number matches the evidence cited;
  * "confirmed fraud" requires a fraud label;
  * there is no decision language and no identifier.

  Failures are structured, for example `timeout`, `invalid_json` or
  `unsupported_citation`, and are never stored.
* **Append-only storage.** Each explanation is stored in `investigations` (migration
  0005) as a new version per event. The row records:
  * the packet and its hash;
  * the prompt, evidence and explanation schema versions;
  * the runtime, model and generation parameters;
  * the validation result.
* **Local runtimes.** Behind `LocalLLMClient`: Ollama, a llama.cpp server, a llama.cpp
  process, and a deterministic reference template (not an LLM) for offline use and as the
  benchmark baseline.

## 14. Real-time scoring (Stage 8)

Summary (details in [REALTIME_SCORING.md](REALTIME_SCORING.md) and
[RISK_POLICY.md](RISK_POLICY.md)):

* **One idempotent hot path.** `FraudScoringService.score_event` runs the contract,
  ingestion, snapshot, sequence, cached models, calibration, rules, policy, shadow and
  persistence. Redelivery returns the stored assessment, and concurrent duplicates
  cannot create two.
* **Arrival time.** Decisions are made at ingestion from what had arrived. Late events
  are flagged and never rewrite earlier decisions, and out-of-arrival-order use of
  information is refused.
* **Versioned authority.** Models give evidence and the versioned policy decides.
  Policies and deployments are hashed and immutable, and activation is explicit and
  validated.
* **Shadow mode.** Shadow models and policies are scored and recorded, never used.
* **Failure safety.** Every failure maps to a conservative fallback; none allows.
* **Operations.** A review queue, offline simulation and comparison, monitoring with
  drift warnings, and structured logs. The LLM stays post-decision.

## 15. Service boundary and step-up (Stage 9)

Summary (details in [API.md](API.md), [SERVICE_SECURITY.md](SERVICE_SECURITY.md),
[AUTHENTICATION.md](AUTHENTICATION.md) and [DEPLOYMENT.md](DEPLOYMENT.md)):

```
merchant backend ─TLS─► proxy ─► ServiceMiddleware (correlation id, size limit, headers, metrics)
  ─► /v1 route: API key → rate limit → signature → scope → strict contract
  ─► FraudScoringService (Stage 8, unchanged, no LLM) ─► immutable assessment
  ─► STEP_UP? ─► WebAuthn (py_webauthn) | PaymentAuthenticationProvider (external; fake in dev)
  ─► authentication_attempts ─► NEW follow-up assessment (scores copied, original untouched)
```

* **Packages.**
  * `fraud_ai/service/` holds the transport and security: app, middleware, routes,
    dependencies, keys, signatures, idempotency, rate limit, network, metrics, errors
    and health.
  * `fraud_ai/stepup/` holds the domain: outcomes (the follow-up policy
    `step-up-followup-1.0.0`), WebAuthn and payment.
  * Both are FastAPI-free where possible. Routes only adapt: no business logic is
    copied into handlers.
* **Tables (migration `0007`):**
  * `service_api_keys`, `request_idempotency`, `request_replay_tokens`;
  * `webauthn_credentials`, `authentication_challenges`, `authentication_attempts`;
  * `payment_auth_requests`.
* **Invariants:**
  * scores are never changed by an adapter;
  * assessments are never mutated;
  * no step-up path returns `ALLOW`;
  * the LLM is reachable only from its own analyst endpoint;
  * the platform never authenticates cardholders or touches card data.
* **SQLite write lock.** SQLite writers share one process-wide lock per engine
  (`database.engine.write_lock`); PostgreSQL relies on the unique constraints.

## 16. Deployment hardening (Stage 10)

Summary; the details and measurements are in [HARDENING.md](HARDENING.md).

```
worker 1..N ─┬─► PostgreSQL  durable: events, assessments, reviews, labels, policies,
             │               deployments, lifecycle events, model registry, API keys,
             │               audit_events (hash chain, UPDATE/DELETE refused by triggers)
             ├─► Redis        short-lived only: rate-limit buckets (Lua token bucket),
             │               replay claims (SET NX PX), locks; errors → 503 (fail closed)
             └─► models (ro)  SHA-256-verified before load; per-worker cache
```

**Packages:**

* `fraud_ai/state/`: `SharedState` with `MemoryState` and `RedisState`.
* `fraud_ai/audit.py`: the hash-chained audit log.
* `fraud_ai/retention.py`: retention jobs over short-lived records only.
* `fraud_ai/risk/promotion.py`: shadow → evaluation → candidate, with activation gated in
  staging and production.
* `fraud_ai/config/secrets.py`: `*_FILE` secrets.
* `fraud_ai/service/startup.py`: fail-closed start-up in every worker, model warm-up, and
  the configuration audit.
* `fraud_ai/stepup/stripe_provider.py`: the Stripe test-mode adapter (not exercised
  against Stripe).

**Migration `0008`:**

* API-key `expires_at`, `last_used_at` and `rotated_from_key_id`;
* `policy_deployments.activated_by`;
* the `audit_events` table, with its immutability triggers;
* the `policy_lifecycle_events` table.

**Invariants added:**

* Durable history never lives in Redis.
* No failure mode allows. The matrix is in HARDENING.md §8.
* The active and shadow models of a deployment share one feature version.
* Retention never touches assessments, labels, reviews, model or policy history, or the
  audit log.

## 17. Extending the platform

* **New model:** add a `ModelSpec`, or a new `FraudModel` implementation registered in
  `fraud_ai/models/factory.py`. Train it on the same prepared split as the baselines, then
  compare with `fraud-ai compare-models`, `fraud-ai evaluate compare` (paired tests on
  identical examples) and `fraud-ai evaluate complementarity`.


* **New feature / changed feature:** add a new feature version (definitions + a pipeline
  entry in `fraud_ai/features/extractor.py`); never edit a released version. Regenerate the
  FEATURES.md catalogue with `fraud-ai features catalog --format markdown`.

* **New event type:** add to `EventType`, add a payload schema to `PAYLOAD_SCHEMAS`, add a
  handler in `EventProcessor`, then add an Alembic migration (the enum CHECK constraint
  changes).
* **New table/column:** change `fraud_ai/database/models.py`, run
  `alembic revision --autogenerate`, review the file (and make sure enum CHECK constraints
  are not duplicated), then run `fraud-ai db migrate`. The migration/model parity test will
  fail until they agree.

## 18. The SENTINEL analyst console (Stage 13)

```
 analyst's browser ─► SENTINEL console server (Next.js, backend-for-frontend) ─signed v2─► /v1 API
                         allow-listed proxy · resolve route · session · demo (DEMO MODE only)
```

* **Separate package.** `sentinel-console/` has its own `package.json`, lock file and
  tests. It is Next.js 16, React 19 and TypeScript.
* **No fraud logic in the console.** Scoring, policy, inference, review rules and operator
  verification stay in the service. The console displays the service's answers and
  forwards the analyst's resolution.
* **Secrets stay server-side.** The console server holds the API key and v2 signing secret
  and signs every call. The browser only reaches `/api/*` on the same origin
  (`connect-src 'self'`). The proxy allows only the analyst routes; `POST /v1/score` and
  administration are unreachable.
* **Operator identity.**
  * Outside the demo, each resolution needs the analyst's own signed assertion.
  * In DEMO MODE only, the console server signs as the demo reviewer, and the UI labels
    this as DEMO MODE.
* **Read-only analyst views.** `GET /v1/analyst/{feed,reviews,cases/{id},summary,system,search}`
  (`fraud_ai/service/analyst.py`, scope `analyst:read`) join what the console needs. They
  write nothing and return pseudonymous references only. They describe reasons only from
  the service's own catalogue and never compute a combined model score.
* **Demo reset** goes through the local supervisor (Stage 14: `scripts/localrun/`), which
  runs the existing guarded `fraud-ai demo reset`. The console never touches a database.

Details: [sentinel-console/ARCHITECTURE.md](sentinel-console/ARCHITECTURE.md) and
[sentinel-console/DESIGN_SYSTEM.md](sentinel-console/DESIGN_SYSTEM.md).

## 19. The local runtime (Stage 14)

```
 Browser
   │  http://127.0.0.1:3000 (same origin only)
   ▼
 SENTINEL console server (Next.js) ── holds the API key and v2 signing secret (0600 files)
   │  signed v2 requests, allow-listed routes
   ▼
 Fraud API (fraud-ai service run) ── 127.0.0.1:8080
   │
   ├── Demo: SQLite demo world (data/demo) · in-memory state · signed models
   ├── Dev:  PostgreSQL 16 + Redis 7 (Docker, compose.local.yml) · signed models
   └── optional local LLM (analyst assistance only)

 sentinel-start ─► supervisor (scripts/localrun/supervisor.py, detached)
                     ├─ lifeline ─► fraud API      .runtime/logs/api.log
                     ├─ lifeline ─► console        .runtime/logs/console.log
                     └─ control endpoint 127.0.0.1:<random>, 256-bit token (0600)
                          GET /status · POST /shutdown · POST /reset (Demo only)
```

* **One implementation.** The PowerShell and shell wrappers in `scripts/` only find the
  interpreter; `scripts/localrun/` (Python, standard library plus `psutil`) does the work:
  configuration (`sentinel.local.env`), dependency fingerprints, the pre-launch checks
  (`preflight.py` reuses the service's own migration, policy and verified model loading),
  ports, process records and logs. `npm run demo` and the Playwright tests use it too.
* **Ownership.** Every process it starts is recorded with its PID and creation time in
  `.runtime/pids/`; only a record whose process still has that creation time is ever
  signalled. Containers are addressed only by their compose project. Each service runs
  under a lifeline that stops it if the supervisor disappears.
* **Modes** set the service environment explicitly (`modes.py`) and scrub inherited
  `DATABASE_URL`, `REDIS_URL`, `STATE_BACKEND`, `DEMO_MODE` and `ENVIRONMENT`, so a stray
  variable can never point a demo at another database. StagingLike runs the unchanged
  `deploy/staging/stack.sh`.
* **Backend change for Windows.** Key and model-file loading gained Windows-only branches
  (`fraud_ai/utils/winfs.py`); see [TRUST_CHAIN.md](TRUST_CHAIN.md#windows). Nothing else in
  the backend changed in Stage 14.

Details: [LOCAL_SETUP.md](LOCAL_SETUP.md).
