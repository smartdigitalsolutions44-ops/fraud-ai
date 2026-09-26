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
  a CLI and, later, a scoring service - not HTML.

If an analyst UI is ever required it is Stage 9, and it will be a *client* of this core.

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
Rules Engine (fraud_ai.rules)                    – explicit security policy
      ▼
Risk Engine (fraud_ai.risk)                      – ML probability + rules → score → decision
      ▼
Decision (ALLOW / STEP_UP_AUTHENTICATION / MANUAL_REVIEW / BLOCK) → risk_assessments
      ▼
Local Offline LLM (Stage 7, fraud_ai.llm)        – explains the decision from evidence only
```

Stages 1-3 implement everything up to and including baseline ML scoring: events, the
fraud database, point-in-time features and snapshots, training datasets, and trained,
versioned baseline models whose probabilities are stored as predictions. The risk engine,
rules engine and LLM layers exist as interfaces only; no decision is made anywhere yet.

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
| **Rules engine** | *Does this violate security policy?* | Explicit, human-written, auditable conditions. | 1 (engine), 2+ (rule sets) |
| **Risk engine** | *What do we do about it?* | Policy that combines ML probability and rule results into a final score and decision. | 1 (boundary) |
| **LLM** | *Why was this decided, in plain words?* | Explanation and analyst assistance from structured evidence. | 7 |

In one sentence each:

* **ML predicts risk.** It outputs a calibrated probability, stored with the model and feature
  versions that produced it.
* **The neural network is one possible ML model.** It implements the same `FraudModel`
  interface as logistic regression or gradient-boosted trees and competes with them on the
  same evaluation framework. It gets no special trust.
* **Rules enforce security policy.** They can raise a decision to a minimum level (e.g.
  "recent password reset ⇒ at least step-up"), but they never lower one.
* **The risk engine decides.** The decision is never a bare `if p > x: block`; it is a
  versioned `RiskPolicy` (weights, ordered thresholds, a conservative no-model fallback).
* **The LLM explains and assists investigation.** It is *not* the classifier. It receives an
  `EvidencePacket` (score, decision, signals, history), never raw personal data, and its text
  never replaces or alters the numerical score.

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
  evaluation/  bootstrap/paired statistics, walk-forward, calibration, costs and bands,
               scenario/cohort/error analysis, comparison and ensembles, drift baseline,
               shortcut detection, complementarity, anomaly evaluation, JSON reports
  models/      FraudModel interface, model-version registry, prediction storage
  rules/       Rule / RuleEngine
  risk/        RiskPolicy / RiskEngine
  llm/         EvidencePacket (privacy-checked) and ExplanationProvider protocol
  security/    keyed pseudonymisation, sensitive-data detection/redaction, key handling
  data/        deterministic synthetic scenario generator and seeding
  cli/         the `fraud-ai` command
  utils/       logging (with redaction), money, time
migrations/    Alembic environment and versions
tests/         pytest suite (SQLite always; PostgreSQL when TEST_POSTGRES_URL is set)
scripts/       developer scripts and a sample event file
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
| `risk_assessments` | Final score and decision, the policy version and triggered rules. |
| `feature_snapshots` | (0002) Exact hashed feature vector per (event, feature version, as_of). |

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
* **LLM privacy.** `EvidencePacket` rejects keys such as `ip_address`, `email`,
  `full_address`, and any value that looks like an IP, email or card number.
  `LOCAL_LLM_ENDPOINT` must be localhost or a private/loopback address.
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

## 12. Extending the platform

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

