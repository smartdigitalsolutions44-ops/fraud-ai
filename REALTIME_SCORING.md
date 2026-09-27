# Real-time scoring and decision orchestration (Stage 8)

> **Synthetic and local only.** Everything here runs on the bundled synthetic generator, on
> one machine, with SQLite (PostgreSQL is tested for correctness, not benchmarked).
> Nothing here is a production SLA, a real-world fraud-reduction figure, a saving, or a
> statement about the strength of any real authentication. Decisions are **internal
> policy outputs**: no payment system, bank or authentication provider is called.

## 1. The hot path

`FraudScoringService.score_event(event)` (`fraud_ai/realtime/service.py`) is one
idempotent pipeline:

```
incoming event
  -> validate against the event contract            (realtime-event-1)
  -> ingest (idempotent on event_id; records arrival_time)
  -> active deployment: verified policy + shadows    (hash-checked every event)
  -> information-cutoff check                        (arrival-time semantics, see 3)
  -> point-in-time feature snapshot                  (Stage 2, as of the EVENT time)
  -> sequence snapshot, if a sequence model needs it (Stage 6)
  -> active model set from the in-process cache      (verified artefacts)
  -> score + persist predictions                     (one per event/model version)
  -> calibrate the primary probability               (the policy's stored calibrator)
  -> evaluate rules                                  (fraud-rules-1.0.0)
  -> risk policy -> decision                         (deterministic, versioned)
  -> shadow models / shadow policies                 (recorded, never used)
  -> persist the immutable risk assessment (+ review item)
  -> return the decision
```

The **LLM is not in this path.** An analyst can ask for an explanation of a stored
assessment afterwards (`fraud-ai investigate <event-id>`, Stage 7). Scoring works when
no LLM runtime exists or when it is down, and a test checks that importing the hot path
loads no LLM runtime code.

The layers stay separate:

```
model scores (evidence)  +  rules (evidence)  +  risk policy (versioned)  =  decision
```

A model never selects an action. It produces a probability, which the policy maps to a
decision. Even an extreme score cannot produce a `TEMPORARY_BLOCK` on its own: that needs
a matched rule of at least medium severity, or a flagging secondary/sequence model (see
[RISK_POLICY.md](RISK_POLICY.md)).

The service is plain application code, callable directly from Python and from the CLI.
There is no public web API.

## 2. Event contract (`realtime-event-1`)

`fraud_ai/realtime/contract.py` builds on the Stage 1 envelope.

| Field | Rule |
|---|---|
| `event_id` | **required**, never generated (idempotency depends on it) |
| `event_type` | a supported type |
| `timestamp` | the **event time**; timezone-aware; at most 5 minutes after arrival (a future event is refused) |
| `user_id` | the user reference; required except for anonymous login attempts |
| `session_id` | required for decision points (logins, transaction creation) |
| `metadata` | the payload, validated against the per-type schema; unknown fields and forbidden data (card numbers, CVV, passwords, tokens) are refused |
| `schema_version` | **required** and supported |
| `arrival_time` | accepted **only in replay** (`realtime replay`); live scoring stamps arrival from the service clock and refuses a client-supplied value |

A malformed, unsupported or unprocessable event (for example, an unknown user) is
*rejected*:

* it returns `MANUAL_REVIEW` with reason `EVENT_REJECTED`, never ALLOW;
* it is not stored, because an invalid event cannot be persisted;
* error messages name fields, never values.

**Decision points.** Only `TRANSACTION_CREATED` and login events can be decided, and
only when the active policy lists their kind (`decision_event_kinds`, taken from what the
primary model was trained on). Every other event is ingested, with `status = ingested`
and no assessment. It still feeds later features.

## 3. Event time versus arrival time

This addresses the known Stage 2 limitation: features use *event time*, but a real-time
scorer only knows what has *arrived*.

| | Historical training and evaluation | Real-time scoring |
|---|---|---|
| Features as of | event time | event time |
| Information used | everything with `occurred_at <= event time` | only what had **arrived** by the event's arrival: the decision is made at ingestion, so later-arriving data is not in the database yet |
| Recorded | event time | `events.arrival_time`; the assessment's `event_time`, `arrival_time` and `lateness_seconds` |
| Recomputation | reproducible | may differ later (late events fill in history); the stored snapshot and decision are never recomputed |

* **Decide at arrival, then freeze.** The snapshot and the assessment are stored when
  the event is ingested. Recomputing history later can give a different vector, which is
  expected, and the stored decision is the record of what was known.
* **Late events.** An event arriving more than `late_event_seconds` (900 by default)
  after its event time is decided on arrival. It gets the reason `LATE_EVENT` and at
  least `ALLOW_WITH_MONITORING`, and it is marked as late.
* **Earlier decisions stay fixed.** A late event cannot change a decision already
  issued: assessments are immutable. New evidence produces a *new* assessment version
  (`realtime reassess`, below), and the original is preserved.
* **Out-of-order replays are refused.** The information-cutoff check refuses a normal
  decision when the user already has stored events at or before this event's time that
  arrived *after* this event did, because using them would leak information from after
  arrival. That only happens when events are replayed out of arrival order. The outcome
  is `MANUAL_REVIEW` with `FALLBACK_INFORMATION_CUTOFF_VIOLATED`. `realtime replay`
  therefore sorts by arrival time.
* **Historical and bulk loads** leave `arrival_time` NULL, which means "arrived on
  time".

## 4. Idempotency and immutability

* **Events.** Ingestion is idempotent on `event_id`. The same id with different content
  (type, time or user) is rejected as a conflicting duplicate.
* **Assessments:**
  * redelivering a decided event returns the stored assessment (`status = duplicate`);
  * `idempotency_key = SHA-256(event id, policy version, assessment version)` is
    unique, and so is `(event_id, assessment_version)`;
  * two concurrent deliveries therefore cannot create two decisions. The loser of the
    race reads the winner's row. This is tested with 6 threads on SQLite and 5 on
    PostgreSQL.
* **Snapshots and predictions:** one per (event, feature version, as-of) and one per
  (event, model version). A duplicate never adds a row (tested).
* **Reassessment.** `fraud-ai realtime reassess <event-id>` issues version *n+1*:
  * it uses fresh features and the current deployment, and keeps the original arrival
    time;
  * it records `supersedes_assessment_id`;
  * it never mutates version *n*;
  * a reassessment does not store new predictions, because the originals stay
    authoritative for the original decision.

**Concurrency.** SQLite has a single writer, so the service serialises scoring on SQLite
with a process-level lock. On PostgreSQL requests run concurrently and the unique
constraints enforce idempotency.

## 5. Active model set and the model cache

* **Model set.** The active model set is part of the policy (see RISK_POLICY.md): a
  primary classifier, an optional secondary classifier, an optional sequence model and
  an optional anomaly signal. Each is pinned to its artefact SHA-256.
* **Activation checks.** Only registered models whose digest matches, and whose
  artefacts load and verify, can be activated.
* **Cache.** `ModelCache` (`fraud_ai/realtime/cache.py`) keys models on
  (name, version, artefact SHA-256). Loads are verified, a corrupt artefact is never
  cached, and concurrent requests for one model load it once. The cache is **invalidated
  when the deployment changes**, so every model is reloaded and re-verified.
* **Not cached:** feature history, snapshots and sequences are always read from the
  database.

## 6. Shadow mode

A deployment lists **shadow models** (classifiers) and **shadow policies**. For every
decided event they are:

* scored, with their predictions persisted in `model_predictions`;
* evaluated: a shadow policy runs the same `decide()` on its own model set;
* recorded in the assessment's `shadow` block: the score, the flag, agreement with the
  active decision and latency;
* never used for the decision.

A shadow failure is recorded as an error and cannot affect the decision. Two regression
tests check this:

* The same events are replayed with shadows, without shadows and with a *corrupted*
  shadow model. The decisions are identical every time.
* A shadow policy that would send **every** event to manual review
  (`test_shadow_policy_cannot_trigger_review_or_change_scores`) leaves every stored
  field identical to a run without shadows. That covers the decision, the final risk
  score, the calibrated score, the risk level, the reason codes, the action and the
  number of review entries.

`fraud-ai monitoring shadow` reports, from the stored assessments and labels known now:

* agreement with the active system and the number of disagreements;
* fraud caught only by the shadow, and fraud caught only by the active system;
* false positives unique to the shadow;
* the shadow latency cost.

## 7. Failure behaviour (no silent ALLOW)

Every failure is explicit and recorded on the assessment (`failures`, `fallback_used`,
`FALLBACK_*` reason codes). None can produce ALLOW or ALLOW_WITH_MONITORING.

| Failure | Decision (default policy) | Tested by |
|---|---|---|
| no active policy / tampered policy or deployment | `MANUAL_REVIEW` (system fallback) | deleting deployments; editing the policy row; editing the deployment row |
| feature extraction fails | `MANUAL_REVIEW` | a failing snapshot query |
| primary model unavailable / artefact invalid / invalid output | `MANUAL_REVIEW` | a deleted model directory; corrupted artefact bytes; a NaN score |
| calibration unavailable or altered | `MANUAL_REVIEW` | edited calibration parameters |
| rule engine fails | `MANUAL_REVIEW` | a broken rule set |
| information cutoff violated | `MANUAL_REVIEW` | an out-of-arrival-order replay |
| sequence extraction fails | at least `STEP_UP_AUTHENTICATION` (the primary still scores) | a failing sequence query |
| secondary / sequence / anomaly model fails | at least `STEP_UP_AUTHENTICATION` | a corrupted GRU artefact |
| event rejected (contract, unknown user, conflicting duplicate, future time) | `MANUAL_REVIEW`, not stored | malformed input; a client arrival time; an unknown user |
| database unavailable / commit fails | `MANUAL_REVIEW`, `status = not_persisted` | a database without schema; a failing commit |
| duplicate event | the stored decision | redelivery, including concurrent |
| late event | at least `ALLOW_WITH_MONITORING`, `LATE_EVENT` | 2-hour-late delivery |

## 8. Manual review queue

`review_queue` holds one entry per `MANUAL_REVIEW` or `TEMPORARY_BLOCK` assessment. The
priority is:

* 1 for a temporary block;
* 2 for a fallback or a high/extreme risk level;
* 3 otherwise.

```
fraud-ai review list [--status open|needs_more_information|resolved|all]
fraud-ai review show <id>              # the assessment, the matched rules, failures, action
fraud-ai review resolve <id> --outcome legitimate|fraud|needs_more_information [--note ...]
```

* **Outcomes are append-only.** Each is stored in `review_outcomes`. After
  `needs_more_information` the entry stays open for a later outcome, and a resolved
  entry cannot be resolved again.
* **Nothing is rewritten.** Resolution never changes the assessment, and it does not
  create a training label: feeding reviews back into labels is later work.
* **No personal data in notes.** A note is refused if it contains an email, IP, card
  number, token, phone number or street address.

A **step-up** is an action *request* only:

```json
{"type": "STEP_UP_AUTHENTICATION", "required_strength": "strong|standard",
 "reason_codes": [...], "note": "placeholder request only; no authentication is performed"}
```

`strong` is requested for takeover-type reasons and for fallbacks. A later stage can map
it to WebAuthn or payment authentication. A **temporary block** carries
`expires_after_hours` (24) and `requires_review: true`, and is never permanent.

## 9. Latency

Every stage is timed separately and stored on the assessment (`latency_ms`: every stage
up to, but not including, the commit). The end-to-end latency (the returned outcome's
`total`) includes the commit. Stages are not additive, because `shadow` nests model
work (see §11). The stages are:

* validation, ingestion, policy load, cutoff check, features, sequence;
* model loading, inference per role, calibration, rules, policy, shadow, persistence,
  commit.

`monitoring summary` and the benchmark report p50, p95 and p99 per stage.

**Initial budgets** (p95, set *after* measuring; see §11):

| Stage | Budget |
|---|---|
| validation | 2 ms |
| ingestion | 30 ms |
| features | 50 ms |
| sequence | 30 ms |
| primary inference | 20 ms |
| rules + policy | 2 ms |
| persistence + commit | 20 ms |
| total (decision events) | 150 ms |

Nothing has been optimised yet. Profiling decides where caching is justified, and the
Stage 2 cache-corruption tests would guard any history cache.

## 10. Monitoring and structured logs

* `fraud-ai monitoring summary` reports, from stored assessments:
  * events ingested and assessments;
  * decision counts and rates, fallbacks and failures by category, late events;
  * per-stage latency percentiles;
  * review-queue size and the shadow disagreement rate;
  * the **drift warnings**.
* **Drift** compares recent assessments with baselines the policy stored when it was
  proposed:
  * features (PSI and JS on the tracked features, from the stored snapshots);
  * the calibrated prediction distribution;
  * decision rates;
  * fraud prevalence where labels are known (these lag, so a low value is reported as
    "labels pending", not as a warning);
  * the anomaly score, if the policy has one.

  These are **warnings only**: nothing retrains, and no policy or decision changes.
* **In-process counters** (`service.metrics`) cover events processed, rejected and
  failed, decisions, fallbacks, per-stage latency and the shadow disagreement rate.
* **Structured logs.** Each decision is one JSON line on `fraud_ai.realtime`. A line
  holds only:
  * the event pseudonym (`rt-…`);
  * the policy version, decision, risk level and reason codes;
  * latencies, the fallback flag and the error category;
  * the assessment version, the duplicate flag and lateness.

  Any other field is dropped. No raw ids, IPs, card data, passwords, tokens or addresses
  appear (tested). The global redaction filter still applies.

## 11. Results (SYNTHETIC benchmark)

> All measurements come from synthetic data on one local machine. The policy bands
> behind these decisions are synthetic-derived experimental defaults. Nothing here is a
> production SLA or a real-world result.

From `python scripts/realtime_benchmark.py --users 300`. The world is 300 synthetic users
over 180 days; the last 7 days (1,785 events) are held out as a live stream. The run used
one CPU and SQLite.

**Active deployment.**

* `risk-policy-1.0.0`: GB primary, NN secondary, GRU sequence model.
* Shadow model: LR. Shadow policy: `risk-policy-1.1.0`.

**Replay in arrival order.**

* 1,785 events: 382 decided (transactions) and 1,403 ingested only.
* No failures.
* Wall time 39.8 s, about 45 events/s (single writer).
* Decisions: 343 ALLOW, 25 ALLOW_WITH_MONITORING, 14 MANUAL_REVIEW. These 14 open the
  review queue.
* Late arrivals: the 20 late events were all non-decision events.

### END-TO-END LATENCY (the complete scoring path, decided events)

The time from `score_event()` receiving the event dict to returning the decision:
contract validation through the database **commit**, plus logging. n = 382 decided
transactions, one thread, SQLite. SYNTHETIC world.

| p50 | p95 | p99 |
|---|---|---|
| **63.7 ms** | **85.8 ms** | **106.2 ms** |

Initial budget: p95 ≤ 150 ms (met here; not a production SLA).

### Stage-level breakdown (NOT directly additive)

Each stage is timed on its own (ms, n = 382). The stages below do **not** sum to the
end-to-end figure, for two reasons:

* **Nesting.** The `shadow` stage *contains* the shadow model's own model resolution,
  model load (cache hit), inference and prediction persistence. Those parts are
  *also* counted in the `model resolution`, `model load/cache` and `prediction
  persistence` rows. Do not add `shadow` to those rows.
* **Untimed overhead** (roughly 5-10 ms at p50; percentiles do not add exactly either): opening the session, the idempotency lookup
  of the event row, recording the latency on the assessment, and the structured log line.

| Stage | p50 | p95 | p99 | Contains / contained in |
|---|---|---|---|---|
| validation (contract) | 0.30 | 0.45 | 0.55 | - |
| ingestion (event processor) | 8.59 | 11.50 | 14.38 | - |
| policy load + hash check | 1.61 | 2.31 | 2.72 | - |
| information-cutoff check | 1.12 | 1.58 | 1.93 | - |
| **feature extraction** (point-in-time snapshot: compute + persist) | 13.42 | 18.59 | 21.16 | - |
| **sequence extraction** (GRU input) | 8.22 | 14.87 | 18.68 | - |
| model resolution (registry lookups) | 3.58 | 4.68 | 5.52 | includes the shadow model's lookup |
| model load / cache (all hits after the first event) | 0.03 | 0.05 | 0.09 | includes the shadow model's cache hit |
| inference: primary (GB) | 3.20 | 5.10 | 5.78 | - |
| inference: secondary (NN) | 1.10 | 1.54 | 1.86 | - |
| inference: sequence (GRU; excludes sequence extraction) | 1.87 | 2.69 | 3.13 | - |
| prediction persistence (GB, NN, GRU **and** the shadow LR) | 6.27 | 8.66 | 10.20 | the LR part is also inside `shadow` |
| calibration | 0.08 | 0.11 | 0.13 | - |
| rules | 0.05 | 0.08 | 0.11 | - |
| policy (`decide`) | 0.03 | 0.06 | 0.08 | - |
| shadow (LR model + shadow policy) | 5.15 | 7.50 | 8.57 | **contains** its resolution, load, inference and prediction persistence |
| risk-assessment persistence (+ review item) | 0.79 | 1.20 | 1.60 | - |
| commit | 2.34 | 3.21 | 4.70 | - |

The stored assessment's `latency_ms` has the same stages. Its `total` stops *before* the
commit, because the row is written inside the transaction. The end-to-end figure above
is the returned outcome's `total`, which includes the commit.

**Other runs.**

* Non-decision events (ingest only): p50 10.4 ms, p95 14.2 ms, p99 16.8 ms.
* Concurrent redelivery of all 1,785 events from 4 threads: every one returned
  `duplicate` (no new rows). Latency p50 8.2 ms, p95 11.3 ms.
* **Model cache.** 1,785 live events were processed, 382 of them decisions.
  * There were exactly **4 model loads**, one per model (GB, NN, GRU, LR), each on first
    use.
  * Every other model access was a **cache hit**: 1,524 hits.
  * There were no load failures, **no invalidations and no unexpected reload**.
  * The concurrent re-delivery pass (4 threads, 1,785 events) returned stored results
    and loaded nothing.

**Findings:**

1. The database work dominates. Feature extraction, sequence extraction, ingestion and
   prediction persistence are each measured separately. Their p50s together are about
   36 ms of the 64 ms end-to-end p50, although prediction persistence partly overlaps
   `shadow`. All model inference is about 6 ms, and rules plus policy are under 0.1 ms.
2. Given (1), the first optimisation target would be the history queries behind
   features and sequences, only after profiling on PostgreSQL. Nothing has been
   optimised yet.
3. Shadow mode costs about 5 ms p50 per decision.

**Shadow comparison (live week; no labels had arrived yet).**

* LR shadow model: agrees with the active system on 94.2% of decisions. There are 22
  disagreements, 14 of them shadow-only flags without a fraud label. Latency p50 4.4 ms.
* `risk-policy-1.1.0` shadow policy: agrees on 93.5%. Every disagreement is
  `ALLOW_WITH_MONITORING` under the active policy becoming `ALLOW` under the shadow (25
  events), which is expected because its monitoring band is gone. Latency p50 0.7 ms.
* Fraud caught only by a shadow: 0, but labels for the live week are not known yet.

**Drift warnings (live week vs training baselines):**

* moderate prediction and decision-rate drift;
* feature drift: `device_age_days` (significant); `address_age_days`, `network_type`
  and `vpn_detected` (moderate);
* prevalence: "labels pending".

These are expected when a later period is compared with the training window of a
synthetic world where accounts age. They are warnings to re-evaluate, not failures.


## 12. CLI

```
fraud-ai seed --live-days 7 --live-output live.jsonl  # history + a held-out SYNTHETIC live stream
fraud-ai policy propose risk-policy-1.0.0 --primary gradient-boosting-1.0.0 [--secondary ..] [--sequence ..] [--anomaly ..]
fraud-ai policy list | show <v> | simulate <v> | compare <a> <b>
fraud-ai deployment show [--history]
fraud-ai deployment activate <v> [--shadow-model REF] [--shadow-policy V] [--note ..]   # asks for confirmation
fraud-ai realtime score <event-file|->      # live: arrival = service clock
fraud-ai realtime replay <event-file>       # recorded events, in arrival order
fraud-ai realtime reassess <event-id>       # new version; the original is kept
fraud-ai review list | show <id> | resolve <id> --outcome ...
fraud-ai monitoring summary [--since-hours H] [--json] | shadow
python scripts/realtime_benchmark.py --users 300
```

## 13. Limitations

* **Single process.** The scoring service is an in-process library. Stage 9 adds an HTTP
  boundary (§14), but there is still no queue consumer or backpressure, and on SQLite
  scoring is serialised.
* **Late information is excluded, not corrected.** An event is decided with what has
  arrived. A late event arriving afterwards is not folded into earlier decisions; a
  reassessment is explicit.
* **The cutoff check is per user.** It covers the user's own events. Late-arriving
  events of *other* users that share a device or network are not checked.
* **Latency is local.** It was measured on one CPU with SQLite. PostgreSQL and real
  load would differ. Commit time is not in the stored breakdown; it is in the returned
  outcome.
* **Drift baselines come from one training window.** Synthetic drift between the
  training period and the live week is expected, so warnings on this data are
  informative, not alarms.
* **Step-up is executed by Stage 9 (§14); temporary blocks are not.** There is still no
  payment-gateway hold or release.

## 14. The HTTP service boundary (Stage 9)

`fraud_ai.service` wraps this engine, unchanged, in a versioned API (`fraud-api-1.0.0`,
see [API.md](API.md)). `POST /v1/score` takes exactly the `realtime-event-1` contract and
calls `FraudScoringService.score_event` in a bounded worker pool with a timeout
(`SERVICE_REQUEST_TIMEOUT`). A timeout or a database failure answers 503 with
`fallback_decision: MANUAL_REVIEW`.

What the boundary adds:

* API keys, scopes, rate limits and HMAC signatures ([SERVICE_SECURITY.md](SERVICE_SECURITY.md));
* `Idempotency-Key` on top of `event_id` idempotency;
* a safe response view: decision, risk level, reason codes, policy and model versions, and
  `step_up_required` / `review_required`. There are no scores, features or latencies;
* `arrival_time` in a request needs the `score:replay` scope. The live path stamps the
  arrival with the service clock, as in §3;
* network-intelligence fields need `signals:trusted`;
* step-up execution ([AUTHENTICATION.md](AUTHENTICATION.md)). The result is a new
  `step_up_followup` assessment version that copies this path's scores verbatim, so the
  original assessment is untouched (§4).

**SQLite concurrency.** SQLite is a single writer. The scorer's write lock is now the
engine's process-wide lock (`fraud_ai.database.engine.write_lock`), shared with the
service's own writes: replay tokens, idempotency and step-up. Without it, two deferred
transactions can deadlock and SQLite fails one at once with "database is locked". The
lock is a no-op on PostgreSQL.

### HTTP benchmark (SYNTHETIC, this machine)

`python scripts/service_benchmark.py`:

* **Setup:** the Stage 8 test world (80 users, 576 live events, 125 of them decision
  points; gradient boosting primary, GRU sequence, logistic shadow), on SQLite.
* **Modes:** each run replays the stream on a fresh copy three ways:
  * `direct` calls the library in-process;
  * `http` is `POST /v1/score` over a loopback socket to uvicorn (keep-alive, one client
    per worker);
  * `http_signed` is `http` with HMAC signatures and persisted replay tokens.
* **Workers** take whole users, so per-user order is preserved.

Latency is per request in milliseconds, with p50/p95/p99 over all 576 requests.

| Workers | Mode | req/s | p50 | p95 | p99 | decisions p50 / p99 |
|---|---|---:|---:|---:|---:|---:|
| 1 | direct | 48.0 | 9.0 | 47.7 | 56.9 | 43.7 / 77.4 |
| 1 | http | 50.1 | 12.2 | 51.2 | 62.5 | 46.3 / 87.3 |
| 1 | http_signed | 42.6 | 15.8 | 55.9 | 66.5 | 51.1 / 75.3 |
| 4 | direct | 53.7 | 70.4 | 140.8 | 203.8 | 98.5 / 213.4 |
| 4 | http | 42.3 | 87.7 | 157.9 | 195.8 | 118.7 / 335.2 |
| 4 | http_signed | 37.6 | 98.8 | 165.6 | 197.6 | 128.7 / 206.4 |
| 8 | direct | 54.7 | 128.7 | 232.7 | 284.5 | 162.1 / 307.3 |
| 8 | http | 39.6 | 169.2 | 285.0 | 359.5 | 198.4 / 353.4 |
| 8 | http_signed | 38.4 | 177.0 | 282.9 | 454.2 | 206.8 / 431.9 |
| 16 | direct | 53.5 | 241.4 | 370.6 | 561.6 | 276.1 / 562.2 |
| 16 | http | 38.7 | 309.4 | 483.3 | 650.1 | 354.1 / 653.4 |
| 16 | http_signed | 34.6 | 358.2 | 557.1 | 761.3 | 398.9 / 800.0 |

Reading it:

* **Single worker.** The HTTP boundary adds about **3 ms at p50** (framing, auth lookup,
  validation, JSON). Signing adds about **3.6 ms** (HMAC plus a committed replay-token
  write).
* **More workers.** Throughput stays flat, at about 50 req/s direct and 35-50 req/s over
  HTTP. SQLite serialises every write, so extra workers only queue, and latency grows
  with the queue. The apparent HTTP "overhead" at 16 workers (68 ms) is mostly that
  queueing plus the extra key-lookup and replay-token work under the lock, not
  per-request framing cost.
* **Caveats.** Concurrent throughput needs PostgreSQL (the constraints and the service are
  tested there), which this benchmark does not measure. These are local, synthetic
  numbers, not an SLA.
