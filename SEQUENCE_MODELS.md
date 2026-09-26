# Sequence models (Stage 6)

> **Synthetic evidence only.** Every result here comes from the bundled synthetic
> generator. It says nothing about real-world detection rates, losses, savings or
> production readiness. A sequence model earns a place only if it adds complementary
> signal to gradient boosting, and "it does not" is a valid, useful finding.

## 1. Why sequences

The tabular models see one point-in-time feature vector per event. Those 107 features
summarise history (counts, ages, windows), but they cannot represent **order**, such as:

* failed logins on several days, then a successful login, a quiet period, and an
  ordinary-looking purchase;
* a hijacked trusted device that adds an address, then a card a day later, then buys;
* a tiny test purchase followed days later by a larger one;
* normal amounts at an abnormal cadence (several purchases at night within minutes).

Stage 5 showed that the remaining misses of gradient boosting are mostly stealthy takeovers,
plus friendly fraud, which is unobservable by design. Sequence models test whether ordered
behaviour recovers any of those.

## 2. Sequence definition (`fraud-sequence-1.0.0`)

`fraud_ai/sequences/definition.py` holds a frozen, versioned definition.

* **Window.** The last `max_events` events (default **16**, chosen in §8.1) of the user
  strictly before the
  scoring point. Optionally only those within `max_age_days`.
* **Target position.** The scored event itself is appended as the last valid position,
  marked `is_target`.
* **Lookback.** `lookback_days` (365) of history is read to decide whether a device,
  network, address or payment method was already *known*. Only the window is emitted.
  This keeps the history read bounded.
* **Padding.** Right padding: positions `[0, length)` are valid.
* **Vocabularies.** Each has `<pad>` = 0 and `<unk>` = 1:
  * event type (all `EventType` values);
  * network type, device type, authentication method and channel.

  **No identifiers are tokens.** There are no user, IP, device, address or payment-token
  embeddings, so nothing can become a per-customer lookup table (tested).
* **27 numeric features per event**, each with its transform:

| Group | Features |
|---|---|
| Time | `log1p` minutes since the previous event; `log1p` hours before the scoring point; `log1p` account age in days |
| Target | `is_target` |
| Amount | `has_amount`, `log1p` amount |
| Device | present, known, `log1p` age (days), changed from the previous event |
| Network | present, known (keyed IP hash), ASN changed, country changed, VPN, proxy/Tor, datacenter, proxy confidence |
| Login | MFA used |
| Address | present, known, `log1p` age |
| Payment method | present, known, `log1p` age |
| Event class | security event (reset, email/phone/MFA change), label event (chargeback or fraud confirmation *known at that time*) |

* **Fingerprint.** The SHA-256 of the full definition (window, schema version, vocabularies,
  feature names and transforms). It is recorded with every sequence model and dataset.
  Changing anything means a new version.
* **Sequence digest.** The SHA-256 of the exact extracted arrays for a dataset. It is stored
  in the training manifest. Evaluation rebuilds the sequences and **refuses to run** if the
  digest differs (tested by rewriting an old event).

## 3. Leakage controls

* **Strict cut-off.** Only `events` rows with `occurred_at < T` for the same user are read,
  ordered by `(occurred_at, event_id)`. Events at exactly `T`, such as a transaction's own
  approval a second later, are excluded.
* **Immutable data only.** Only the append-only `events` table is read: each event's
  payload as it was, plus `events.device_id` as an identity. Mutable state is never read:
  * device trust flags;
  * login counters;
  * address `is_active`;
  * transaction status.
* **Replay.** Each historical event is encoded with the state *before* it: known flags,
  ages and changes are what was known at that event.
* **Labels and chargebacks.** They appear only if their event happened before `T`. That is
  legitimate history, since a chargeback known yesterday is a fact today.

**Mutation tests** (`tests/test_sequences.py`) check that each of these leaves a sequence's
digest unchanged:
* an event at 10:01 for a 10:00 scoring point;
* a chargeback or fraud confirmation that arrives later;
* device trust or counter updates;
* identical output from batch and single-event extraction.

**Model inputs versus metadata.** Metadata (event id, user, time, label) stays on the dataset
examples. A `SequenceMatrix` is the Stage 3 `ModelMatrix`, with the same leakage guards,
plus the aligned sequences.

## 4. Architectures

All three share the **event encoder**:
* learned embeddings: event type (8 dimensions) and the four context types (4 each);
* the 27 numeric features, standardised with statistics from the *valid training
  positions*, clipped to ±10;
* a projection to `hidden_size` (64).

| Model | Encoder → | Output |
|---|---|---|
| **GRU** (`gru`) | unidirectional GRU (1 layer, hidden 64) over `pack_padded_sequence`, so padding never enters the state | the final hidden state (at the scored event) → dense head (32) → logit |
| **Causal Transformer** (`transformer`) | a learned distance-to-target embedding, then 2 pre-norm blocks of 4-head causal self-attention (d = 64, feed-forward 128, GELU) | the output at the scored event → head → logit |
| **Hybrid** (`hybrid-gru`) | the GRU sequence representation, concatenated with an MLP (64) over the Stage 3 preprocessed 107-feature static vector | fusion head → logit |

* **No bidirectional recurrence.** It would read "future" positions and violate real-time
  scoring semantics.
* **Causal masking.** Position *i* attends only to positions ≤ *i*, and padding keys are
  masked. Changing later positions leaves earlier outputs unchanged, and padding never
  changes the output (tested).
* **Attention weights** are readable (`SequenceModel.attention`) for **research inspection
  only**. They are not explanations and not evidence of causality.

## 5. Training and infrastructure

Nothing is duplicated.

* **Shared training loop.** Sequence models use `fraud_ai/models/torch_training.fit_binary`,
  the same loop as the Stage 5 network (which was refactored onto it):
  * weighted `BCEWithLogitsLoss` (focal optional), AdamW and gradient clipping;
  * early stopping on **validation PR-AUC**, with the best checkpoint restored;
  * per-epoch history and overfitting flags.
* **Shared plumbing.** Deterministic single-threaded execution, the model factory, the
  registry and the training manifests.
* **Safe artefacts.** Weights are saved as `state_dict` only and loaded with
  `weights_only=True` after the SHA-256 check.
* **Same split as the baselines.** Training, validation and test are the baselines' exact
  time-ordered split, so the dataset fingerprint is identical and paired comparisons are
  valid.
* **Walk-forward, calibration, scenarios, errors, costs and the comparison** all work
  unchanged: the context rebuilds and verifies the sequences.

## 6. CLI

```bash
fraud-ai sequence build <event-id> [--max-events 16 --max-age-days D --output f.json]
fraud-ai sequence inspect <event-id>
fraud-ai train gru|transformer|hybrid [--max-events 16 --hidden-size 64 --layers N ...]
fraud-ai sequence compare [--base gradient-boosting-1.0.0]   # caught only by each model
fraud-ai sequence stealth-report                             # stealthy/temporal takeovers
fraud-ai evaluate report gru-1.0.0                           # every Stage 4 report
fraud-ai score <event-id> --model gru-1.0.0                  # builds the sequence, stores p
```

## 7. Synthetic generator: temporal attacks and lookalikes

**New fraud scenario `slow_account_takeover`** (5% of users at a multiplier of 1). Its
variants:

| Variant | Pattern |
|---|---|
| A | failed logins on 2–4 days → success → quiet 1–3 days → ordinary purchase from a now-"known" device |
| B | a hijacked trusted device on the home network: new address → a card 1–2.5 days later → a purchase 1–2.5 days after that |
| C | a £1–5 digital test purchase → a larger purchase 1–4 days later |
| D | 3–5 normal-value purchases within minutes, at night |
| E | a hijacked trusted session: the victim's device, network and normal amounts; only timing differs |

**New legitimate scenario `legitimate_lookalike`** (4%), which mirrors those patterns:
* a week of travel (new foreign networks);
* a new phone with an immediate purchase;
* a forgotten password over several days, then a reset and a purchase;
* gradual legitimate address and card changes before a purchase;
* bursts of small purchases;
* a large purchase after 1–2 months of inactivity.

**Guard tests** assert that no single current-event feature separates the temporal
takeovers from legitimate events (univariate ROC-AUC < 0.95), alongside the global
< 0.92 guard.

## 8. Results on the 1,000-user synthetic world

> **All results in this section are SYNTHETIC.** They describe one generator, one world,
> one time-ordered split and one seed. They are not real-world detection rates, losses or
> savings.

Produced by `scripts/sequence_benchmark.py` (SQLite, CPU only, 1,000 bootstrap iterations).

**The world.** A fresh 1,000-user world with the Stage 6 generator: 180 days, seed 2026,
186,060 events, 14-day maturity.

**The dataset:** 33,923 labelled transactions, of which 431 are fraud (1.27%). All seven
models use this one time-ordered split:

| Split | Rows | Fraud |
|---|---|---|
| train | 23,746 | 314 |
| validation | 5,089 | 57 |
| test | 5,088 | 60 |

The generator changed in Stage 6, so this world is harder than the Stage 5 one. Gradient
boosting's test PR-AUC falls from 0.956 to 0.905. **Stage 5 figures are not comparable.**

### 8.1 Sequence length: chosen on validation performance and cost

The GRU was trained at each length with the same seed and settings. Nothing was
registered, and the test split was not used.

| Window | Validation PR-AUC | Best epoch | GRU training | Batch inference (5,088 rows) | Dataset build |
|---|---|---|---|---|---|
| **16 events** | **0.8085** | 9 | **76 s** | **0.16 s** | 282 s |
| 32 events | 0.8146 | 9 | 163 s | 0.34 s | 278 s |
| 64 events | 0.8160 | 19 | 645 s | 0.74 s | 299 s |

* **The rule** (set before the run): choose the *shortest* window whose validation
  PR-AUC is within **0.01** of the best. A 32- or 64-event window gains 0.006–0.007
  validation PR-AUC, which is within seed-to-seed noise on 57 validation frauds.
  * It costs 2.1× (32) and 8.5× (64) the training time.
  * It costs 2.1× and 4.7× the inference time.
* **Chosen default: 16 events + the scored event.** The longest window was deliberately
  not chosen automatically.
* **A first run was stopped.** It used a "highest validation PR-AUC" rule, which would
  have picked 64 for a +0.0014 gain. It was stopped before any model was trained or
  registered.

### 8.2 Test results (threshold 0.5, 95% stratified bootstrap)

| Model | PR-AUC | ROC-AUC | Precision | Recall | FPR | Brier (uncal. → sigmoid) |
|---|---|---|---|---|---|---|
| **gradient boosting** | **0.905 [0.832, 0.958]** | 0.996 | 0.895 | 0.850 | **0.001** | 0.00267 → 0.00247 |
| feed-forward NN | 0.878 [0.796, 0.941] | 0.990 | 0.708 | 0.850 | 0.004 | 0.00471 → 0.00294 |
| **GRU** | 0.851 [0.755, 0.928] | 0.952 | 0.537 | 0.850 | 0.009 | 0.01163 → 0.00301 |
| **Transformer** | 0.831 [0.735, 0.913] | 0.937 | 0.510 | 0.817 | 0.009 | 0.02326 → 0.00397 |
| **hybrid GRU + static** | 0.879 [0.798, 0.941] | 0.993 | 0.435 | 0.900 | 0.014 | 0.01145 → 0.00244 |
| random forest | 0.823 | 0.970 | 0.920 | 0.767 | 0.001 | — |
| logistic regression | 0.800 | 0.980 | 0.149 | 0.900 | 0.061 | — |

**Paired differences** (gradient boosting minus each model, on the same resampled rows):

| Comparison | PR-AUC difference | McNemar at 0.5 (GB right / other right) |
|---|---|---|
| GB − GRU | **+0.053 [+0.019, +0.098]** (excludes zero) | 41 / 3, p < 0.001 |
| GB − Transformer | **+0.074 [+0.028, +0.129]** (excludes zero) | 45 / 2, p < 0.001 |
| GB − hybrid | +0.025 [−0.007, +0.064] (overlaps zero) | 64 / 3, p < 0.001 |
| GB − feed-forward NN | +0.027 [−0.018, +0.073] (overlaps zero) | 16 / 1, p < 0.001 |

**On this synthetic evaluation window, gradient boosting remains stronger.**

* **Pure sequence models.** The GRU and the Transformer are measurably worse on PR-AUC
  (the intervals exclude zero), and their false-positive rates are 7–8 times higher.
* **Hybrid.** Its PR-AUC interval overlaps gradient boosting's. It buys recall (0.90 vs
  0.85) at more than 10 times the false-positive rate (1.4% vs 0.1%).
* **Calibration.** Class weighting makes every sequence model over-confident. Sigmoid
  calibration (fitted on validation) fixes most of it, and the hybrid then has the
  lowest Brier score (0.00244).

### 8.3 Complementary detection vs gradient boosting (test, 60 frauds, own thresholds)

| Model | Caught by both | Only GB | **Only this model** | Missed by both | New false positives |
|---|---|---|---|---|---|
| GRU | 50 | 1 (takeover) | **1 (stealthy takeover)** | 8 | 40 |
| Transformer | 49 | 2 (1 takeover, 1 temporal takeover) | **0** | 9 | 43 |
| hybrid | 51 | 0 | **3 (friendly fraud)** | 6 | 64 |
| feed-forward NN | 50 | 1 | 1 (friendly fraud) | 8 | 15 |

* **Missed by all seven models:** 4 of the 60 test frauds.
* **Combinations** (research only, never persisted): none adds signal.
  * GB + GRU rank average: −0.027 [−0.066, +0.002].
  * GB + hybrid rank average: +0.006 [−0.014, +0.026].
  * No combination's interval lies above zero.

**Finding.** The sequence models add almost no complementary signal on this window.
* The GRU catches one stealthy takeover that gradient boosting misses, and adds 40 false
  positives to do it.
* The hybrid's three extra catches are friendly fraud, a category that is unobservable by
  design. That is best read as noise, bought with 64 extra false positives.

### 8.4 Stealthy and temporal account takeover

There are **18 cases** in the test split: 13 takeovers with no password reset in the
previous 24 hours, and 5 cases from the temporal `slow_account_takeover` scenario.

| Model | Recall on these cases |
|---|---|
| gradient boosting | 0.83 (15/18) |
| GRU | 0.83 |
| hybrid | 0.83 |
| feed-forward NN | 0.78 |
| Transformer | 0.72 |
| random forest | 0.67 |
| logistic regression | 0.89, at a 6.1% overall FPR |

* **Caught only by a sequence model:** 1 case, caught by the GRU at p = 0.67, against
  0.06 for gradient boosting.
  * Its prior 16 events contain 6 device changes and 5 ASN changes.
  * The purchase itself uses a known device, network, address and card.
  * This is the kind of pattern the GRU was built for. It is one case.
* **Missed by every model:** 1 case. It has a known device, network and address; one
  failed login; three device changes and six ASN changes. Every model scores it at or below
  0.05.
* **Temporal takeovers:** gradient boosting and the GRU each miss one of the 5
  `slow_account_takeover` cases, and the Transformer misses two.

### 8.5 Walk-forward (30-day expanding folds, fresh retrain per fold)

| Fold (test from) | Train rows / fraud | Test fraud | GB | NN | GRU | Transformer | Hybrid |
|---|---|---|---|---|---|---|---|
| 5 | 4,210 / 21 | 82 | 0.486 | **0.641** | 0.564 | 0.533 | 0.606 |
| 6 | 9,634 / 103 | 85 | **0.817** | 0.752 | 0.795 | 0.696 | 0.792 |
| 7 | 15,181 / 187 | 60 | 0.831 | 0.825 | 0.744 | 0.715 | **0.852** |
| 8 | 20,958 / 271 | 57 | **0.911** | 0.848 | 0.824 | 0.820 | 0.860 |
| mean (sd) | | | 0.761 (0.188) | 0.766 (0.093) | 0.731 (0.117) | 0.691 (0.119) | **0.778** (0.118) |

* **Little data.** As in Stage 5, gradient boosting is the weakest model with little
  training data (fold 5: 21 training frauds) and the strongest with the most.
* **Across folds.** The hybrid has the highest mean, and the feed-forward network the
  lowest variance.
* **Uncertainty.** The per-fold intervals are wide. For example, fold 5 gives gradient
  boosting [0.39, 0.60] and the hybrid [0.51, 0.71]. One fold per regime is not enough to
  claim an advantage.

### 8.6 Cost, size and latency (CPU only, one thread; model-only unless stated)

| Model | Parameters | Artefact | Training | Single-event p50 / p95 | Batch throughput |
|---|---|---|---|---|---|
| gradient boosting | — | 648 KB | 10.1 s | 2.73 / 4.66 ms | 9,596 rows/s |
| feed-forward NN | 31,425 | 195 KB | 23.8 s | 0.64 / 0.91 ms | 9,170 rows/s |
| **GRU** | 30,717 | 156 KB | 75.3 s | **1.22 / 1.40 ms** | **30,945 rows/s** |
| **Transformer** | 73,981 | 336 KB | 229.7 s | 1.67 / 1.97 ms | 10,806 rows/s |
| **hybrid** | 43,197 | 241 KB | 93.9 s | 1.52 / 1.94 ms | 8,033 rows/s |

* **Weights in memory.** Float32 weights take 0.12 MB (GRU), 0.30 MB (Transformer) and
  0.17 MB (hybrid).
* **Sequence extraction (database, SQLite, one event):** **7.1 ms p50, 13.8 ms p95**. This
  is measured separately from inference, and it comes on top of the Stage 2 feature
  extraction for the hybrid.
* **Building the dataset** (sequences for 33,923 events) takes about 280 s.
* **Totals.** The per-model reports took about 19 minutes, most of it in walk-forward
  retraining of the sequence models.

### 8.7 Conclusion

On this synthetic window:
* **gradient boosting remains stronger;**
* **the pure sequence models perform worse overall;**
* **the GRU catches one stealthy takeover that gradient boosting misses;**
* **the hybrid is statistically indistinguishable from gradient boosting in PR-AUC, but
  runs at a much higher false-positive rate.**

No sequence model is adopted. The case for keeping them is research: they are the only
models that see ordered behaviour, and the walk-forward results hint at better behaviour
with little training data. That needs more worlds, seeds and a real temporal attack
distribution to test.

## 9. Limitations

* **Synthetic data.** The temporal attacks were written by us. A model that learns them
  learns *our* generator, and real attackers differ.
* **Sample sizes.** Stealthy and temporal takeovers number in the tens in the test split,
  so per-scenario recall is indicative only.
* **Single seed and small search.** Architecture differences within noise should not be
  over-read.
* **Truncated history.** The window is capped at `max_events`. Very long gradual changes
  beyond it are seen only through ages and known flags.
* **Extraction cost.** Sequence extraction reads up to `lookback_days` of a user's events at
  scoring time. It is bounded, but still a database cost separate from inference.
* **Attention is not explanation.** Permutation importance of sequence channels describes
  reliance on this data, not causes.

## 10. Sequence evidence in analyst explanations (Stage 7)

The Stage 7 evidence packet ([LLM_ANALYST.md](LLM_ANALYST.md)) reuses this point-in-time
sequence. `fraud_ai.evaluation.stealth.sequence_summary`, formerly private, feeds the
`temporal_summary` section:

* **Counts over the window:** history length, device, ASN, country and address changes,
  payment methods added, security changes, failed logins and transactions.
* **Cadence:** minutes since the previous event and the median gap.
* **A 6-event timeline:** the event type, hours before, and whether the device and the
  network were known.

The packet uses the window of the sequence models being explained (default 16 events) and
contains no identifiers. It carries the GRU's stored probability next to gradient
boosting's, so a stealthy takeover that only the GRU flags is described as a
disagreement: "gru-1.0.0 scored … while gradient-boosting-1.0.0 scored …". The GRU's
flag is never presented as a confirmed finding.

The controlled limitation `sequence_models_limited` states the §8 finding: sequence models
added little over gradient boosting on this synthetic data.

