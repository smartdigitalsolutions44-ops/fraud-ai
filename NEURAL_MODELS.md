# Neural models (Stage 5)

> **Synthetic evidence only.** Every result in this document comes from data produced by
> the bundled synthetic generator. It says nothing about real-world detection rates,
> losses, savings or production readiness. The goal of Stage 5 is to *understand* whether
> a neural network adds anything over the Stage 3 baselines, not to make it win.

## 1. What was built

| Component | Module | Purpose |
|---|---|---|
| Feed-forward classifier | `fraud_ai/models/neural.py` | P(fraud), the same contract as the baselines |
| Shared training loop (Stage 6 refactor) | `fraud_ai/models/torch_training.py` | One loop for the feed-forward, GRU, Transformer and hybrid models |
| Autoencoder (experimental) | `fraud_ai/models/anomaly.py` | An anomaly score for unusual behaviour. **Not** a fraud probability |
| PyTorch support | `fraud_ai/models/torch_support.py` | Device selection, determinism, safe weight files, hashes |
| Model factory | `fraud_ai/models/factory.py` | Builds and loads every model kind; no special cases elsewhere |
| Experiment runner | `fraud_ai/models/experiments.py` | A small grid, selected on validation PR-AUC |
| Grouped permutation importance | `fraud_ai/models/inspection.py` | Model-agnostic inspection |
| Complementarity | `fraud_ai/evaluation/complementarity.py` | Does B add signal where A fails? |
| Anomaly evaluation | `fraud_ai/evaluation/anomaly_report.py` | Distributions, PR-AUC, FPR at anomaly thresholds, shift |

**Framework.** PyTorch is the only new dependency.
* The code runs on the CPU. CUDA is used only when requested (`--device cuda`, or `auto`
  when a GPU is present).
* The measurements in this document are CPU-only: the benchmark machine has no GPU.

## 2. One interface for every model

The neural network implements the same `FraudModel` contract as the baselines:
`train(matrix, labels, validation=None)`, `predict`, `predict_proba`, `evaluate`,
`explain`, `manifest`, `save` and `load`.

* **Validation during training.** `train` accepts the *validation* split for early stopping.
  The scikit-learn baselines ignore it. The test split is never passed to training.
* **One factory.** Training, `fraud-ai evaluate …`, walk-forward retraining and
  `fraud-ai score` all go through `factory.build_model` and `factory.load_model`, so none
  of them has neural-specific code.
* **Score kind.** Each model declares a `score_kind`, which is either `fraud_probability` or
  `anomaly_score`. The following refuse anomaly-score models:
  * `score_event` (they are never stored as fraud predictions);
  * `build_context` (unless `allow_anomaly=True`);
  * the default model comparison.

## 3. Preprocessing and inputs

* **Same preprocessing as the baselines.** The network uses the Stage 3 deterministic
  preprocessing (`preprocessing-1.0.0`) in the same configuration as logistic regression:
  * signed-log transform for heavy-tailed units;
  * median imputation from the training rows;
  * standardisation of numeric values;
  * one-hot categories;
  * **three separate missing-reason indicators** (`unknown`, `not_observed`,
    `not_applicable`). They are never collapsed (tested).
* **Same checks.** The feature order, feature version, catalogue fingerprint and
  preprocessing version are the ones the baselines use, and the same checks refuse
  incompatible inputs.
* **Input clip (±10 standard deviations).** Standardised inputs are clipped to ±10 before
  the network (the `input_clip` hyperparameter, which is recorded).
  * Why: features that are rarely observed get tiny training spreads, so their z-scores
    reached the hundreds and dominated activations and, above all, the autoencoder's
    reconstruction error.
  * The preprocessing itself is unchanged, and the baselines are unaffected.

## 4. Architecture

```
input (≈ 280 columns)
  → Linear → LayerNorm → ReLU → Dropout      (hidden_sizes[0])
  → Linear → LayerNorm → ReLU → Dropout      (hidden_sizes[1])
  → …
  → Linear → 1 logit → sigmoid at inference
```

* **Configurable:**
  * hidden sizes;
  * activation (ReLU or GELU);
  * normalisation (LayerNorm, BatchNorm or none);
  * dropout, batch size, learning rate and weight decay;
  * maximum epochs, patience and minimum improvement;
  * loss, focal gamma, gradient clip, input clip and device.
* **Why LayerNorm by default.** LayerNorm normalises each row on its own, so a single-event
  prediction equals the same row scored in a batch (tested). BatchNorm makes training
  depend on batch composition, which is awkward when fraud is about 1% of rows.
* **Categorical embeddings: not yet.** One-hot encoding is kept for this baseline network.
  An embedding layer can replace the one-hot block later without changing the interface.

## 5. Training loop

* **Mini-batches.** Each epoch shuffles the rows with a seeded `torch.Generator`.
* **Optimiser.** AdamW with a constant learning rate. A scheduler was not justified at this
  scale, so none is used.
* **Loss.** `BCEWithLogitsLoss(pos_weight = negatives / positives)`: fraud weighting
  without duplicated rows.
  * Focal loss is available for experiments: the same weighting multiplied by
    `(1 − p_t)^γ`.
  * Oversampling is available but is not the default.
* **Gradient clipping** by norm (1.0 by default).
* **History recorded every epoch:**
  * train loss and validation loss;
  * train PR-AUC, validation PR-AUC and validation ROC-AUC;
  * learning rate.
* **Early stopping on validation PR-AUC**, with patience and a minimum improvement. The
  best checkpoint is restored.
  * PR-AUC is the selection metric because it is what the project evaluates, and because
    class-weighted validation loss rewards over-confident scores.
  * If the validation split has only one class, validation loss is used instead, and the
    summary records which was used.
  * Without a validation split, the latest 15% of the (time-ordered) *training* rows are
    held out. It is never the test split.
* **Overfitting flags** come from the history and are copied into the model's warnings:
  * the train/validation PR-AUC gap at the selected epoch;
  * train PR-AUC ≥ 0.99 (possible memorisation);
  * validation PR-AUC falling after the selected epoch;
  * validation loss rising by more than 25% after the selected epoch.

  Early stopping restores the best epoch, but these flags are never hidden.

## 6. Reproducibility and artefacts

**Determinism.** Training and inference run inside `torch_support.deterministic`:
* a seeded generator;
* `torch.use_deterministic_algorithms(True)`;
* one CPU thread;
* `CUBLAS_WORKSPACE_CONFIG` set for CUDA.

On the CPU the same seed, data and library versions give **bit-identical** predictions
(tested). Results may differ across PyTorch versions, CPU instruction sets, or CPU versus
GPU, so the PyTorch version and device are recorded.

**Artefacts.** Each model is saved to `models/neural-network-<version>/`:

| File | Content |
|---|---|
| `model.pt` | `state_dict` tensors only. Loaded with `torch.load(weights_only=True)` after the digest check |
| `config.json` | Hyperparameters, input width, seed, imbalance |
| `preprocessing.json` | The fitted Stage 3 preprocessing |
| `history.json` | The per-epoch history and the training summary |
| `manifest.json` | Architecture, parameter count, optimiser, training summary, environment (PyTorch, device, determinism) |
| `training_manifest.json`, `metrics.json` | The pipeline record (dataset, split, metrics, warnings, timings) |
| `artifact_hashes.json` | The SHA-256 of every file, plus the prediction digest |

* **The prediction digest** covers `model.pt`, `config.json` and `preprocessing.json`. It is
  stored in `model_versions.artifact_sha256` and verified **before** any weights are read.
  A tampered or missing file is refused (tested).
* **No pickled model objects** are ever loaded.
* **Versions are never overwritten.**
* **`model_versions` records:**
  * the algorithm `torch.FeedForward`;
  * the hyperparameters, seed, dataset fingerprint, feature version and preprocessing
    version;
  * the split sizes, metrics, warnings and permutation importance;
  * the full manifest, including the early-stopping epoch and the number of epochs
    completed.

## 7. Autoencoder anomaly model (experimental)

```
input → 64 → 32 → bottleneck 8 → 32 → 64 → reconstruction
```

* **Trained on legitimate rows only.** Fraud rows are excluded from fitting, and their
  number is recorded. Early stopping uses the reconstruction loss on the *legitimate*
  validation rows.
* **Anomaly score:** the fraction of *training* legitimate events that reconstruct better.
  It is stored as 1,001 reference quantiles, so 0.99 means "more unusual than 99% of
  normal training behaviour".
* **It is not a fraud probability.** Its `score_kind` is `anomaly_score`. It cannot be
  used with `fraud-ai score`, it is excluded from the default comparisons, and it is
  never combined into a production score.
* **What it measures.** It detects **unusual behaviour**, not fraud. Legitimate house
  movers, new customers and VPN users are unusual too.

## 8. CLI

```bash
fraud-ai train neural-network [--hidden 128,64,32 --dropout 0.3 --learning-rate 1e-3 \
    --weight-decay 1e-4 --max-epochs 60 --patience 8 --loss weighted_bce|focal \
    --activation relu|gelu --normalization layernorm|batchnorm|none --device cpu|auto|cuda]
fraud-ai neural experiments [--quick] [--max-epochs 60] [--no-focal]
fraud-ai neural training-history neural-network-1.0.0 [--format json]
fraud-ai neural inspect neural-network-1.0.0
fraud-ai anomaly train-autoencoder [--hidden 64,32 --bottleneck 8 ...]
fraud-ai anomaly evaluate 1.0.0 [--compare-with gradient-boosting-1.0.0]
fraud-ai evaluate complementarity gradient-boosting-1.0.0 neural-network-1.0.0 --anomaly 1.0.0
# and every generic command:
fraud-ai evaluate confidence|walk-forward|calibration|scenarios|errors|costs|compare|report ...
fraud-ai score <event-id> --model neural-network-1.0.0
```

## 9. Results on the 1,000-user synthetic world

> **Historical (Stage 5 generator).** Stage 6 added temporal takeover and legitimate
> lookalike scenarios, so this world no longer matches the current generator. These
> figures document Stage 5. Current comparisons, including the feed-forward network, are
> in [SEQUENCE_MODELS.md](SEQUENCE_MODELS.md) §8.

Produced by `scripts/neural_benchmark.py` on the same world as the Stage 4 benchmark:
1,000 users, 180 days, seed 2026, 14-day maturity, SQLite, 1,000 bootstrap iterations,
CPU only (no GPU on this machine).

* **Dataset:** 34,388 labelled transactions, 354 of them fraud (1.03%). Its fingerprint is
  `5454166f04129b7a…`, the same as in Stage 4.
* **Splits:** identical for every model.

| Split | Rows | Fraud |
|---|---|---|
| train | 24,072 | 256 |
| validation | 5,158 | 46 |
| test | 5,158 | 52 |

> On this synthetic evaluation window the test split has **52 fraud events**. Every
> interval below is correspondingly wide.

### 9.1 Hyperparameter experiments (validation only)

36 configurations were tried:
* hidden layers `[64,32]`, `[128,64,32]` or `[256,128,64]`;
* dropout 0.1, 0.3 or 0.5;
* learning rate 1e-3 or 3e-4;
* weight decay 0 or 1e-4.

The grid took 671 s in total.

* **Validation PR-AUC was flat** across the grid: from 0.804 to 0.848, with a median of
  0.836. Most configurations lie within a few hundredths of each other, which is within
  seed-to-seed noise.
* **Selected configuration: `[128, 64, 32]`, dropout 0.3, learning rate 1e-3, weight decay
  1e-4** (validation PR-AUC 0.848). This happens to be the default. The runners-up were
  `[256,128,64]` variants at 0.847 and 0.846.
* **Dropout 0.5** gave the lowest results (0.80–0.82).
* **Loss experiment** (same architecture, same seed): focal loss scored 0.826 against 0.848
  for weighted BCE. Focal loss is therefore **not** adopted. This is a single run per
  loss, so the result is indicative only.

### 9.2 The trained model: `neural-network-1.0.0`

* **Size:** 31,425 parameters.
* **Input:** 280 columns after preprocessing.
* **Loss:** `BCEWithLogitsLoss` with `pos_weight` 93.0.
* **Optimiser:** AdamW.
* **Early stopping:** on validation PR-AUC. The best epoch was **29 of 37** (patience 8).
* **Training time:** 22.3 s on one CPU thread.
* **Overfitting flag:** at the selected epoch the train/validation PR-AUC gap is 0.117
  (train 0.965, validation 0.848). It is reported, not hidden.
* **Gradient boosting memorises more:** it reaches a train PR-AUC of 1.000, against 0.965
  for the network.

### 9.3 Comparison on the identical test split (threshold 0.5, 95% stratified bootstrap)

| Model | PR-AUC | ROC-AUC | Precision | Recall | FPR | FNR | Brier | Log loss |
|---|---|---|---|---|---|---|---|---|
| logistic regression | 0.784 [0.689, 0.868] | 0.991 | 0.207 | 0.923 | 0.036 | 0.077 | 0.0286 | 0.108 |
| random forest | 0.884 [0.809, 0.945] | 0.997 | 0.872 | 0.654 | 0.001 | 0.346 | 0.0029 | 0.014 |
| gradient boosting | 0.956 [0.917, 0.985] | 0.999 | 0.957 | 0.846 | 0.000 | 0.154 | 0.0017 | 0.006 |
| **neural network** | **0.903 [0.839, 0.961]** | 0.996 [0.991, 0.999] | 0.833 [0.736, 0.932] | 0.769 [0.654, 0.885] | 0.002 [0.001, 0.003] | 0.231 | 0.0029 | 0.014 |

**Paired tests** (the difference is the first model minus the second, on the same
resampled rows):

| Pair | PR-AUC difference (95% CI) | McNemar at 0.5 (A right / B right) |
|---|---|---|
| gradient boosting − neural | **+0.054 [−0.004, +0.115]** | 11 / 1, p = 0.006 |
| random forest − neural | −0.019 [−0.072, +0.031] | 5 / 8, p = 0.58 |
| logistic − neural | −0.119 [−0.185, −0.062] | 8 / 176, p < 0.001 |

**On this synthetic evaluation window, gradient boosting remains stronger than the neural
network.** Its PR-AUC point estimate is 0.054 higher, and at the 0.5 threshold it is
right on 11 events where the network is wrong, against 1 the other way. The PR-AUC
difference interval only just includes zero.

* **Against random forest,** the intervals overlap: there is no reliable difference.
* **Against logistic regression,** the network's PR-AUC is higher and the interval
  excludes zero.

None of this declares a model best in general.

### 9.4 Walk-forward (30-day expanding windows, fresh retrain per fold)

The fold models are retrained from scratch, using the fold's own validation period for
early stopping and labels as known at each cutoff.

| Fold (test from) | Train rows / fraud | Test fraud | LR | RF | GB | NN |
|---|---|---|---|---|---|---|
| 5 (2026-04-29) | 4,473 / 15 | 71 | 0.498 | 0.512 | 0.516 | **0.580** |
| 6 (2026-05-29) | 9,990 / 83 | 76 | 0.691 | 0.738 | **0.830** | 0.814 |
| 7 (2026-06-28) | 15,659 / 164 | 58 | 0.735 | 0.817 | **0.896** | 0.839 |
| 8 (2026-07-28) | 21,437 / 218 | 40 | 0.754 | 0.856 | **0.924** | 0.900 |
| mean (sd) | | | 0.669 (0.117) | 0.731 (0.154) | 0.791 (0.188) | 0.783 (0.140) |

* **With little data** (fold 5: 15 training frauds), the network scores highest. Across
  folds it varies less than gradient boosting and random forest (sd 0.140, against 0.188
  and 0.154).
* **With more data,** gradient boosting pulls ahead.
* This is one fold per regime, without intervals. It is a hypothesis to test on more
  worlds and seeds, not a finding.

### 9.5 Calibration (fitted on validation, reported on test)

| Method | Brier | Log loss | ECE | PR-AUC |
|---|---|---|---|---|
| uncalibrated | 0.00292 | 0.0144 | 0.0034 | 0.903 |
| sigmoid | 0.00266 | 0.0133 | 0.0016 | 0.903 |
| isotonic | 0.00260 | 0.0112 | 0.0011 | 0.805 |

* **Better calibrated than logistic regression.** Class weighting makes the network
  over-confident at the top, but far less so than logistic regression (Brier 0.0029
  against 0.0286).
* **Reliability:** the 0.9–1.0 bucket holds 45 events with an observed fraud rate of 0.89.
* **Sigmoid** calibration improves Brier without changing the ranking.
* **Isotonic** calibration lowers Brier further but costs 0.10 PR-AUC, because it creates
  ties.

### 9.6 Scenarios and cohorts (test, threshold 0.5)

| Segment | n | NN | GB | RF | LR |
|---|---|---|---|---|---|
| account_takeover (recall) | 30 | 0.83 | 0.97 | 0.63 | 0.97 |
| stealthy_account_takeover (recall) | 16 | **0.69** | 0.94 | 0.44 | 0.94 |
| new_account_card_fraud (recall) | 15 | 1.00 | 1.00 | 1.00 | 1.00 |
| high_velocity_fraud (recall) | 23 | 1.00 | 1.00 | 0.78 | 1.00 |
| drop_address_fraud (recall) | 35 | 0.89 | 1.00 | 0.80 | 1.00 |
| friendly_fraud (recall, *small sample*) | 7 | 0.00 | 0.00 | 0.00 | 0.57 |
| new_legitimate_customer (FPR) | 420 | 0.0071 | 0.0024 | 0.0119 | 0.0929 |
| large_legitimate_purchase (FPR) | 407 | 0.0025 | 0.0000 | 0.0000 | 0.0835 |
| shared_network_customer (FPR) | 613 | 0.0016 | 0.0000 | 0.0000 | 0.0343 |
| house_mover (FPR) | 419 | 0.0000 | 0.0000 | 0.0000 | 0.0525 |
| legitimate_vpn_user (FPR) | 327 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

* **Takeovers:** the network misses more of them than gradient boosting, especially
  stealthy ones.
* **Operational cohorts:** as with every model, only **new accounts** are flagged, with 3
  false positives in 99 legitimate events (FPR 3.0%, against a global 0.16%).
* **Errors:**
  * 8 false positives: 3 new customers, 2 normal, 2 accounts from the
    credential-stuffing scenario, and 1 shared network;
  * 12 false negatives: 5 account takeovers and 7 friendly fraud.

### 9.7 Does the network add signal where gradient boosting fails?

**Disagreement groups** (each model at 0.5):

| Group | Events | Fraud | What the events are |
|---|---|---|---|
| both high | 41 | 40 | 25 takeovers and 15 new-account card frauds |
| both low | 5,105 | 8 | 7 friendly fraud and 1 takeover |
| gradient boosting high, network low | 5 | 4 | takeovers, all to a *new* address with *no* password reset |
| gradient boosting low, network high | 7 | 0 | new customers, normal and credential-stuffing accounts: all false positives |

* **Gradient boosting's 8 misses:** the network catches **none** of them. They are 7
  friendly fraud cases (indistinguishable by design) and 1 takeover.
* **Gradient boosting's 2 false positives:** the network clears 1 of them, but adds 7 new
  false positives.
* **Combinations** (research only, never persisted):

| Combination | PR-AUC | Difference vs gradient boosting |
|---|---|---|
| average of gradient boosting and network | 0.958 | +0.002 [−0.021, +0.028] |
| rank average | 0.954 | −0.002 [−0.040, +0.035] |
| rank average with anomaly score | 0.801 | −0.155 [−0.246, −0.076] |

**On this window the network does not add signal where gradient boosting fails.** Its
disagreements are mostly false positives. They do not reveal a different fraud pattern.

### 9.8 Autoencoder anomaly score (experimental)

* **Training:** 25 s, on legitimate training rows only.
* **Distributions (test):**
  * fraud: median anomaly score 0.98, 10th percentile 0.37;
  * legitimate: median 0.67, 90th percentile 0.95.
* **Ranking:** PR-AUC **0.327 [0.205, 0.475]** against a prevalence of 0.010. ROC-AUC is
  0.813 [0.726, 0.893].
* **Flagging:**
  * at 0.95 it flags 11.2% of events, with recall 0.69 and **FPR 10.7%**;
  * at 0.99 it flags 3.7%, with recall 0.42 and FPR 3.3%.
* **Unusual is not fraudulent.** At 0.95 it flags:
  * 20.5% of legitimate new customers;
  * 18.2% of large legitimate purchases;
  * 9.5% of house movers;
  * 7.0% of VPN users.
* **Stealthy takeovers:** 0.63 recall at 0.95.
* **Against gradient boosting:** it scores **none** of gradient boosting's 8 missed frauds
  at or above 0.95. It adds 544 legitimate events above its threshold that gradient
  boosting scores low.
* **Distribution shift:** the share of legitimate events at or above 0.95 rises from 3–5%
  during the training months to 9.4% in July and 10.9% in August 2026. Later behaviour
  drifts away from the training reference.

**Conclusion.** The anomaly score is a weak, noisy fraud signal on this data. It is more
useful as a drift and novelty indicator than as a detector. It stays separate and
experimental.

### 9.9 Inspection (not used by any decision)

Grouped permutation importance (drop in validation PR-AUC):

| Model | Top features |
|---|---|
| neural network | `time_since_device_last_seen_hours` (0.074), `payment_methods_per_account` (0.071), `transactions_last_1h` (0.054), `successful_logins_last_1h`, `logins_last_5m` |
| gradient boosting | `time_since_device_last_seen_hours` (0.149), `payment_method_age_days` (0.115), `time_since_previous_transaction_minutes` (0.112), `address_age_days` |
| random forest (impurity) | `new_device`, `address_age_days`, `device_age_days` |
| logistic regression (coefficients) | `new_payment_method=true`, `transaction_amount_minor_units`, `logins_last_15m` |

* **Common ground:** both non-linear models lean on device recency.
* **Where the network differs:** it relies more on velocity (logins and transactions in
  the last hour) and on payment-method counts.

### 9.10 Timings (CPU only, this machine, model-only; database time excluded)

| Model | Train | Single-event p50 / p95 | Batch |
|---|---|---|---|
| logistic regression | 0.7 s | 0.47 / 0.67 ms | 5,520 rows/s |
| random forest | 9.1 s | 17.5 / 17.9 ms | 10,384 rows/s |
| gradient boosting | 10.3 s | 2.33 / 2.84 ms | 10,121 rows/s |
| **neural network** | 22.3 s | **0.55 / 0.71 ms** | 9,419 rows/s |
| autoencoder | 25.0 s | 0.65 / 0.82 ms | 10,123 rows/s |

Other timings:
* Building the dataset (point-in-time features for 34k events) takes about 250 s. It
  dominates end-to-end time, as in Stage 3.
* CUDA is not available here, so there is no CPU/GPU comparison.
* A larger world (`--seed-users 2500`) is supported by the script but was not run for this
  report, because of time.

## 10. Limitations

* **Synthetic data only.** All figures describe one synthetic generator and one
  time-ordered split.
* **Small test split.** The test split has about 50 fraud events, so intervals are wide.
* **Not independent.** Events from one account are correlated, so the bootstrap intervals
  are, if anything, too narrow.
* **One seed per configuration** in the grid. Differences of a few hundredths in
  validation PR-AUC are within seed-to-seed noise.
* **CPU-only measurements.** The benchmark machine has no GPU, so GPU paths are
  implemented but not measured.
* **Determinism has limits.** Bit-identical reproduction holds for the same PyTorch
  version on a CPU. It is not guaranteed across versions or on a GPU.
* **Permutation importance** describes what the network relies on in this data, not
  causes. Correlated features share credit unpredictably.
* **The autoencoder** is sensitive to the input clip and to rare categories. Its scores
  measure novelty relative to the training window, which also rises under legitimate
  drift.
