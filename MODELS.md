# Models

Stage 3 establishes **baselines**: logistic regression, random forest and gradient
boosting, trained and evaluated so that later models have something honest to beat. The
Stage 5 neural network and autoencoder are documented in [NEURAL_MODELS.md](NEURAL_MODELS.md). Nothing in this stage makes a fraud
decision. Model outputs are probabilities, stored as predictions; thresholds are evaluated,
never enforced.

> **All numbers in this document come from the bundled synthetic generator.** They show that
> the pipeline works and how the models behave on that data. They say nothing about
> real-world fraud rates, real detection performance or real losses.

## 1. Pipeline

```
fraud-ai train all
  │  1. dataset   TrainingDatasetBuilder (Stage 2): point-in-time vectors + labels resolved
  │               separately under the label-availability policy
  │  2. X / y     ModelMatrix.from_vectors(...) - feature values only; y from the labels
  │  3. split     time-ordered train / validation / test (same split for every model)
  │  4. fit       Preprocessor.fit(train) -> estimator.fit(train)       [seeded, 1 thread]
  │  5. evaluate  train, validation, test metrics + threshold analysis + overfitting checks
  │  6. inspect   coefficients / impurity / permutation importance (never used by decisions)
  │  7. save      models/<name>-<version>/{estimator.joblib, preprocessor.json, manifest.json}
  │  8. register  model_versions row with fingerprints, split sizes, seed, hyperparameters,
  │               library versions and the artefact SHA-256
  ▼
fraud-ai score <event> --model <name>-<version>
     event -> feature snapshot (as of the event) -> preprocessor -> model -> probability
           -> model_predictions row (linked to the snapshot)
```

Code: `fraud_ai/models/`, with modules `matrix`, `preprocessing`, `splits`, `metrics`,
`estimators`, `training`, `scoring`, `registry` and `report`.

## 2. What may enter the model (leakage guards)

`ModelMatrix` is the only path from data to an estimator.

* `from_vectors` reads `FraudFeatureVector.values` and `missing` only. Event ids, user ids,
  timestamps, feature hashes, labels and label provenance stay on the dataset examples.
* `from_records` (tabular input) rejects:
  * any column that is not a feature of the declared feature version;
  * any column whose name looks like an id (`*_id`, `id`), a timestamp (`*_at`,
    `timestamp`, `date`), a label (`label*`, `is_fraud`, `y`, `target`, `fraud_type`),
    provenance, a hash, a snapshot or a status.

  Such names can only be allowed through an explicit per-version approval list.
  `fraud-features-1.0.0` approves none: it has no raw timestamps, only elapsed durations.
* A matrix must have exactly one feature version, the current catalogue fingerprint and
  the canonical feature order. Mixed versions, an edited catalogue or a reordered feature
  list are refused.
* A loaded model refuses:
  * a different feature version or catalogue fingerprint;
  * an unsupported preprocessing version;
  * an artefact whose SHA-256 differs from the one recorded at training;
  * event kinds it was not trained on;
  * a feature snapshot computed for any moment other than the event itself.

These refusals are tested in `tests/test_model_matrix.py`, `test_preprocessing.py` and
`test_model_scoring.py`.

## 3. Time-ordered splits

Fraud data is temporal: models are trained on the past and used on the future, so the
evaluation must look the same. Random shuffling is not offered as a default.

* **Fraction split (default).** Examples are sorted by (event time, event id). The oldest
  70% train, the next 15% validate and the latest 15% test (`--train-fraction` and
  `--validation-fraction` change this). Cut points move past equal timestamps, so
  `max(train) < min(validation)` and `max(validation) < min(test)` hold strictly.
* **Date split.** `--train-end D1 --validation-end D2` gives train `< D1 <=` validation
  `< D2 <=` test.
* **Window.** The default window avoids label bias:
  * the label cutoff is the latest moment the database knows about;
  * the event range ends at `cutoff - maturity` (30 days by default).

  Every example, fraud or not, has therefore had the same time for its label (for example
  a chargeback) to arrive. Without this, recent periods would contain known fraud but
  immature negatives.
* **One split for all models.** Every model in a run uses the identical dataset
  (fingerprinted) and the identical split.

## 4. Preprocessing and missing values

`preprocessing-1.0.0` is fitted on the **training split only**, serialised to
`preprocessor.json` and reloaded exactly. Output column order follows the feature-set order.

| Feature type | Columns | Missing handling |
|---|---|---|
| numeric (float/int) | value | Imputed with the *training median* (never a silent 0), plus three indicators: `__unknown`, `__not_observed`, `__not_applicable` |
| boolean | `=true`, `=false` | `=unknown`, `=not_observed`, `=not_applicable` one-hot categories |
| categorical | one per declared category, plus `=__other__` for unseen values | the same three missing categories |

* The three Stage 2 missing reasons stay distinct all the way into the model. For example,
  "no previous transaction" (`not_observed`) is not "the intel gave no answer" (`unknown`).
* **Logistic regression** also applies `sign(x) * log1p(|x|)` to heavy-tailed units
  (counts, durations, amounts, ratios), then standardises with the training mean and
  standard deviation.
* **Tree models** use raw values; they are invariant to monotone transforms.
* Columns constant on the training split are dropped. Which ones is recorded and
  deterministic.
* The preprocessing configuration and version are stored with the model version.

## 5. Models and class imbalance

| Model | Implementation | Defaults |
|---|---|---|
| `logistic-regression` | `sklearn.LogisticRegression` | `C=0.5`, `lbfgs`, `class_weight="balanced"` |
| `random-forest` | `sklearn.RandomForestClassifier` | 300 trees, `min_samples_leaf=3`, `max_features="sqrt"`, `class_weight="balanced_subsample"` |
| `gradient-boosting` | `sklearn.HistGradientBoostingClassifier` | lr 0.05, 300 iterations, 15 leaves, `min_samples_leaf=20`, L2 1.0, **early stopping off**, `class_weight="balanced"` |

* **Dependencies.** Only scikit-learn was added; it brings numpy, scipy, joblib and
  threadpoolctl. XGBoost would add a heavy dependency without a clear benefit at this
  scale.
* **Early stopping is off.** It would carve an unseeded random validation slice out of the
  time-ordered training data.
* **Class weighting is the default.** Weighting rescales the loss so the rare class matters
  as much in total as the majority. It invents no data and leaves predictions on the
  original examples. `--imbalance oversample` (random oversampling of positives, training
  split only, seeded) exists for controlled experiments; `none` disables both.
* **Accuracy is never reported or optimised.** A model that never flags anything is "99%
  accurate" at 1% fraud.

## 6. Metrics and thresholds

For each of train, validation and test:

* PR-AUC (average precision), ROC-AUC and the Brier score;
* at the evaluation threshold: precision, recall, F1, FPR, FNR, TPR, TNR, TP/FP/TN/FN and
  the confusion matrix.

A ratio with an empty denominator is reported as `n/a`, never as 0.

* **What matters most here:** PR-AUC, precision and recall at the chosen threshold, and the
  false positive rate. That last one is the share of legitimate customers who would be
  inconvenienced.
* **The threshold is an evaluation setting, not a decision.** Each model is analysed at
  0.10 to 0.90 on both validation and test.
* **A validation-selected threshold** (maximum F1 on validation, ties towards fewer flags)
  is also reported, with the test metrics it would produce. Selecting on validation and
  reporting on test avoids tuning to the test set.
* Nothing is blocked: the risk engine (later stages) owns decisions.

## 7. Overfitting checks

These warnings are stored with the model and printed by `train`, `models show` and
`compare-models`:

* train PR-AUC more than 0.10 above test;
* train PR-AUC of 0.99 or more while test is below 0.95 (memorisation);
* validation and test PR-AUC more than 0.15 apart (instability across time);
* fewer than 30 fraud examples in test (wide uncertainty);
* a split with no fraud at all (PR-AUC undefined).

## 8. Versioning and reproducibility

* **Naming.** Versions are named deterministically (`logistic-regression-1.0.0`) and are
  never overwritten. The registry row and the artefact directory are both checked before
  training starts; choose a new `--version`.
* **What `model_versions` stores:**
  * model name and version, algorithm and training timestamp;
  * dataset fingerprint (SHA-256 over the feature version, catalogue fingerprint, label
    policy, kinds, range and every (event id, feature hash, label));
  * feature version, catalogue fingerprint and preprocessing version;
  * train/validation/test row counts, hyperparameters and seed;
  * all metrics, the threshold analysis, warnings and inspection output;
  * the artefact path and SHA-256, and the active flag;
  * a training manifest with the Python, platform and library versions (scikit-learn,
    numpy, scipy, joblib, SQLAlchemy, pydantic).
* **Determinism.** The seed controls every estimator and the oversampler. Native thread
  pools are pinned to one thread for training and inference, which makes results bit-for-
  bit reproducible on the same stack. A test retrains all three models and asserts
  identical predictions. The benchmark runs above reproduced identical metrics across
  three separate training runs.
* **`fraud-ai evaluate reproduce <model>`** rebuilds the recorded dataset and split, reloads the
  verified artefact and reports whether the data is unchanged and the metrics reproduce
  exactly. It exits non-zero if they do not.
* **Artefact safety.** `estimator.joblib` is a pickle, and loading a pickle executes code.
  The digest over `estimator.joblib` and `preprocessor.json` is therefore checked against
  the database **before** deserialising. Only load artefacts produced by this pipeline.

## 9. Scoring

`score_event(session, event_id, model)` works as follows:

1. It loads the point-in-time snapshot as of the event (creating it if absent). A snapshot
   for any other moment is refused.
2. It loads the verified artefact, checks compatibility and the event kind, and computes
   P(fraud).
3. It writes a `model_predictions` row with the event, model and version, feature version,
   `feature_snapshot_id`, probability, threshold, `predicted_class` and timestamp.

* There is **one prediction per (event, model version)**, enforced by a unique constraint.
  Scoring again returns the stored prediction if it reproduces exactly. A different
  probability or threshold raises `PredictionConflictError`: a historical prediction is
  never silently recomputed or replaced.
* **Latency is reported in two parts.** Model inference (preprocessing plus estimator) is
  measured separately from the database-bound snapshot and prediction work (section 11).

## 10. Example comparison (synthetic)

> **Historical (Stage 3 generator).** The figures in this section were produced before
> Stage 4 removed several giveaway signals from the synthetic generator (see
> [EVALUATION.md](EVALUATION.md) §11). They are kept to document Stage 3, and are **not**
> comparable with current results. Current synthetic results, with confidence intervals,
> are in [EVALUATION.md](EVALUATION.md) §12.

The output of `fraud-ai train all --version 1.0.1` on 300 synthetic users over 180 days
(`fraud-ai seed --users 300 --days 180`, seed 7). The default 30-day maturity gives 9,206
labelled transactions, 92 of them fraud (1.00%):

```text
dataset 4ac0f40742085e29: 9206 examples, 92 fraud (1.00%)
  train         6444 rows    52 fraud  2025-09-02T07:33:50 .. 2026-06-17T07:21:57
  validation    1381 rows    15 fraud  2026-06-17T07:41:20 .. 2026-07-11T07:25:12
  test          1381 rows    25 fraud  2026-07-11T08:01:54 .. 2026-08-01T23:06:31
WARNING logistic-regression-1.0.1: only 25 fraud examples in test: metrics have wide uncertainty
WARNING random-forest-1.0.1: only 25 fraud examples in test: metrics have wide uncertainty
WARNING gradient-boosting-1.0.1: train PR-AUC >= 0.99: the model may be memorising training data
WARNING gradient-boosting-1.0.1: only 25 fraud examples in test: metrics have wide uncertainty

model                               PR-AUC  ROC-AUC   thr   prec  recall     F1     FPR  train s  p50 ms    rows/s  warn
------------------------------------------------------------------------------------------------------------------------
logistic-regression-1.0.1            0.907    0.991  0.50  0.622   0.920  0.742  0.0103     0.08    0.46     11025     1
random-forest-1.0.1                  0.921    0.988  0.50  0.917   0.880  0.898  0.0015     1.94   17.67     10238     1
gradient-boosting-1.0.1              0.943    0.993  0.50  0.950   0.760  0.844  0.0007     3.03    2.33     11317     2

dataset dataset-4ac0f40742085e29  feature version fraud-features-1.0.0  rows train/validation/test = 6444/1381/1381 (test fraud examples: 25)
Results are measured on the configured held-out test split. With the bundled generator this data is SYNTHETIC: it says nothing about real-world fraud rates.
No model is selected automatically: compare PR-AUC, precision/recall at the operating threshold and the false positive rate together.
```

Threshold analysis on the synthetic **test** split (`fraud-ai models show ...`):

| Model | thr | precision | recall | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| logistic-regression | 0.30 | 0.471 | 0.960 | 0.0199 | 24 | 27 | 1329 | 1 |
| logistic-regression | 0.50 | 0.622 | 0.920 | 0.0103 | 23 | 14 | 1342 | 2 |
| logistic-regression | 0.90 | 0.870 | 0.800 | 0.0022 | 20 | 3 | 1353 | 5 |
| random-forest | 0.30 | 0.880 | 0.880 | 0.0022 | 22 | 3 | 1353 | 3 |
| random-forest | 0.50 | 0.917 | 0.880 | 0.0015 | 22 | 2 | 1354 | 3 |
| random-forest | 0.90 | 1.000 | 0.120 | 0.0000 | 3 | 0 | 1356 | 22 |
| gradient-boosting | 0.30 | 0.955 | 0.840 | 0.0007 | 21 | 1 | 1355 | 4 |
| gradient-boosting | 0.50 | 0.950 | 0.760 | 0.0007 | 19 | 1 | 1355 | 6 |
| gradient-boosting | 0.90 | 1.000 | 0.520 | 0.0000 | 13 | 0 | 1356 | 12 |

### How to read this

* **Uncertainty.** The test split has **25 fraud examples**. One more or one fewer caught
  fraud moves recall by 0.04. The PR-AUC differences between the three models (0.907 /
  0.921 / 0.943) are within the noise such a small sample implies. No model is declared
  "best".
* **A second world shows the noise.** On a separate 150-user synthetic world (PostgreSQL
  benchmark, 8 fraud examples in test), random forest scored a PR-AUC of 0.73 against
  gradient boosting's 0.95. The ranking is not stable at these sample sizes.
* **Overfitting is flagged, not hidden.** Gradient boosting reaches train PR-AUC 1.000, so
  it is warned as possibly memorising, although its test PR-AUC stays high.
* **The trade-offs differ.** Logistic regression catches more fraud at 0.5 but flags 7–14×
  more legitimate transactions (FPR 1.03% against 0.07–0.15%). Each model's probability
  scale is different, so thresholds are not transferable between models.
* **The synthetic data is easier than reality.**
  * The generator makes some fraud patterns quite distinctive. For example, most synthetic
    fraud ships to a shipping address created minutes earlier.
  * Permutation importance for gradient boosting is dominated by `address_age_days`.
  * Legitimate counter-examples (house moves, new customers, VPN users, large legitimate
    purchases) exist, but they are fewer than real life would provide. Friendly fraud is
    deliberately indistinguishable.
  * High synthetic PR-AUC therefore mostly reflects the generator, not a property of the
    models.

### Inspection (non-LLM)

Inspection output is informational only; it never feeds a decision.

* **Logistic regression.** Standardised coefficients are the log-odds per unit of the
  transformed feature. The strongest positive ones on this data were `logins_last_5m`,
  `time_since_device_last_seen_hours`, `transaction_amount_minor_units`,
  `devices_per_account` and `unusually_high_transaction=true`.
* **Random forest.** Impurity importance is biased towards high-cardinality columns. Here
  it ranked transaction amount, address age, `new_address`, device age and `new_device`
  highest.
* **Gradient boosting.** Permutation importance (the drop in validation PR-AUC, seeded) put
  `address_age_days` far ahead of the rest.

## 11. Performance (synthetic, this machine)

From `scripts/benchmark_models.py`. Model-only timings exclude the database.

| Measurement | logistic | random forest | gradient boosting |
|---|---|---|---|
| training time (6,444 rows) | 0.08 s | 1.99 s | 2.98 s |
| single-event inference, model only, p50 / p95 | 0.48 / 0.84 ms | 17.3 / 18.1 ms | 2.3 / 3.5 ms |
| batch inference, model only | ~11,000 rows/s | ~7,800 rows/s | ~11,400 rows/s |

| Database-bound step | SQLite (300 users) | PostgreSQL (150 users, local) |
|---|---|---|
| point-in-time feature extraction, p50 / p95 | 10.8 / 12.6 ms | 17.5 / 22.9 ms |
| `score_event` end to end (snapshot + model + row), p50 / p95 | 18.8 / 29.2 ms | 28.4 / 31.3 ms |

* The random forest's single-event cost is dominated by evaluating 300 trees per call.
* Native thread pools are pinned to one thread. Without that, gradient-boosting p95
  latency exceeded 3 s when two processes shared the CPU.
* End-to-end scoring is dominated by feature extraction, not by the model.

## 12. Limitations

* **Synthetic data only.** No claim is made about real fraud, real detection rates or real
  losses. Test sets hold tens of fraud examples. Stage 4 therefore reports bootstrap
  confidence intervals and paired tests, and those intervals usually overlap.
* **Transaction models only by default.** Login events carry very sparse labels. `--kind
  login|all` works, but needs `--implicit-negatives` and a careful maturity choice.
* **Probabilities are not calibrated in scoring.** Class weighting shifts probabilities
  upward. Stage 4 fits and stores sigmoid and isotonic calibrators (on validation only),
  but scoring does not apply them until one is explicitly adopted.
* **The single split is only the baseline.** Stage 4 adds walk-forward folds; on synthetic
  worlds these show large fold-to-fold variation.
* **Pickled artefacts** are safe only when produced by this pipeline and verified by
  digest.

## 13. Evaluation

Confidence intervals, walk-forward evaluation, calibration, cost curves, scenario, cohort
and error analysis, and paired model comparison are described in
[EVALUATION.md](EVALUATION.md). The command is `fraud-ai evaluate ...`. The Stage 3
reproducibility check is now `fraud-ai evaluate reproduce <model>`.

## 14. Neural models (Stage 5)

The feed-forward network (`fraud-ai train neural-network`) uses the same `FraudModel`
contract, preprocessing, split, registry, scoring and evaluation as the baselines. It is
built and loaded through `fraud_ai/models/factory.py`.

On the 1,000-user synthetic world, **gradient boosting remains stronger**:
* gradient boosting minus the network is +0.054 PR-AUC [−0.004, +0.115];
* McNemar at 0.5: gradient boosting is right on 11 events where the network is wrong,
  against 1 the other way (p = 0.006);
* the network does not recover any of gradient boosting's misses.

The details, the experimental autoencoder and all caveats are in
[NEURAL_MODELS.md](NEURAL_MODELS.md).
