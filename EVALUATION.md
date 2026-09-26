# Evaluation (Stage 4)

This document describes how fraud-ai models are evaluated and what the evaluation can and
cannot tell you.

> **Synthetic evidence only.** Every number in this document comes from data produced by
> the bundled synthetic generator. It is evidence about the evaluation machinery and about
> the generator. It says **nothing** about real-world detection rates, fraud losses,
> savings or production readiness. No model is declared best.

## 1. What is evaluated, and how

| Question | Method | Module | CLI |
|---|---|---|---|
| How uncertain is each metric? | Stratified percentile bootstrap: 95% by default, seeded, configurable iterations | `evaluation/stats.py` | `evaluate confidence` |
| Is performance stable over time? | Walk-forward (expanding window) retraining with as-of labels | `evaluation/walk_forward.py` | `evaluate walk-forward` |
| Are the probabilities calibrated? | Uncalibrated vs Platt (sigmoid) vs isotonic, fitted on validation only | `evaluation/calibration.py` | `evaluate calibration` |
| Which threshold is cheapest under assumed costs? | Expected cost per threshold, plus a risk-band analysis | `evaluation/costs.py` | `evaluate costs` |
| Which scenarios are missed or over-flagged? | Per-scenario metrics with small-sample notes; operational-cohort FPR checks | `evaluation/segments.py` | `evaluate scenarios` |
| What do the errors look like? | Pseudonymised false-positive and false-negative reports with feature context | `evaluation/segments.py` | `evaluate errors` |
| Do two models really differ? | Paired bootstrap PR-AUC difference and exact McNemar test; agreement groups; ensemble research | `evaluation/comparison.py` | `evaluate compare` |
| What did the training data look like? | Drift baseline: PSI and Jensen–Shannon distance | `evaluation/drift.py` | `evaluate drift-baseline` |
| Does one feature give the answer away? | Univariate folded ROC-AUC for every numeric and boolean feature | `evaluation/shortcuts.py` | benchmark script |

`fraud-ai evaluate report <model>` writes every per-model artefact in one pass.
`fraud-ai evaluate reproduce <model>` is the Stage 3 reproducibility check.

### Common options

`--bootstrap N` (default 1000), `--level` (0.95), `--seed` (0),
`--threshold` (default: the model's recorded threshold), `--output-dir` (default:
`EVALUATION_DIRECTORY`, which is `evaluation/`).

### The evaluation context

Every report is built from the **recorded** dataset of the model:

* The dataset is rebuilt from the training manifest.
* The rebuilt dataset fingerprint must equal the recorded one. If the data has changed
  since training (for example a new label), evaluation refuses to run instead of silently
  measuring something else.
* Multi-model reports require every model to share one dataset fingerprint, so
  comparisons are always on exactly the same examples.
* Model artefacts are loaded through the SHA-256-verified loader.

## 2. Bootstrap confidence intervals

* **Resampling.** Stratified: each resample keeps the number of fraud and legitimate
  examples fixed. With few fraud examples, an unstratified resample can contain no fraud
  at all.
* **Interval.** Percentile interval at the configured level. The same seed gives identical
  intervals (tested).
* **Metrics.** PR-AUC, ROC-AUC, precision, recall, F1, FPR and FNR, on validation and test.
* **Undefined values.** A metric that is undefined in a resample (for example, precision
  with nothing flagged) is skipped. `valid_resamples` records how many resamples
  contributed.
* **Limitation.** The bootstrap treats events as independent. Events from one account are
  correlated, so the true uncertainty is, if anything, larger.

## 3. Walk-forward evaluation

Expanding-window folds of `--period-days` (30 by default):

```
fold k:  train [origin, origin + (n+k)·P)   validate [+P)   test [+P)
```

For each fold:

* A **fresh** model of the same kind is trained, with the same hyperparameters, seed and
  imbalance strategy. Fold models are experiments: they are not registered and cannot be
  used for scoring.
* **Training labels are the labels known at the fold's training cutoff.**
  * An example is used only if it matured by the cutoff (event + maturity ≤ cutoff).
  * It counts as fraud only if a fraud label had been recorded by then.
  * So a chargeback that arrives later can never inform an earlier fold (tested).
* **Validation** labels are as known at the validation cutoff. The validation-selected
  threshold is chosen there.
* **Test** uses the eventual labels, which are the ground truth being measured.
* **Stored per fold:**
  * the train, validation and test start and end, row counts, fraud counts and prevalence;
  * the test metrics and a bootstrap PR-AUC interval;
  * the model's threshold and the validation-selected threshold;
  * the base model version and the fold model id.
* **Which folds run.** Up to `--max-folds` of the most recent folds with a complete
  validation period.
* **Skipped folds.** A fold whose training rows lack both classes is skipped, and the
  reason is recorded.
* **Stability.** The mean, standard deviation, minimum and maximum of each metric across
  folds.

## 4. Calibration

Class weighting pushes probabilities up, so raw scores are not calibrated likelihoods.

* **Methods:**
  * uncalibrated;
  * sigmoid (Platt): a logistic fit on logit(p);
  * isotonic: monotone, piecewise constant.
* **Fitted on the validation split only.** The test split is used only for reporting.
  Changing the test labels changes the reported test metrics but never a fitted
  calibrator (tested).
* **Reported:** Brier score, log loss, expected calibration error (ECE), PR-AUC/ROC-AUC
  after calibration, and reliability buckets.
  * The buckets are 0.0–0.1, …, 0.9–1.0.
  * Each bucket gives its count, mean predicted probability, observed fraud rate and fraud
    count.
* **Persistence.** Fitted calibrators are stored in `model_calibrations` (migration `0004`),
  keyed by model version, method and dataset fingerprint.
  * A `CHECK` constraint makes `fitted_on = 'test'` impossible.
  * Re-running is idempotent.
  * Different parameters for the same key raise `CalibrationConflictError`.
  * A calibrator is stored, but **not applied** to scoring. Adopting one is a later,
    explicit decision.
* **Isotonic on small data.** With a handful of validation positives, isotonic regression
  produces coarse steps and ties. It can then lower the ranking metrics even while Brier
  stays similar, so both are shown.

## 5. Cost-sensitive evaluation and risk bands

Costs are **experiment parameters, not facts**.

The defaults are fraud loss £500, manual review £5, step-up £1 and false-positive friction
£10. `--loss-mode amount` uses each transaction's amount as the loss instead.

For each threshold (flagged means p ≥ threshold):

```
total = missed fraud × loss  +  flagged × action cost  +  false positives × friction
```

* **Actions.** Both "manual review" and "step-up" are costed.
* **Reference points.** "Flag everything" and "flag nothing" are included for comparison.
* **The lowest-cost threshold** is reported as a finding of the experiment. It is **never
  applied** anywhere.

**Threshold bands** (0–0.3, 0.3–0.7, 0.7–1 by default; `--bands`) are conceptual regions
for a future risk engine, not rules. For each band the report gives:

* the share of the population;
* the fraud rate, and the band's share of all fraud;
* the number of legitimate events in the band (false-positive load);
* the manual-review load;
* a conceptual cost.

## 6. Scenario and cohort evaluation

**Scenarios** are defined explicitly in `evaluation/segments.py`:

| Segment | Population | Definition |
|---|---|---|
| normal_customer, legitimate_vpn_user, house_mover, shared_network_customer, new_legitimate_customer | mixed | accounts of that synthetic scenario |
| large_legitimate_purchase | legitimate only | a legitimate purchase ≥ 3× the customer's median, or above their previous maximum |
| account_takeover | fraud only | fraud labelled `account_takeover` |
| stealthy_account_takeover | fraud only | takeover with no password reset in the previous 24 h |
| new_account_card_fraud | fraud only | fraud labelled `stolen_payment_method` |
| friendly_fraud | fraud only | fraud labelled `friendly_fraud` |
| high_velocity_fraud | fraud only | fraud with ≥ 2 logins, ≥ 1 failed login or ≥ 1 other transaction in the previous hour |
| drop_address_fraud | fraud only | fraud shipped to an address added in the last 24 h |

Rules for reporting segments:

* **Rates need a denominator.** A rate is reported only where its denominator exists:
  fraud-only segments report recall and FNR; legitimate-only segments report FPR.
* **PR-AUC** needs at least 10 examples of each class.
* **Small samples.** Any segment with fewer than 10 examples in a class carries a note
  that its rates are indicative only.
* **Intervals.** Wilson intervals are given for recall and FPR.

**Operational cohorts** are compared with the global false-positive rate:

* the cohorts are mobile-network users, VPN users, shared-network users, new accounts
  (< 30 days), house movers and high-value buyers;
* a cohort is flagged only if **all** of these hold:
  * its FPR is at least 2× the global FPR;
  * it is at least 0.5 percentage points higher;
  * the lower bound of its Wilson interval is above the global FPR;
  * it has at least 30 legitimate events.

Cohorts are operational: network type, account age and purchase size. **No demographic
or protected characteristic is inferred**, and the platform does not hold any.

## 7. Error analysis

`evaluate errors` lists false positives, sorted by descending probability, and false
negatives, sorted by ascending probability.

* **References.** Each event is identified only by a one-way pseudonym:
  `ex-` followed by the first 16 hex characters of sha256("fraud-ai-evaluation:" + event id).
* **What is not included.** No event id, user id, IP address, postal address or payment
  data (tested).
* **Context.** Each error carries a fixed set of point-in-time context features.
* **False-positive traits.** Traits such as VPN, new device, new address, shared network,
  large purchase and house move are reported with their *lift*: how much more common the
  trait is among false positives than among all legitimate events.
* **False negatives** are grouped by fraud type and scenario.

## 8. Model comparison

* **Paired bootstrap.** For each pair of models, the difference in PR-AUC is computed on
  the same resampled rows. The report gives the interval, a bootstrap p-value and whether
  the interval excludes zero.
* **Exact McNemar test.** A test on the discordant decisions at each model's own
  threshold.
* **The conclusion is always cautious.** It reads either "the PR-AUC difference interval
  excludes zero on this split" or "no reliable difference". A winner is never declared.
* **Agreement groups** at each model's threshold, each with its fraud rate:
  * all models low;
  * all models high;
  * only model X high;
  * mixed.
* **Ensemble research.** Three combinations, **evaluated only** (never persisted or
  activated):
  * the average probability;
  * the probability weighted by validation PR-AUC;
  * the fraction of models voting fraud (majority vote).

  The reference single model and the weights are chosen on *validation*. An ensemble
  "appears useful" only if its paired PR-AUC difference interval lies above zero.

## 9. Drift baseline

* **Reference.** The reference distributions come from the model's training split.
* **Features:** transaction amount, address age, device age, logins in the last hour,
  network type, VPN, new device and new address.
* **Numeric features** use decile bins with recorded edges, plus one bucket per missing
  reason. A rise in "unknown" network intelligence therefore shows up as drift.
* **Categorical and boolean features** use token frequencies, plus `__other__`.
* **Measures:**
  * PSI: < 0.10 stable, 0.10–0.25 moderate, > 0.25 significant;
  * Jensen–Shannon distance (base 2, 0–1).
* **Demonstration.** The report compares the later test period with the baseline.

**Limitations:**

* univariate only: joint shifts are invisible;
* the bins come from one training window;
* the thresholds are conventions;
* drift is a prompt to re-evaluate, not proof of degraded performance;
* there is no live drift service yet (Stage 8).

## 10. Report artefacts

```
evaluation/<model-id>/summary.json
                     /confidence.json      bootstrap intervals (validation, test)
                     /thresholds.json      threshold analysis + risk bands
                     /calibration.json     three methods, reliability buckets
                     /scenarios.json       segments + operational cohorts
                     /errors.json          pseudonymised FP / FN
                     /costs.json           manual-review and step-up cost curves
                     /walk_forward.json    folds + stability
                     /drift_baseline.json  reference distributions + test-period comparison
evaluation/comparisons/<dataset>/compare.json
```

* **Header.** Every file starts with:
  * the report name and the evaluation version (`evaluation-1.0.0`);
  * the model(s), the dataset fingerprint and the feature version;
  * the split sizes and the full settings, including the seed and costs;
  * a synthetic-data note.
* **Reproducible.** Apart from `generated_at`, the same database, model and settings
  produce identical files (tested).

## 11. Synthetic generator changes in Stage 4 (removing giveaways)

Stage 3 noted that the generator made fraud too distinctive: gradient-boosting
permutation importance was dominated by `address_age_days`, and a single feature could
separate most fraud. Stage 4 adds legitimate behaviour that overlaps fraud signals, and
makes fraud less uniform:

* **Legitimate customers now sometimes:**
  * log in from a one-off device (4% of logins);
  * reset a forgotten password just before buying (2%);
  * log in from an unfamiliar network such as a friend's Wi-Fi or a hotel (8%);
  * make unusually large purchases at 3–9× their normal spend (8% of purchases);
  * buy digital goods with no shipping address (15%);
  * send gifts to a newly added address (3%).
* **Account takeovers now vary:**
  * 20% hijack the victim's own device and home network;
  * 30% are quiet credential reuse from a domestic residential IP;
  * 50% are loud (failed logins, password reset, account changes).
* **Takeover destinations and amounts:**
  * 30% buy digital goods, 20% ship to the victim's own address and 50% use a new drop
    address;
  * stealthy amounts are 1–3× normal spend, loud ones 2–6×.
* **New-account card fraud amounts** now overlap legitimate first purchases.
* **Offices always have at least two staff** on the same network.
* **Configurable prevalence.** `--fraud-multiplier` (0.1–3) scales the fraud scenarios for
  prevalence experiments.
* **Guard test.** `test_no_single_feature_separates_synthetic_fraud` fails if any single
  feature reaches a univariate ROC-AUC of 0.92 or more on the test world's training split.

## 12. Benchmark results (synthetic)

Produced by `python scripts/evaluation_benchmark.py --users 1000` (seed 2026, 180 days, fraud
multiplier 1.0, 14-day maturity, SQLite, 1,000 bootstrap iterations, seed 0).

**The world.**

* 1,000 users and 189,078 events.
* 34,388 labelled transactions, of which 354 are fraud (1.03%).
* The time-ordered split:

| Split | Rows | Fraud |
|---|---|---|
| train | 24,072 | 256 |
| validation | 5,158 | 46 |
| test | 5,158 | 52 |

* Dataset fingerprint: `5454166f04129b7a…`.

**Shortcut check.** The strongest single feature on the training split is
`device_successful_login_count`, with a univariate ROC-AUC of 0.80. The next are
`rapid_multi_change_count` (0.78) and `new_device` (0.78). No single feature separates
fraud.

> On this synthetic evaluation window the test split has only **52 fraud events**. Every
> interval below is correspondingly wide. None of these figures is a real-world detection
> rate.

### Confidence intervals (test, threshold 0.5, 95% stratified bootstrap)

| Model | PR-AUC | ROC-AUC | Precision | Recall | FPR |
|---|---|---|---|---|---|
| logistic regression | 0.784 [0.689, 0.868] | 0.991 [0.985, 0.996] | 0.207 [0.183, 0.235] | 0.923 [0.846, 0.981] | 0.036 [0.031, 0.041] |
| random forest | 0.884 [0.809, 0.945] | 0.997 [0.995, 0.999] | 0.872 [0.771, 0.971] | 0.654 [0.519, 0.788] | 0.001 [0.000, 0.002] |
| gradient boosting | 0.956 [0.917, 0.985] | 0.999 [0.998, 1.000] | 0.957 [0.894, 1.000] | 0.846 [0.750, 0.942] | 0.000 [0.000, 0.001] |

The models sit at very different operating points at 0.5. Logistic regression has high
recall but flags about 3.6% of legitimate transactions. The tree models flag almost none.
The thresholds are not comparable across models.

### Walk-forward (30-day periods, expanding window)

Folds 1–4 were skipped. The early history is sparse account backfill, so their training
windows contain no fraud known by the cutoff.

| Fold (test month from) | Train rows / fraud | Test fraud | LR PR-AUC | RF PR-AUC | GB PR-AUC |
|---|---|---|---|---|---|
| 5 (2026-04-29) | 4,473 / 15 | 71 | 0.498 | 0.512 | 0.516 |
| 6 (2026-05-29) | 9,990 / 83 | 76 | 0.691 | 0.738 | 0.830 |
| 7 (2026-06-28) | 15,659 / 164 | 58 | 0.735 | 0.817 | 0.896 |
| 8 (2026-07-28) | 21,437 / 218 | 40 | 0.754 | 0.856 | 0.924 |

* PR-AUC rises steeply as more labelled fraud becomes available: with 15 training frauds,
  all three models are near 0.5.
* The fold-to-fold standard deviation is 0.12–0.19.
* The single-split figures are therefore one draw from a wide range.

### Calibration (fitted on validation, reported on test)

| Model | Method | Brier | Log loss | ECE | PR-AUC |
|---|---|---|---|---|---|
| LR | uncalibrated | 0.02857 | 0.1084 | 0.0570 | 0.784 |
| LR | sigmoid | **0.00387** | 0.0168 | 0.0010 | 0.784 |
| LR | isotonic | 0.00411 | 0.0262 | 0.0012 | 0.683 |
| RF | uncalibrated | 0.00293 | 0.0141 | 0.0058 | 0.884 |
| RF | sigmoid | 0.00275 | 0.0118 | 0.0024 | 0.884 |
| RF | isotonic | 0.00275 | 0.0118 | 0.0016 | 0.843 |
| GB | uncalibrated | 0.00168 | 0.0062 | 0.0011 | 0.956 |
| GB | sigmoid | 0.00163 | 0.0067 | 0.0016 | 0.956 |
| GB | isotonic | 0.00166 | 0.0073 | 0.0004 | 0.934 |

**Logistic regression is badly over-confident.** Its reliability buckets show this:

* the 0.3–0.9 buckets hold 280 events with a fraud rate of 0–10%;
* the 0.9–1.0 bucket holds 88 events with a fraud rate of 45.5%.

This is the effect of class weighting. Sigmoid calibration reduces its Brier score about
seven-fold without changing its ranking.

For the tree models, the differences between methods are small. Isotonic lowers PR-AUC for
every model, because its coarse steps create ties.

### Scenarios (test, threshold 0.5)

| Segment | n (fraud) | LR recall / FPR | RF recall / FPR | GB recall / FPR |
|---|---|---|---|---|
| account_takeover | 30 | 0.97 | 0.63 | 0.97 |
| stealthy_account_takeover | 16 | 0.94 | 0.44 | 0.94 |
| new_account_card_fraud | 15 | 1.00 | 1.00 | 1.00 |
| friendly_fraud | 7 (*small*) | 0.57 | 0.00 | 0.00 |
| high_velocity_fraud | 23 | 1.00 | 0.78 | 1.00 |
| drop_address_fraud | 35 | 1.00 | 0.80 | 1.00 |
| new_legitimate_customer (legitimate) | 420 | FPR 0.093 | 0.012 | 0.002 |
| house_mover (legitimate) | 419 | FPR 0.053 | 0.000 | 0.000 |
| large_legitimate_purchase | 407 | FPR 0.084 | 0.000 | 0.000 |
| legitimate_vpn_user | 327 | FPR 0.000 | 0.000 | 0.000 |

* **Friendly fraud** (disputed genuine purchases) is essentially undetectable by design.
  Its 7 examples carry a small-sample note.
* **Stealthy takeovers** are where random forest loses most recall.
* **Legitimate new customers, house movers and large purchasers** carry most of logistic
  regression's false positives.
* **VPN users** are not over-flagged by any model.

### Operational cohorts (legitimate events; flagged if FPR ≥ 2× global with a Wilson bound above global)

| Model | Global FPR | Flagged cohorts |
|---|---|---|
| LR | 3.6% | new accounts (16.2%, n=99), house movers (9.4%, n=598), high-value buyers (8.4%, n=407) |
| RF | 0.10% | new accounts (5.1%, n=99; 5 FPs) |
| GB | 0.04% | new accounts (1.0%, n=99; 1 FP) |

Mobile-network, VPN and shared-network users were not flagged for any model.

### Errors (test, threshold 0.5)

**False positives:**

* **LR (184).** The most common traits among its false positives are:
  * new address (lift 7.4×);
  * new device (7.1×);
  * house move (5.3×);
  * new account (4.5×);
  * large purchase (2.3×).
* **RF (5)** and **GB (2)**: almost all are new customers.

**False negatives:**

* **GB (8):** 7 friendly fraud and 1 account takeover.
* **RF (18):** 11 account takeovers, mostly stealthy, and 7 friendly fraud.
* **LR (4):** 3 friendly fraud and 1 takeover.

### Costs (defaults: fraud £500, review £5, step-up £1, friction £10; manual review)

| Model | Flag nothing | Flag everything | At 0.5 | Lowest-cost threshold (not applied) |
|---|---|---|---|---|
| LR | £26,000 | £76,850 | £5,000 | 0.55 → £4,655 |
| RF | £26,000 | £76,850 | £9,245 | 0.05 → £2,855 |
| GB | £26,000 | £76,850 | £4,250 | 0.05 → £1,595 |

With a fixed £500 loss and cheap reviews, the cost curves favour very low thresholds for
the tree models. That is a property of the assumed costs, not a recommendation.

### Risk bands (0–0.3 / 0.3–0.7 / 0.7–1)

| Model | Low band: population / share of fraud | Review band: population / legitimate events | High band: population / share of fraud |
|---|---|---|---|
| LR | 92.9% / 1.9% | 4.3% / 214 | 2.8% / 80.8% |
| RF | 99.1% / 19.2% | 0.27% / 5 | 0.66% / 63.5% |
| GB | 99.0% / 13.5% | 0.12% / 4 | 0.85% / 82.7% |

### Model comparison (paired, test)

| Pair | PR-AUC difference (95% CI) | McNemar (A right / B right) | p |
|---|---|---|---|
| LR − RF | −0.100 [−0.164, −0.046] | 14 / 179 | < 1e-30 |
| LR − GB | −0.173 [−0.251, −0.102] | 4 / 182 | < 1e-40 |
| RF − GB | −0.073 [−0.124, −0.027] | 2 / 15 | 0.002 |

**On this synthetic test split, each paired PR-AUC difference interval excludes zero.**
This is not a declaration that any model is best:

* the walk-forward folds show the ordering is much less clear with less training data (in
  fold 5 all three models are within 0.02 of each other);
* the result comes from one synthetic generator;
* McNemar compares decisions at 0.5, which are very different operating points for these
  models.

**Agreement groups** (each model at its own threshold):

| Group | Events | Fraud rate | Share of all fraud |
|---|---|---|---|
| all low | 4,926 | 0.08% | 7.7% |
| only LR high | 181 | 2.2% | 7.7% |
| mixed | 17 | 58.8% | 19.2% |
| all high | 34 | 100% | 65.4% |

**Ensembles** (research only; the reference model, gradient boosting, was chosen on
validation):

| Ensemble | PR-AUC | Difference vs reference |
|---|---|---|
| average probability | 0.888 | −0.069 [−0.120, −0.024] |
| weighted probability | 0.891 | −0.065 [−0.115, −0.022] |
| majority vote | 0.836 | −0.120 [−0.190, −0.056] |

No ensemble appears useful on this window.

### Drift baseline (test period vs training reference)

| Feature | PSI | Status |
|---|---|---|
| device_age_days | 0.103 | moderate |
| vpn_detected | 0.082 | stable |
| network_type | 0.077 | stable |
| address_age_days | 0.051 | stable |
| other tracked features | < 0.01 | stable |

The moderate `device_age_days` shift is expected: accounts age during the window.

### Timings (this machine, SQLite)

| Step | Time |
|---|---|
| Seed | 653 s |
| Training (3 models) | 381 s |
| Build evaluation context | 254 s |
| Per-model report, 1,000 bootstrap iterations | 35–55 s |
| Paired comparison | 106 s |

### Stage 5 additions

The same framework now also evaluates the neural network and the autoencoder:
* `fraud-ai evaluate …` accepts `neural-network-<version>`;
* walk-forward retrains a fresh network per fold, with early stopping on that fold's
  validation period;
* `fraud-ai evaluate complementarity A B [--anomaly V]` adds disagreement groups, A's
  misses caught by B, and experimental combinations;
* `fraud-ai anomaly evaluate` reports on anomaly scores. Those are *not* fraud
  probabilities, and the fraud reports refuse them.

The results on this world are in [NEURAL_MODELS.md](NEURAL_MODELS.md) §9.

### Stage 6 additions

* **Sequence models run through the same framework.** The evaluation context rebuilds
  their point-in-time sequences and verifies the recorded sequence digest.
* **`complementarity` reports `fraud_detection_overlap`:** fraud caught by both models,
  caught by only one of them, and missed by both, with fraud types and scenarios.
* **`fraud-ai sequence stealth-report`** covers the stealthy and temporal takeover cases:
  every model's probability and the prior behaviour from the sequence, as pseudonymised
  summaries.

## 13. What this does not show

* **Real-world performance.** Nothing here measures real fraud, real customers or real
  losses.
* **Rare scenarios.** Fraud segments have tens of examples, and their intervals are wide.
* **Independence.** Events from the same account are correlated. The bootstrap intervals
  are therefore optimistic rather than conservative.
* **Costs.** The costs are assumptions. Change them and the cheapest threshold moves.
* **Calibration and ensembles are not adopted.** Calibrators are stored but not applied,
  and ensembles are research only.
