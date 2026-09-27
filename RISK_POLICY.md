# Risk policy and rules (Stage 8)

> **Synthetic-derived, experimental.** The policy bands proposed here come from Stage 4 cost
> and threshold analysis on the bundled synthetic data. They are **defaults for
> experiments**, not validated operating points, and they imply nothing about real fraud,
> losses or savings. Nothing is activated automatically.

## 1. What decides

```
model scores (evidence)   +   rules (evidence)   +   risk policy (versioned)   =   decision
```

* **Models** provide probabilities. The primary classifier's probability is *calibrated*
  (sigmoid, fitted on the validation split) and becomes the risk score. A secondary or
  sequence model and an anomaly signal are *corroborating* evidence.
* **Rules** are explicit, versioned security conditions over point-in-time features. A
  matched rule reports a severity, a reason code and the evidence it used.
* **The policy** is a pure, deterministic function (`fraud_ai/risk/engine.py:decide`). It
  maps the evidence to one of five internal decisions. The live service and the offline
  simulator call the same function.

| Decision | Meaning (an internal policy output; nothing is executed) |
|---|---|
| `ALLOW` | proceed |
| `ALLOW_WITH_MONITORING` | proceed; watch the account for `monitoring_hours` (72) |
| `STEP_UP_AUTHENTICATION` | request a stronger authentication (`standard` or `strong`); placeholder only |
| `MANUAL_REVIEW` | queue for an analyst |
| `TEMPORARY_BLOCK` | hold for `temporary_block_hours` (24) *and* review; never permanent |

There is no permanent ban. The Stage 1 `BLOCK` value was removed by migration 0006.

## 2. Policy definition (`risk-policy-schema-1.0.0`)

A policy (`fraud_ai/risk/policy.py:RiskPolicyDefinition`) is complete and immutable:

| Part | Content |
|---|---|
| version | `risk-policy-X.Y.Z` |
| model set | `primary` (required, with its calibration embedded), optional `secondary`, `sequence` and `anomaly`; each with its artefact SHA-256 and threshold |
| bands | increasing lower bounds on the calibrated primary score; each has a risk level (`very_low`, `moderate`, `elevated`, `high`, `extreme`) and a decision, which never becomes less restrictive as risk rises |
| rules | `rules_version`, plus the rule-set fingerprint at creation |
| rule severity → minimum decision | low → monitoring; medium → step-up; high → review; critical → review |
| escalations | a flagging secondary/sequence model → at least monitoring; an anomaly signal → at least monitoring; a late event (> 900 s) → at least monitoring |
| corroboration | `TEMPORARY_BLOCK` needs a matched rule of at least medium severity, or a flagging secondary/sequence model; otherwise it becomes `MANUAL_REVIEW` |
| fallbacks | one decision per failure category. Validation **refuses** any fallback below `STEP_UP_AUTHENTICATION` |
| decision event kinds | the event kinds the policy decides on (from the primary model's training kinds) |
| flags | `synthetic_derived`, action windows |

**Versioning and immutability:**

* The definition is hashed (SHA-256 of the canonical JSON) and stored in `risk_policies`.
* Every load re-hashes the stored definition. A policy edited in place is refused and
  never used; the live path then falls back to manual review.
* A deployment row is hashed the same way.
* A new policy is always a new version, and creating an existing version is refused.
* Activation (`fraud-ai deployment activate`) is explicit and asks for confirmation. It
  first validates that:
  * every model is registered, with the pinned digest, and its artefact loads and
    verifies;
  * every calibration exists for that model with identical parameters;
  * the rule-set fingerprint still matches;
  * shadow models are registered classifiers outside the active set;
  * shadow policies are valid.
* `policy_deployments` is append-only. The latest row is the active one, and history is
  never rewritten.

Each assessment records the policy version, the deployment id, the rule-set version, the
primary model and every model score, so any decision can be traced to the exact
configuration that made it.

## 3. How the initial bands are proposed

`fraud-ai policy propose` (`fraud_ai/risk/offline.py:propose_policy`) works on the primary
model's recorded dataset. It uses the **validation split only**: the test split is
reserved for simulation.

1. Fit and persist the sigmoid calibrator on validation (Stage 4).
2. Run Stage 4 `cost_curve` on the calibrated validation scores, over a grid of 0.01 to
   0.99:
   * **manual review** starts at the lowest-cost threshold with the review cost;
   * **step-up** starts at the lowest-cost threshold with the (cheaper) step-up cost,
     capped at the review bound.
3. **Monitoring** starts at the highest threshold at or below step-up that still keeps
   `--monitor-recall` (95%) of validation fraud at or above it.
4. **Temporary block** starts at the lowest threshold strictly above review with
   validation precision ≥ `--block-precision` (0.95) and at least 5 flagged events. If
   none qualifies, there is no block band.
5. **Coinciding bounds** keep the *stricter* band.
6. **Guard.** At least 10 fraud and 10 legitimate validation events are required. Fewer
   is refused: bands derived from such small counts would be meaningless.

The derivation (thresholds, targets, per-band validation counts, cost assumptions and
drift baselines) is stored with the policy and shown by `policy show --json`.

The costs are **synthetic experiment parameters** (`--fraud-loss`, `--review-cost`,
`--step-up-cost`, `--friction`). With the defaults (loss 500, review 5, step-up 1,
friction 10) fraud is much more expensive than friction, so the cost-optimal thresholds
are low. That is a property of the assumptions, not a recommendation.

## 4. Rules (`fraud-rules-1.0.0`)

`fraud_ai/rules/ruleset.py`. Each rule has an id, a version, a severity, a reason code,
its parameters and its evidence features. It is deterministic and tested. The rule set's
fingerprint covers every rule spec; a change needs a new rule version and a new rule-set
version.

| id | reason code | condition | severity |
|---|---|---|---|
| R001 | `ATO_RESET_NEW_DEVICE_HIGH_VALUE` | password reset (24 h) **and** new device **and** (unusually high amount **or** ≥ 3× median) - transactions | high |
| R002 | `FAILED_LOGIN_BURST` | ≥ 5 failed account logins in 15 min **or** ≥ 10 failed logins from the network in 1 h | medium |
| R003 | `RAPID_ACCOUNT_CHANGES` | ≥ 3 kinds of account change in 24 h | medium |
| R004 | `MFA_REMOVED_NEW_DEVICE` | MFA removed (24 h) **and** new device | high |
| R005 | `ANONYMISED_NETWORK_NEW_DEVICE` | (Tor **or** datacenter) **and** new device. **VPN alone never matches** | low |
| R006 | `NEW_PAYMENT_NEW_ADDRESS_HIGH_VALUE` | new payment method **and** new address **and** unusually high amount - transactions | medium |

* **Missing evidence never matches.** The rule reports the missing features instead.
* **Rules never act.** They only raise the decision to the policy's minimum for their
  severity, and never lower it.
* **No credential rule.** The synthetic data has no compromised-credential signal, so no
  rule claims to detect one.

## 5. Simulation and comparison

```
fraud-ai policy simulate <version> [--split test] [--step-up-stop-rate 0.5] ...
fraud-ai policy compare <a> <b> [--iterations 1000]
```

* **Simulation** replays the policy through `decide()` over the labelled **test split**
  of the models' recorded dataset. That split was not used to choose any band. The
  simulation reports:
  * the decision distribution;
  * fraud caught (review or block), challenged (step-up) and missed;
  * step-up, review, block and monitoring volumes;
  * false-positive volume and rate;
  * reason-code counts;
  * the estimated cost.

  **No stored decision changes**, and nothing is written except the report file.
* **Cost model.** It uses explicit assumptions:
  * `step_up_fraud_stop_rate` (default 0.5) is the share of fraud a step-up would stop.
    The synthetic data *cannot* measure this.
  * Monitoring does not stop fraud.
  * A review or block stops fraud, and a legitimate customer blocked pays
    `temporary_block_friction`.
* **Comparison** runs A and B on **exactly the same events**. It refuses policies whose
  models were trained on different datasets, or that decide on different event kinds. It
  reports:
  * the decision crosstab;
  * fraud caught only by A or only by B;
  * false positives unique to each;
  * the cost difference with a stratified bootstrap 95% interval.
* **No automatic activation.** A cheaper policy in one synthetic run is a finding to
  investigate, never a reason to activate it.

## 6. Results (SYNTHETIC-DERIVED)

> Every threshold, cost and number in this section is **synthetic-derived**: synthetic
> data, assumed costs (loss 500, review 5, step-up 1, friction 10, block friction 30,
> step-up stop rate 0.5) and one seed. None of it is a validated operating point or a
> real-world result.

From `python scripts/realtime_benchmark.py --users 300`:

**Setup.**

* The world: 300 users over 180 days with a fraud multiplier of 2. The last 7 days were
  held out as the live stream.
* Models: gradient boosting as primary, the feed-forward network as secondary, the GRU as
  sequence model, and logistic regression as the shadow model. All use the default
  training configuration.
* Validation split: 1,241 events, 30 of them fraud. Test split: 1,240 events, 48 fraud.

**Proposed bands** (calibrated primary score; default costs):

| Policy | Band proposal |
|---|---|
| `risk-policy-1.0.0` (GB + NN + GRU, monitor recall 95%, block precision 95%) | ALLOW < 0.01 ≤ MONITORING < 0.02 ≤ MANUAL_REVIEW < 0.69 ≤ TEMPORARY_BLOCK |
| `risk-policy-1.1.0` (GB only, monitor recall 80%, block precision 90%) | ALLOW < 0.02 ≤ MANUAL_REVIEW < 0.68 ≤ TEMPORARY_BLOCK |

For both policies the step-up and review thresholds coincided at 0.02, so the review band
was kept (the stricter one). **There is no step-up band.** With fraud costing 50–100
times a review under the assumed costs, the cost-optimal thresholds are very low. That
is a consequence of the assumptions, which is exactly why these are experiments.

**Simulation (test split, never used for the bands):**

| | risk-policy-1.0.0 | risk-policy-1.1.0 |
|---|---|---|
| ALLOW / MONITOR | 1,085 / 51 | 1,132 / 4 |
| STEP_UP / REVIEW / TEMP_BLOCK | 1 / 70 / 33 | 1 / 91 / 12 |
| fraud caught (review or block) / missed | 46 / 2 | 46 / 2 |
| false positives (≥ step-up, legitimate) | 58 | 58 |
| estimated cost (assumed costs) | 2,101.1 | 2,096.4 |

**Comparison (identical 1,240 events):**

* Decisions differ on 68 events. Almost all of them are a temporary block under A that
  is a manual review under B, and monitoring under A that is an allow under B.
* No fraud is caught by only one policy, and neither has false positives the other
  lacks.
* The cost difference A − B is +4.7, with a 95% interval of [+3.3, +6.0]. B is slightly
  cheaper under these assumptions, entirely through lower monitoring cost. Blocking more
  (A) changes nothing measurable here.

**Findings (synthetic):**

1. On this world, gradient boosting's calibrated score separates well enough that both
   policies catch 46 of 48 test fraud events with the same 58 false positives.
2. The policies differ in *how* they intervene (block versus review, monitor versus
   allow), not in *what* they catch.
3. A difference of 4.7 cost units on about 1,240 events is not a reason to switch.
   Activation stays an explicit decision.


## 7. Limitations

* **Bands come from synthetic validation data.** One seed and one world were used, with
  a few dozen fraud examples; intervals are wide.
* **The cost model has unmeasured assumptions.** Change them and the thresholds move.
* **Calibration is fitted once.** It is fitted on one validation window and does not
  adapt to drift. Drift monitoring warns, and a new policy version is the remedy.
* **Only corroborating signals escalate.** Secondary/sequence models and the anomaly
  signal can raise a decision to monitoring or corroborate a block. They never create a
  review or a block on their own.
* **Rules are few and hand-written.** Their thresholds are conventions, not tuned values.
