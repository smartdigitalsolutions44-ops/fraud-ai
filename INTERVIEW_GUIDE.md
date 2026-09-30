# Interview guide

Questions about fraud-ai you should be able to answer, with short answer guidance. Each
answer is short enough to say in under a minute. The linked documents give the detail.
Keep two rules:

* say "on synthetic data" whenever you quote a number;
* say what did **not** work.

## Why did gradient boosting beat the neural network?

* **The result, stated carefully.** On the synthetic test split, GB's PR-AUC was 0.956 and
  the network's 0.903. The paired difference was +0.054, with an interval of [−0.004,
  +0.115]. That interval only just includes zero, so say "stronger here", not "better in
  general". At the 0.5 threshold, McNemar was 11 / 1 in GB's favour (NEURAL_MODELS.md §9).
* **Why it is plausible:**
  * The data is **tabular**, with engineered features: counts, ratios and flags on very
    different scales. Trees handle that and their interactions without scaling or much
    tuning.
  * There were **few positives**: about 256 training frauds. Networks need more data to
    learn what trees find with splits.
  * GB is robust to irrelevant features and monotone transforms.
* **What would change it:** far more labelled data, raw sequences or high-cardinality
  inputs where learned representations help. Even the sequence models were worse overall
  here; the GRU caught one stealthy takeover that GB missed.

## Why use point-in-time features?

* A model learns from the features it was trained on. If training features use information
  from **after** the event, such as a later chargeback or a device seen later, the model
  looks brilliant offline and fails live. That is **leakage**.
* Every feature is computed "as of" the event's time, from data that had *arrived* by then
  (arrival time, not just event time). The snapshot is stored with the assessment, so the
  exact inputs of any decision can be replayed.
* Tests deliberately insert future data and check that it does not change the features.

## Why isn't a VPN proof of fraud?

* Many genuine people use VPNs: privacy-minded customers, corporate networks, travellers.
  The synthetic world has a `legitimate_vpn` scenario for exactly this reason. In the demo,
  that customer is allowed.
* A VPN is **a signal that raises uncertainty**, not evidence of intent. Treating it as
  proof would create **false positives** concentrated on one group of customers. The
  cohort analysis checks for this (a flag rate at least 2× the global rate, with a Wilson
  bound).
* The right response to uncertainty is proportionate: monitoring or a step-up, not a
  block.

## Why keep the LLM outside scoring?

* **Determinism and auditability.** A decision must be reproducible from stored inputs,
  versioned models and a versioned policy. An LLM's output is neither stable nor
  calibrated.
* **Attack surface.** Event fields are merchant- and attacker-controlled text. An LLM
  reading them in the decision path could be prompt-injected into allowing fraud.
* **Latency and availability.** Scoring must not depend on a slow, optional component.
  Scoring works with no LLM at all; the investigation endpoint returns 503, and "decisions
  are unaffected".
* **What it does instead:** it explains stored outputs to an analyst. Every claim must
  cite evidence, output is validated (schema, citations, privacy, no decision language),
  and it has no tools.

## Why signed models?

* A model file *is* the decision logic. Whoever can replace it can make any event pass,
  without touching the code or the database.
* Each artefact is signed (Ed25519) with a **model-signing key** used for nothing else.
  Staging and production refuse to start with an unsigned or modified model.
* The file is read **once** into memory, and the signature is checked over those bytes. It
  cannot be swapped between the check and the load.
* **Limit:** it protects against tampering, not against a bad model signed by someone who
  holds the key. That is what key custody and two-person policy activation are for.

## Why two-person approval?

* Activating a policy changes how **every** event is decided. One compromised or mistaken
  operator should not be able to do that alone. This is separation of duties.
* Two different **authenticated** people must approve the exact definition (bound to its
  SHA-256). A third role activates it. Approvals expire, and each is re-verified at
  activation from its stored signed assertion. Rows inserted directly into the database
  do not count.
* Stage 12 made "person" mean a **person with a key**, not a name in configuration.

## Why Redis?

* With several worker processes or instances, per-process memory cannot enforce **global**
  rate limits, replay protection (each signature used once) or idempotency.
* Redis gives atomic operations (Lua and `SET NX`) and expiry, at sub-millisecond latency.
* It holds **only short-lived state**. Durable history stays in PostgreSQL, so losing
  Redis resets counters but loses no decision. If Redis is unavailable, the service
  **fails closed**: 503, never unprotected.

## Why WebAuthn?

* It is **phishing-resistant**. The credential is bound to the site's origin and RP ID, so
  a fake site cannot reuse it. SMS and e-mail codes can be phished or intercepted.
* The platform stores only public keys and counters. There is no shared secret to steal.
* It uses a maintained library (py_webauthn); no custom cryptography.
* **Limit:** passing step-up is **evidence, not proof**. An attacker holding the victim's
  device, or a friendly fraudster (the real cardholder), passes. A success therefore leads
  to ALLOW_WITH_MONITORING, not a clean slate.

## What are false positives?

* A **genuine** customer treated as fraud: blocked, challenged or sent to review. In the
  demo, the manual-review case is one: a normal customer.
* They cost money (review time, lost sales) and trust. They also fall unevenly on groups
  such as VPN users, house movers and travellers, which the cohort analysis looks for.
* Trade-off: lowering the threshold catches more fraud and creates more false positives.
  The policy bands come from a cost curve, with stated assumptions (fraud £500, review £5,
  step-up £1, friction £10). Change the costs and the best threshold moves.

## Why PR-AUC?

* With about 1 % fraud, **accuracy** is useless: "always allow" scores 99 %. **ROC-AUC**
  looks excellent (0.99+) because the huge number of true negatives dilutes false
  positives.
* **PR-AUC** focuses on the positive class: of what we flag, how much is fraud (precision),
  and how much fraud do we catch (recall). That is the operational question.
* Report it with **bootstrap confidence intervals**. With 52 test frauds, a point estimate
  alone would overstate certainty. Pair it with **calibration** and with **costs at a
  threshold**, because PR-AUC summarises every threshold and a decision uses one.

## What would you change with real data?

* **Labels:**
  * chargebacks arrive weeks later, so allow for label maturity;
  * labels are biased by past decisions: blocked fraud never gets a chargeback;
  * friendly fraud is labelled inconsistently.
* **Re-validate everything:**
  * re-derive the features and check them for leakage;
  * re-run the shortcut check;
  * re-derive the bands from real costs;
  * re-check calibration and cohort false-positive rates.

  The synthetic scenarios were written by the author, so the models learned the
  generator.
* **Monitoring first:** run new models and policies in **shadow** against real traffic
  before they decide. The mechanism already exists.
* **Operations and compliance:**
  * a legal basis, a DPIA and retention decisions;
  * erasure execution (designed, not built);
  * a real Stripe/3-D Secure integration;
  * hardware-backed operator keys;
  * multi-host load testing;
  * an analyst UI built on ANALYST_WORKFLOW.md.

## Harder follow-ups to expect

* **"How do you know the audit log wasn't changed?"**
  * The log is hash-chained, but a DBA could rewrite and re-chain it.
  * Signed anchors of the chain head are stored in **write-once (Object Lock) storage**,
    and verification compares the two.
  * The Stage 12 drill restored a backup to a clone, rewrote an event, and re-chained it.
    The chain still verified; **the anchors caught it**.
  * Limit: the staging object store is on the same host.
* **"What happens if the model service is down?"** Explicit fallbacks:
  * a failed secondary model means at least a step-up;
  * a database failure means 503 "not decided", with a MANUAL_REVIEW fallback hint;
  * nothing fails open.
* **"Is this production-ready?"** No. It is a portfolio release candidate on synthetic
  data. PORTFOLIO.md §7 lists the gaps.
