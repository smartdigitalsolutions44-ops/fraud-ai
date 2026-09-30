# Demo walkthrough (Stage 12)

A 5-10 minute walkthrough of the system on a **deterministic, synthetic** world. Every
decision shown is the running service's live answer, not a slide. Every expected decision
was measured, not chosen. A missed fraud is shown as missed.

**Everything here is SYNTHETIC.** No real customer, card or payment data exists anywhere in
the demo. The demo keys and secrets are demo-only and are generated on first reset.

## 1. Commands

```bash
pip install -e ".[dev]"                   # once
export DEMO_MODE=true
fraud-ai demo reset                       # build the world (about 4 minutes, 4 vCPU)
fraud-ai demo start                       # interview mode: serves on 127.0.0.1:8080
fraud-ai demo run                         # in a second terminal: the 9 steps below
```

* `demo start` builds the world first if there is none (`--reset` rebuilds it).
* The world lives in `data/demo/` (`--root` or `DEMO_ROOT` to move it):

  | File | Contents |
  |---|---|
  | `fraud_ai_demo.db` | the database |
  | `models/` | signed models |
  | `keys/` (0700) | demo keys |
  | `operators.json` | the demo operator registry |
  | `demo.env` and `demo-credentials.json` (0600) | demo configuration and API key |
  | `catalogue.json` | the ten cases with their measured decisions |

### The reset guard

`demo reset` deletes and recreates a database, so it refuses unless **all** of these hold
(`fraud_ai/demo/guard.py`, tests in `tests/test_demo.py`):

1. `DEMO_MODE=true` is set explicitly;
2. the profile is `development` or `test`; staging and production are refused;
3. the database is `<root>/fraud_ai_demo.db`. A `DATABASE_URL` pointing anywhere else is
   refused; so is any SQLite file not named `*_demo.db`, and any PostgreSQL database not
   ending in `_demo`;
4. the database does not exist or has no tables, or its **first** audit event is
   `demo.world_created`, which only a demo reset writes. A database with any other history
   is refused whatever its name, and so is a migrated one without audit history.

## 2. What is the same as staging, and what is not

`demo start` prints the differences before serving.

**The same security logic as staging:**

* signed **v2** requests only (`SIGNATURE_MIN_VERSION=v2`);
* **signed models required**: an unsigned or tampered model refuses start-up;
* **operator authentication required** for reviewers and admin actions. Signed,
  single-use Ed25519 assertions; roles come from `operators.json`, never from the request;
* two-person policy approval;
* the hash-chained audit log with signed external anchors;
* signed releases;
* scoped API keys, replay protection, rate limits, fail-closed configuration checks.

**Different (demo convenience, stated plainly):**

| Demo | Staging |
|---|---|
| SQLite, one process | PostgreSQL with least-privilege roles |
| in-memory shared state | Redis |
| local key files | Vault transit (KMS) |
| a file anchor directory | S3 Object Lock (COMPLIANCE) |
| the development **fake** payment provider | – (neither is 3-D Secure) |
| plain HTTP on 127.0.0.1 | TLS through Caddy |
| the reference LLM template, unless `LOCAL_LLM_RUNTIME` names a real local model | – |
| **hand-set** policy bands, so that every decision type appears | bands derived from validation data |

Nothing else is relaxed. In particular, no security check is disabled.

## 3. The world

* Seed `20260701`, 360 users, 60 days of history before 2026-07-01 plus 8 live days,
  fraud-rate multiplier 2.5.
* Gradient boosting (primary) and logistic regression (shadow, never decides), both
  trained with fixed seeds and signed with the demo model key.
* The first half of the live stream is scored as background, so queues and history exist.
* The ten cases are picked from the rest by a selection pass on a scratch copy.
* The expected decisions are then **measured** by a second pass on a fresh copy, in exactly
  the walkthrough's order (each case's earlier events for the same user first).

The measured catalogue (`catalogue.json`, seed 20260701, 360 users):

| # | Case | Synthetic scenario | Measured decision | Honest reading |
|---|---|---|---|---|
| 1 | Normal purchase | normal | ALLOW | correct |
| 2 | Legitimate VPN customer | legitimate_vpn | ALLOW | correct: a VPN is a signal, not proof |
| 3 | House mover | new_home_address | ALLOW | correct |
| 4 | Large legitimate purchase | suspicious_velocity (the owner's own purchase) | ALLOW | correct |
| 5 | High-velocity fraud | account_takeover | **ALLOW** | **missed.** No strict match existed (a restricted repeat purchase), so this is the *relaxed* fallback, flagged `relaxed_match` |
| 6 | Account takeover | account_takeover | STEP_UP_AUTHENTICATION | caught (friction, not a block) |
| 7 | Stealth (slow) takeover | slow_account_takeover | ALLOW_WITH_MONITORING | weakly flagged: monitored, not stopped |
| 8 | Manual review | normal | MANUAL_REVIEW | a **false positive**: a genuine customer sent to an analyst |
| 9 | Step-up, then success | legitimate_lookalike | STEP_UP_AUTHENTICATION | friction for a genuine customer |
| 10 | Step-up, then failure | friendly_fraud | STEP_UP_AUTHENTICATION | the provider result is chosen by the demo (fake provider); a real friendly fraudster would *pass* step-up |

In the selection pass, most fraud in this small world was **allowed**, for example
account_takeover 82 ALLOW of 87 and slow_account_takeover 37 of 40 (catalogue field
`selection_pass_decisions`). The hand-set bands show the decision types; they do not make
the model better. Its measured quality is in EVALUATION.md.

## 4. The walkthrough (`fraud-ai demo run`)

| Step | What you see | What it shows |
|---|---|---|
| **1. Service up** | `/v1/health` 200; `/v1/ready` `ready` with every check | fail-closed readiness: DB, models (signatures verified), policy, shared state |
| **2. Legitimate customers** | cases 1-4 scored with signed v2 requests; decision, `=` against the measured expectation, top reason codes | normal customers are left alone |
| **3. Suspicious activity** | cases 5-7 | caught (6), weakly flagged (7) and **missed** (5): what a model misses is part of the story |
| **4. Manual review** | case 8 appears in `/v1/reviews`. Resolving it **without** an operator assertion gets `401 OPERATOR_AUTH_REQUIRED`; with reviewer `rita`'s signed, single-use assertion bound to this review and resolution, `200` | the analyst's identity is authenticated, not a string; the original decision is never rewritten |
| **5. Step-up** | case 9: a payment step-up, then a signed provider callback `authenticated`, then a new follow-up assessment `ALLOW_WITH_MONITORING`. Case 10: `failed`, so the follow-up stays `STEP_UP_AUTHENTICATION` (another attempt; after the maximum, MANUAL_REVIEW, never ALLOW) | results create **new** immutable assessments; scores never change |
| **6. Model disagreement** | the shadow LR agrees with the active GB on 279 of 298 events here; the counts it alone flags | shadow models and policies are recorded but never decide |
| **7. LLM explanation** | `POST /v1/assessments/{id}/investigate` returns an explanation citing evidence | analyst assistance only: scoring never needs or uses it. By default it is the **reference template, not a language model**, and the walkthrough says so |
| **8. Audit** | `audit verify` (hash chain), `audit anchor-now --always` (signed external anchor), `audit verify-anchor` | a DB-level rewrite that re-chains the log is caught by the anchors (the staging drill shows it) |
| **9. Signed model and release** | `models verify-signature gradient-boosting-1.0.0`; `release manifest` signed by operator `sec` (security_admin, authenticated); `release verify` | the release is bound to models, migrations, policy and audit state |

The run writes `walkthrough.json`. The Stage 12 run on the default world:

* all ten decisions equal the measured expectations;
* the authenticated review returned 200;
* step-up: success → `ALLOW_WITH_MONITORING`; failure → `STEP_UP_AUTHENTICATION`;
* shadow report present;
* the LLM step returned 200 (reference template);
* anchors, model signature and release verified.

`tests/test_demo.py` repeats this end to end on a 200-user world against the real service
process.

## 5. Talking points and honest limits

* The demo shows **mechanisms**: authenticated operators, signed artefacts, immutable
  decisions, fail-closed checks. It does not show fraud-detection performance.
* The **bands are hand-set** so that each decision type appears. In staging and in the
  evaluation, bands are derived from validation data.
* The fake payment provider is a development stand-in. **No real Stripe test was run**
  (HARDENING.md §31).
* A real local LLM can be plugged in: `LOCAL_LLM_RUNTIME=llamacpp-server`,
  `LOCAL_LLM_ENDPOINT`, `LOCAL_LLM_MODEL` in `demo.env`. See LLM_ANALYST.md for the Stage 12
  benchmark.
* Interview questions and answers: INTERVIEW_GUIDE.md. The project overview: PORTFOLIO.md.
