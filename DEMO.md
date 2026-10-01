# Demo walkthrough (Stages 12 to 14)

**Fastest way in (Stage 14):** `.\scripts\setup-local.ps1` then
`.\scripts\sentinel-start.ps1 -Mode Demo` on Windows, or `./scripts/setup-local.sh` then
`./scripts/sentinel-start.sh` on Linux/macOS; see [LOCAL_SETUP.md](LOCAL_SETUP.md). The
console version of the walkthrough is [the interview walkthrough](#interview-walkthrough)
below. The CLI walkthrough in sections 1 to 4 still works unchanged.

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

## 5. The same demo in the SENTINEL console (Stages 13 and 14)

```powershell
.\scripts\sentinel-start.ps1 -Mode Demo                  # Windows → http://127.0.0.1:3000
```

```bash
./scripts/sentinel-start.sh --mode demo                    # Linux/macOS
cd sentinel-console && npm run demo                        # the same, attached to the terminal
```

* **What starts.** The world is built if needed (through the guarded reset); then the
  service runs with the demo world's own configuration and the console's production build
  runs in **DEMO MODE**. The top bar says so (DEMO MODE · SYNTHETIC DATA).
* **Start-up.** The start-up sequence has seven lines (contacting the fraud service, trust
  chain, data plane, model signatures, risk policy, audit chain, analyst console), each
  resolved by real readiness data. On a fresh world the audit chain shows DEGRADED, because
  no external anchor exists until `fraud-ai audit anchor-now` (or the walkthrough's step 8)
  runs.
* **Demo page.** It lists the ten cases with their measured decision and a developer note,
  kept separate from model output. **Score this scenario** sends the case's events
  through the real service (server-side, signed); the page then shows the service's
  decision against the measured one.
* **Resolving a case.** Open the case from the Review Queue and run the investigation.
  This is the reference template unless a tested local model is configured. Then resolve
  it. In DEMO MODE the console server signs as demo reviewer `rita`, and the outcome
  records `operator:rita`.
* **RESET DEMO.** It needs the typed phrase `RESET DEMO`. It runs the same guarded
  `fraud-ai demo reset` through the local supervisor and is refused outside DEMO MODE.

The Playwright test (`sentinel-console/e2e/`) runs exactly this flow on a freshly reset
world, and captures the screenshots in `sentinel-console/docs/screenshots/`.

## Interview walkthrough

Seven to eight minutes in the console, from a running demo (`sentinel-start`). Optional:
Ctrl+K → "Toggle presentation mode" for larger text on a shared screen; it hides build
details only, never system state.

| Time | Screen | Show | Say |
|---|---|---|---|
| 0:00 | Terminal | `sentinel-start -Mode Demo`; the browser opens | One command: the fraud service, the console, signed models, a synthetic world. Nothing else on the machine is touched. |
| 0:30 | Start-up | The seven lines resolve; audit shows DEGRADED | Every line is a real check, not an animation. The audit chain is verified but has no external anchor yet, so the console says DEGRADED instead of pretending. Enter the console. |
| 1:00 | Overview | Metric cards, flagged assessments, decision distribution, system health | Live numbers from the service. A flag is a risk signal for review, not a fraud finding. |
| 2:00 | Review Queue → a case | Open the manual-review case (Enter, or the Demo page's "Score this scenario" first) | The header line says what happened and why in one sentence: decision, the leading reason, rules matched, model agreement. |
| 3:00 | Timeline | Day separators, offsets from the case event, marked events | Chronology at a glance: what happened before the event, and after the decision. Marked events carry a stored signal (new device, VPN, account change), not proof. |
| 4:00 | Model assessment | Primary vs shadow; agree or disagree | The primary model drives the policy through its calibrated score; shadow models are recorded and never decide. No consensus score: it is not a vote. |
| 5:00 | Investigation | Run investigation | Analyst assistance: observed evidence, interpretation, limitations. It cites the stored evidence and never decides. With no local model it is the reference template, and says so. |
| 6:00 | Analyst decision | Press R (opens the panel, never submits); choose an outcome; read the confirmation | The confirmation says what will happen. Submit once: the outcome is recorded with the verified reviewer and is final; the original assessment never changes. Reload to show it comes from the service. |
| 7:00 | System | The seven-group rail, models table, policy bands, audit | The security operations view: signed requests, signed models, operator authentication, the audit chain, each with its state and cause. The console cannot change any of it. |

Close with `sentinel-stop`, and `sentinel-reset-demo` before the next run (it rebuilds the
world through the guarded reset; type RESET DEMO).

### Recording a 2-4 minute demo video (shot list)

No video tooling is needed; record the screen at 1920x1080 with presentation mode on.

1. **0:00-0:15:** terminal, `sentinel-start -Mode Demo`, the "SENTINEL is ready" banner.
2. **0:15-0:35:** the start-up sequence resolving; pause on the DEGRADED audit line.
3. **0:35-1:00:** Overview, slow pan across the metric cards and the flagged list.
4. **1:00-1:40:** open the manual-review case; header summary, then the timeline.
5. **1:40-2:15:** model panel (primary vs shadow), then run the investigation; scroll
   through observed evidence, interpretation, limitations.
6. **2:15-2:50:** R, choose "Resolve as legitimate", read the confirmation, submit, reload.
7. **2:50-3:20:** System page rail; end on the models table with "Verified".
8. **3:20-3:40:** terminal, `sentinel-status`, then `sentinel-stop`.

### Time to demo

| | Linux container (local) | Linux (CI, fresh checkout) | Windows (CI, fresh checkout) |
|---|---|---|---|
| `setup-local` | 66-79 s (Python packages cached) | see the CI summary | see the CI summary |
| First start (builds the world) | 201-223 s | see the CI summary | see the CI summary |
| Start with the world present | 6-14 s | see the CI summary | see the CI summary |

The CI jobs `local-scripts` and `local-windows` record their timings in the run summary.

## 6. Talking points and honest limits

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
