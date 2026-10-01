# SENTINEL demo

How to show SENTINEL in an interview: exact commands, exact clicks, what to say, and what
to do when something is unavailable. Everything runs on a **deterministic, synthetic**
world: every decision you show is the running service's live answer, and every expected
decision was measured, not chosen. A missed fraud is shown as missed.

**Everything here is SYNTHETIC.** No real customer, card or payment data exists anywhere in
the demo. Demo keys and secrets are generated on first reset and are demo-only.

## 1. Before the interview

Do this at least ten minutes before, so the slow first build is out of the way.

| Step | Windows (PowerShell) | Linux / macOS |
|---|---|---|
| 1. Install (once) | `.\scripts\setup-local.ps1` | `./scripts/setup-local.sh` |
| 2. Start | `.\scripts\sentinel-start.ps1 -Mode Demo` | `./scripts/sentinel-start.sh --mode demo` |
| 3. Check | `.\scripts\sentinel-status.ps1` | `./scripts/sentinel-status.sh` |
| 4. Optional: a fresh world | `.\scripts\sentinel-reset-demo.ps1` (type `RESET DEMO`) | `./scripts/sentinel-reset-demo.sh` |

* Step 2 prints **SENTINEL is ready** and opens `http://127.0.0.1:3000`. The first start
  builds the world (3–5 minutes); later starts take seconds.
* Step 3 should show API and Console **ONLINE**, both models **signature verified**,
  PostgreSQL and Redis **NOT USED** (Demo mode uses SQLite and in-memory state).
* A fresh world (step 4) puts the manual-review case back in the queue unresolved.
* In the browser, **Ctrl+K → Toggle presentation mode** enlarges text for a shared screen. It
  hides build details only, never system state.
* Keep [the screenshots](sentinel-console/docs/screenshots/) open in a tab as a backup.

## 2. The interview demo (5–8 minutes)

Start from a running demo with the browser closed, or on the start-up screen.

| Time | Screen | Exact clicks | Say | It demonstrates |
|---|---|---|---|---|
| 0:00 | Terminal | Run `sentinel-start` (step 2 above); the browser opens | "One command starts the fraud service, the analyst console and a synthetic world with signed models. Nothing else on the machine is touched." | one-command local run |
| 0:30 | Start-up | Watch the seven lines resolve; click **Enter console (degraded)** | "Every line is a real check against the running service, not an animation: signed requests, database, signed models, the risk policy, the audit chain. The audit line says DEGRADED because a fresh world has no external anchor yet; the console says so instead of pretending." | trust and readiness checks; honest states |
| 1:00 | Overview | Nothing to click; point at the metric cards, the flagged list and system health | "These are live numbers from the service. A flag means 'look at this', not 'this is fraud'." | the analyst's starting point |
| 1:45 | Live Feed | Click **Live Feed** in the left navigation | "Every decision the service made, newest first: risk band, decision, reasons, review and step-up state, and latency; the status bar shows the policy and model versions. Most traffic is allowed, as it should be." | real-time decisions with versions |
| 2:15 | Suspicious case | Click **Demo**, then **Score this scenario** on the *Manual review* card; when it shows *Service decided … = measured*, click **Open case** | "I just sent this customer's events through the real service with a signed request. The header says what happened and why in one line: sent to manual review, the leading reason, and whether the models agree." | end-to-end scoring; case summary |
| 3:00 | Timeline | Scroll the left column | "The customer's history before this event, with offsets from it. Marked events carry a stored signal, a new device or an account change, but a signal is not proof." | point-in-time context |
| 3:45 | Model comparison | Scroll to the *Model assessment* panel | "The models disagree here: gradient boosting, the primary, is above its threshold; logistic regression, the shadow, is well below. The console says so and does not average them: it is not a vote. The decision is the policy's, made from the primary's *calibrated* score falling in the high band; the shadow is recorded and never decides." | model disagreement; primary vs shadow; calibration and policy |
| 4:30 | Analyst assistance | Click **Run investigation** | "This is analyst assistance: observed evidence, interpretation and limitations, every statement citing stored evidence. It never decides. With no local model configured it is a deterministic reference template, and it says so." | the LLM is outside the decision path |
| 5:15 | Resolve | Press **R** (it focuses the panel and never submits), click **Resolve as legitimate**, read the confirmation, add a note, click **Resolve as legitimate** again to confirm; then reload the page | "The confirmation says exactly what will happen. The outcome is recorded with the authenticated reviewer, here demo reviewer `operator:rita`, and is final; the original assessment never changes. After a reload it still shows, because it comes from the service." | authenticated, immutable resolution |
| 6:00 | System | Click **System**; scroll down to *Active risk policy* | "The security operations view: signed v2 requests, operator authentication, both models' signatures verified, the active policy and its risk bands, the audit chain. The console can see all of this and change none of it; policy changes need two authenticated people." | trust controls |
| 6:45 | Architecture | Switch to the architecture diagram in [README.md](README.md#architecture) | "A merchant calls a signed API; features are computed as of the event; signed models score it; a versioned policy decides; the assessment is immutable; reviews and step-ups create new records; the audit log is anchored in write-once storage." | the whole system |
| 7:30 | Terminal | Run `sentinel-stop` | "And it stops only what it started." | clean shutdown |

**If you have a minute more:** in the case, open **Show 6 rules that did not match**
("every rule was evaluated, and none fired; the decision came from the score band"), or the
*Audit trail* panel ("the assessment, the review and the explanation are each an audit
event in the hash chain").

### Questions the demo invites

* *"Why was a genuine customer sent to review?"* It is a false positive at the demo's
  hand-set bands; the demo catalogue labels it as such.
* *"Is this real fraud performance?"* No: synthetic data, and in this small world most fraud
  is allowed (see §6). Real evaluation numbers are in [EVALUATION.md](EVALUATION.md).
* More: [INTERVIEW_GUIDE.md](INTERVIEW_GUIDE.md).

## 3. Fallbacks

| If | Then |
|---|---|
| **No local LLM** (the default) | Nothing to do: the investigation uses the reference template and labels it "not a language model". Say so; it is the honest default because the small local models failed the structured-output benchmark ([LLM_ANALYST.md](LLM_ANALYST.md)). |
| **A configured local LLM is down or times out** | The investigation panel shows *Local analyst model unavailable*, and states that scoring, decisions and the rest of the case are unaffected. Show that: it is the design. Remove `LOCAL_LLM_RUNTIME` from `data/demo/demo.env` and restart to get the template back. |
| **No network / no Docker** | Demo mode needs neither: SQLite, in-memory state, local signed models. Dev and StagingLike need Docker and refuse clearly without it. |
| **A port is busy** | `sentinel-start` names the process using it and starts nothing; stop that process, or run `sentinel-stop` if it is an earlier SENTINEL session. |
| **The browser did not open** | Open `http://127.0.0.1:3000` yourself. |
| **The console says OFFLINE** | The service stopped: `sentinel-status`, then the logs in `.runtime/logs/`. The console recovers on its own once the service is back. |
| **The manual-review case is already resolved** | Run `sentinel-reset-demo` before the interview (step 4), or show the resolved case: the outcome and reviewer are part of the story. |
| **The demo world looks wrong** | `sentinel-reset-demo` rebuilds it through the guarded reset. |
| **Everything fails** | Use the screenshots (README *Screenshots*), or the CLI walkthrough: `fraud-ai demo run` (§8). |

## 4. Recording a 2–4 minute video (shot list)

Record the screen at 1920×1080 with presentation mode on. No video tooling is required.

| Time | Shot | Show |
|---|---|---|
| 0:00–0:15 | **Clean start-up** | terminal: `sentinel-start`, the "SENTINEL is ready" banner |
| 0:15–0:35 | start-up checks | the seven lines resolving; pause on the DEGRADED audit line; Enter console |
| 0:35–0:55 | **Overview** | slow pan across the metric cards and the flagged list |
| 0:55–1:15 | **Review queue** | the queue; open the manual-review case (Demo → Score this scenario → Open case) |
| 1:15–1:45 | **Case investigation** | the header summary, then the timeline |
| 1:45–2:05 | **Model disagreement** | the *Model assessment* panel: *Models disagree*, primary above its threshold, shadow below |
| 2:05–2:35 | **Analyst assistance** | Run investigation; scroll through evidence, interpretation, limitations |
| 2:35–3:05 | **Review resolution** | R, Resolve as legitimate, the confirmation, submit, reload |
| 3:05–3:30 | **System verification** | System page: models *Verified*, trust and audit groups |
| 3:30–3:45 | close | terminal: `sentinel-status`, then `sentinel-stop` |

## 5. Time to demo

| | Fresh clone, this project's Linux sandbox | Linux CI (fresh checkout) | Windows CI (fresh checkout, path with spaces) |
|---|---|---|---|
| `setup-local` | 64 s¹ | 90 s (step time) | 152 s |
| First start (builds the world) | 305 s | 174 s | 204 s |
| Start with the world present | 7 s | – | 13 s |
| Stop | 4 s | – | 3 s |

¹ The sandbox's network blocks the PyTorch CPU wheel index, so the clone's `.venv` reused
the machine's existing PyTorch (`--system-site-packages`, `SENTINEL_TORCH_INDEX_URL=`);
everything else was installed fresh. CI runs the unmodified setup. CI figures: runs
`36899999431`, `36920010359` and `36923589942`.

## 6. The demo world

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

## 7. What is the same as staging, and what is not

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

## 8. The CLI walkthrough (no console)

The same world, driven from the terminal by `fraud-ai demo run`: useful as a fallback, and
for showing the API and the audit and release commands directly.

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

### The nine steps of `fraud-ai demo run`

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

## 9. Talking points and honest limits

* The demo shows **mechanisms**: authenticated operators, signed artefacts, immutable
  decisions, fail-closed checks. It does not show fraud-detection performance.
* The **bands are hand-set** so that each decision type appears. In staging and in the
  evaluation, bands are derived from validation data.
* The fake payment provider is a development stand-in. **No real Stripe test was run**
  (HARDENING.md §31).
* A real local LLM can be plugged in: `LOCAL_LLM_RUNTIME=llamacpp-server`,
  `LOCAL_LLM_ENDPOINT`, `LOCAL_LLM_MODEL` in `demo.env`. See LLM_ANALYST.md for the Stage 12
  benchmark.
* Interview questions and answers: [INTERVIEW_GUIDE.md](INTERVIEW_GUIDE.md). The project
  overview: [PORTFOLIO.md](PORTFOLIO.md).
