# Analyst workflow contract (Stage 12)

This is the **contract** a future analyst console would build on. **No console is built.**
It maps each analyst task to the existing API calls, their fields and their authorisation,
and says plainly where data is not exposed yet. Every call below exists and is exercised by
the demo walkthrough and the staging E2E. Nothing here changes how decisions are made.

## 1. Principles

* **Minimal personal data.** The analyst sees pseudonymous identifiers, decisions, reason
  codes, model versions, step-up status and cited evidence. The API never returns names,
  e-mail addresses, card data, raw IP addresses (unless `STORE_RAW_IP` is set, which is off
  by default), device fingerprints or address hashes. Review notes that look like personal
  data or secrets are refused (422 `INVALID_NOTE`).
* **Decisions are immutable.** Resolving a review appends an outcome. It never rewrites the
  assessment, the score or the label used for training.
* **The LLM assists and never decides.** Its output is a stored, validated explanation that
  cites evidence. It cannot score, resolve, approve or change anything.
* **The reviewer is an authenticated person, not a string.** Resolution requires an
  operator assertion from a registry member with the `reviewer` role (§4).

## 2. Screens and calls

| Analyst task | Call (scope) | Fields used |
|---|---|---|
| **Review queue** | `GET /v1/reviews?status=open&limit=50` (`review:read`) | `review_id`, `assessment_id`, `event_id`, `priority` (1 is most urgent; the queue is ordered by priority, then age), `status`, `reason_codes`, `created_at` |
| **Case details** | `GET /v1/reviews/{review_id}` (`review:read`) | `review`, `assessment` (the view below) and earlier `outcomes` (`resolution`, sanitised `note`, `created_at`) |
| **Assessment and risk reasons** | `GET /v1/assessments/{assessment_id}` (`assessment:read`) | `decision`, `risk_level`, `reason_codes`, `policy_version`, `model_version`, `fallback_used`, `assessed_at`, `mode` |
| **Step-up status** | the same view, `authentication` | `attempts`, `latest_result` (`SUCCESS`/`FAILED`), `method` (`webauthn` or `payment`), `completed`, `followup_assessment_id`. `latest_assessment_id` leads to the follow-up; `supersedes_assessment_id` leads back |
| **Model disagreement** | `POST /v1/assessments/{id}/investigate` (`investigation:write`), evidence group `model_agreement` | the explanation cites `pattern` (`all_low`, `all_high`, `mixed`), `models_flagging`, `models_total`, `models_uncertain` and pairwise differences. The live shadow-versus-active aggregate is `fraud-ai realtime shadow-report` (operators) |
| **LLM investigation** | `POST /v1/assessments/{id}/investigate` | `investigation_id`, `explanation_version`, `runtime`, `model`, `explanation`, `note` ("decision support only; nothing was rescored or decided") |
| **Resolution** | `POST /v1/reviews/{review_id}/resolve` (`review:write`) with the header `X-Fraud-Operator-Assertion` | body `{"resolution": "legitimate" \| "fraud" \| "needs_more_information", "note": "…"}` (note at most 500 characters, PII-checked) |

All calls are signed v2 requests with a scoped API key (API.md §3). The console backend
holds the key. The analyst's own key signs only the operator assertion (§4).

### Model disagreement: what is not exposed yet

Per-assessment shadow scores are **stored** (`risk_assessments.model_scores`, shadow model
versions included). The HTTP API does **not** return them. Today, an analyst sees
disagreement only through the investigation's cited `model_agreement` evidence, and in
aggregate through the operator's shadow report.

A console that needs a raw per-model score panel would need a new read-only field. It
would add **internal model data** to the analyst's view. That is a deliberate product
decision, not a missing bug. `privacy export` also excludes these scores (PRIVACY.md).

## 3. States

```
  score → MANUAL_REVIEW or TEMPORARY_BLOCK ──► review item: open
                     │
                     ├─ resolve legitimate | fraud ──────► resolved (outcome appended; final)
                     └─ resolve needs_more_information ──► needs_more_information (outcome
                                                           appended; can be resolved again)
score → STEP_UP_AUTHENTICATION ──► step-up attempt(s) ──► follow-up assessment (new, immutable)
                                     success → e.g. ALLOW_WITH_MONITORING
                                     failure → another attempt, until STEP_UP_MAX_ATTEMPTS;
                                               then MANUAL_REVIEW, never ALLOW
```

* A resolved item gets 409 `ALREADY_RESOLVED`: outcomes are appended, never rewritten, and
  a final resolution closes the item.
* Priority (`fraud_ai/risk/engine.py:review_priority`):

  | Priority | Items |
  |---|---|
  | 1 | TEMPORARY_BLOCK |
  | 2 | MANUAL_REVIEW from a fallback, or at high or extreme risk |
  | 3 | other MANUAL_REVIEW |

  It is a queue order, not an SLA.

## 4. Authenticating the analyst

The service does not trust an analyst name in a request. Every resolution carries a
**signed operator assertion** (an EdDSA JWT; AUTHENTICATION.md §6):

* **issued by** the analyst's own Ed25519 key, registered in `OPERATOR_REGISTRY_FILE` with
  the `reviewer` role;
* **for** `action = review.resolve`, `target = <review_id>`, `binding = {"resolution": …}`.
  A token for another review, or for another resolution, is refused;
* **short-lived** (at most `OPERATOR_ASSERTION_MAX_SECONDS`) and **single use** (its `jti`
  is recorded; a replay gets `REPLAYED_ASSERTION`).

| Response | When |
|---|---|
| 401 `OPERATOR_AUTH_REQUIRED` | no assertion (in staging and production) |
| 401 `OPERATOR_AUTH_FAILED` | a bad signature, expired, replayed, wrong target or resolution, unknown or disabled key |
| 403 `OPERATOR_AUTH_FAILED` (refusal code `FORBIDDEN`) | a valid operator without the `reviewer` role |

The outcome records the **verified** operator id (`review_outcomes.reviewer`). The audit
log records `operator.authenticated` with the assertion id and key id, never the token.

A console would hold the analyst's key in the browser (WebCrypto, non-extractable) or in a
hardware token, and sign assertions client-side. **That integration is not built.** Today,
assertions come from `fraud-ai operators assert` or the demo and E2E helpers.

## 5. What an analyst never sees or does

* card numbers, CVV, PINs or passwords: never accepted or stored anywhere;
* keyed pseudonyms, fingerprints, device, IP or address hashes, API or signing secrets;
* other customers' data. The views are keyed by assessment or review id, and `privacy
  export` is a separate security-admin command;
* re-scoring, changing a score, a label, a threshold or a policy. Policy changes go through
  two-person approval by `policy_approver`s and activation by a `policy_activator`
  (TRUST_CHAIN.md);
* acting through the LLM. It explains; it has no tools.
