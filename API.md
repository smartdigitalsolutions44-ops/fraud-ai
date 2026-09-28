# fraud-ai service API (`fraud-api-1.0.0`)

A machine-to-machine HTTP API over the Stage 8 scoring engine (Stage 9). Merchants and
applications call it from **their backend**, never from a browser. Every example below
uses **synthetic, made-up** identifiers and credentials.

> Research system on synthetic data. This is not production-ready, not a certified
> payment or authentication product, and not PCI-assessed. Decisions are internal policy
> outputs, and nothing here describes real-world fraud rates.

```
merchant / application backend
  │  HTTPS (TLS terminated at a reverse proxy, see DEPLOYMENT.md)
  ▼
fraud service boundary   API key → rate limit → signature → scope → strict validation
  ▼
Stage 8 FraudScoringService (unchanged; no LLM)
  ▼
immutable risk assessment → action request (ALLOW … STEP_UP … MANUAL_REVIEW … BLOCK)
  ▼  (only if STEP_UP_AUTHENTICATION)
step-up: WebAuthn passkey | external payment authentication
  ▼
recorded attempt → NEW immutable follow-up assessment (the original is never changed)
```

## 1. Conventions

| | |
|---|---|
| Base path | `/v1` (the major version is in the path; `api_version` is in every body) |
| Auth | `Authorization: Bearer <key_id>.<secret>`; see [SERVICE_SECURITY.md](SERVICE_SECURITY.md) §2 |
| Signing | `X-Fraud-Timestamp` + `X-Fraud-Signature: v1=<hex>`, optional `X-Fraud-Key-Version` (§3) |
| Idempotency | `Idempotency-Key` on `POST /v1/score` (§4) |
| Correlation | `X-Correlation-ID` (8-64 characters of `[A-Za-z0-9._-]`), echoed; otherwise generated |
| Content type | `application/json` for request bodies; other types get 415 |
| Size limit | `REQUEST_SIZE_LIMIT` bytes (default 64 KiB); 413 above it |
| Errors | `{"error": {"code", "message", "correlation_id"}}`; no stack traces or internals |
| OpenAPI | `fraud-ai service openapi` prints it. `/v1/openapi.json` and `/v1/docs` are served only with `SERVICE_EXPOSE_OPENAPI=true` |

### Endpoints and scopes

| Method and path | Scope | Purpose |
|---|---|---|
| `POST /v1/score` | `score:write` | score one event (`realtime-event-1`) |
| `GET /v1/assessments/{assessment_id}` | `assessment:read` | a safe assessment view, with review and authentication status |
| `POST /v1/assessments/{assessment_id}/investigate` | `investigation:write` | analyst-triggered LLM explanation (optional runtime) |
| `GET /v1/reviews?status=open&limit=50` | `review:read` | the review queue |
| `GET /v1/reviews/{review_id}` | `review:read` | one review item and its outcomes |
| `POST /v1/reviews/{review_id}/resolve` | `review:write` | append an outcome |
| `GET /v1/policy` | `policy:read` | active policy versions |
| `POST /v1/step-up/{assessment_id}/webauthn/challenge` | `stepup:write` | a passkey challenge |
| `POST /v1/step-up/webauthn/verify` | `stepup:write` | verify the assertion; record the result |
| `POST /v1/step-up/webauthn/cancel` | `stepup:write` | the user abandoned the ceremony |
| `POST /v1/step-up/{assessment_id}/payment` | `stepup:write` | request external payment authentication |
| `GET /v1/step-up/payment/{request_id}` | `stepup:write` | poll a payment-authentication request |
| `POST /v1/callbacks/payment/{provider}` | provider signature | the provider's signed result |
| `POST /v1/webauthn/registrations/challenge` | `webauthn:write` | start passkey registration for a user |
| `POST /v1/webauthn/registrations` | `webauthn:write` | finish registration |
| `GET /v1/health` | none | liveness (the process only) |
| `GET /v1/ready` | none | readiness: database, migrations, policy, primary model; never the LLM |
| `GET /v1/metrics` | `metrics:read` | Prometheus text format |

Special scopes:

* `score:replay` allows a recorded `arrival_time` in the body (backfill tooling only).
* `signals:trusted` allows network-intelligence fields (§2.2).

## 2. `POST /v1/score`

The body is exactly the Stage 8 event contract (`realtime-event-1`, see
[REALTIME_SCORING.md](REALTIME_SCORING.md) §2). The contract is strict:

* unknown fields, event types and `schema_version` values are refused;
* malformed ids are refused;
* timestamps must be timezone-aware, and events from the future are refused;
* forbidden data (card numbers, CVV, passwords, …) is refused.

```http
POST /v1/score HTTP/1.1
Authorization: Bearer fak_0123456789abcdef.EXAMPLE-NOT-A-REAL-SECRET-xxxxxxxxxxxxxxxxxx
Content-Type: application/json
Idempotency-Key: checkout-7f3a-attempt-1
X-Fraud-Timestamp: 1782900000
X-Fraud-Signature: v1=<hex HMAC-SHA256>

{
  "event_id": "5b0c2f8e-0d4e-4c2b-9a51-3f1f6f0e9a11",
  "event_type": "TRANSACTION_CREATED",
  "timestamp": "2026-07-01T12:00:00+00:00",
  "user_id": "0f6a4a8e-5c1d-4b8f-a2a7-6f7f0d1e2c3b",
  "session_id": "sess-synthetic-42",
  "device_id": "device-synthetic-7",
  "source": "api",
  "schema_version": 1,
  "metadata": {
    "transaction_id": "7c1e9a3b-2d4f-4e6a-8b0c-1d2e3f4a5b6c",
    "amount": "42.50",
    "currency": "GBP",
    "merchant_category": "5411",
    "channel": "web"
  }
}
```

```json
{
  "api_version": "fraud-api-1.0.0",
  "status": "decided",
  "event_id": "5b0c2f8e-0d4e-4c2b-9a51-3f1f6f0e9a11",
  "assessment_id": "9d3f1e2a-4b5c-4d6e-8f70-a1b2c3d4e5f6",
  "assessment_version": 1,
  "risk_level": "elevated",
  "decision": "STEP_UP_AUTHENTICATION",
  "reason_codes": ["SCORE_BAND_ELEVATED"],
  "action_type": "STEP_UP_AUTHENTICATION",
  "policy_version": "risk-policy-1.0.0",
  "model_version": "gradient-boosting-1.0.0",
  "step_up_required": true,
  "review_required": false,
  "fallback_used": false
}
```

| Status | Meaning |
|---|---|
| 200 `decided` | a new assessment |
| 200 `duplicate` | the event was already scored; the **latest** assessment is returned, for example a step-up follow-up |
| 202 `ingested` | recorded, but not a decision point (for example a login under a transaction-only policy) |
| 403 `INSUFFICIENT_SCOPE` | includes `arrival_time` without `score:replay` |
| 409 `EVENT_CONFLICT` | the `event_id` was already used by a *different* event |
| 409 `IDEMPOTENCY_KEY_REUSED` / `IDEMPOTENCY_IN_PROGRESS` | §4 |
| 422 `INVALID_EVENT` | the contract was violated. The message names fields, never values, and ids are redacted |
| 422 `UNTRUSTED_SIGNAL` | network-intelligence fields came from a key without `signals:trusted` (§2.2) |
| 503 `SCORING_TIMEOUT` / `SCORING_UNAVAILABLE` | the body carries `"fallback_decision": "MANUAL_REVIEW"`. Treat the event as needing review; a retry with the same `event_id` is safe |

What the response **never** contains:

* probabilities, calibrated scores or model scores;
* features, rule internals or shadow results;
* latencies, artefact paths or personal data.

### 2.1 Client-supplied `arrival_time`

The service stamps the arrival time itself. A body `arrival_time` (for replaying recorded
streams) requires `score:replay`; otherwise the request gets 403.

### 2.2 Network signal integrity

`metadata.network.ip`, ASN and country are application-visible facts. The intelligence
fields are different:

* `network_type` (other than `unknown`), `is_mobile_network`;
* `is_datacenter`, `is_known_proxy`, `is_known_vpn`, `is_tor`, `proxy_confidence`;
* `intel_source`.

These are risk signals that a merchant must not be able to assert, for example
`"is_known_vpn": false`. They are accepted only from keys with `signals:trusted` (the
operator's own enrichment pipeline). From any other key the request is refused with 422
`UNTRUSTED_SIGNAL`, never silently dropped. The server-observed peer address is separate
(see [SERVICE_SECURITY.md](SERVICE_SECURITY.md) §6).

## 3. Signed requests

```
signing_secret = HMAC-SHA256(SERVICE_SIGNING_MASTER_KEY, "fraud-ai-signing:" + key_id)   (hex)
X-Fraud-Timestamp: <unix seconds>
X-Fraud-Signature: v1=hex(HMAC-SHA256(signing_secret, "<timestamp>." + raw_body))
```

`fraud-ai service-key create --show-signing-secret` prints the key's signing secret once.
A GET is signed over an empty body. Requests are rejected with 401 when the signature is:

* missing, when `SERVICE_REQUIRE_SIGNATURES=true`: `MISSING_SIGNATURE`;
* wrong: `INVALID_SIGNATURE`;
* older or newer than `SIGNATURE_MAX_AGE` (default 300 s): `EXPIRED_SIGNATURE`;
* already used: `REPLAYED_SIGNATURE`. Replay tokens are persisted (one process), or
  claimed atomically in Redis across all workers and instances when
  `STATE_BACKEND=redis` (Stage 10).

**Signing-key versions (Stage 10).** During a master-key rotation, signatures from both the
current and the previous master key verify until the previous key's expiry. A client may
send `X-Fraud-Key-Version: <version>` to name the key it signed with. Without the header,
every allowed key is tried. `fraud-ai service-key signing-secret <key-id> [--previous]`
prints the secret for either version.

If signatures are required but the server has no signing key, every request gets
**503 `SIGNING_UNAVAILABLE`**. That is a server misconfiguration; nothing is processed
unsigned.

A retry must be signed again with a new timestamp. Idempotency then returns the original
result.

```python
import hashlib, hmac, json, time
body = json.dumps(event).encode()
ts = int(time.time())
sig = hmac.new(signing_secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
headers = {"X-Fraud-Timestamp": str(ts), "X-Fraud-Signature": f"v1={sig}"}
```

## 4. Idempotency

`Idempotency-Key` is 8-100 characters of `[A-Za-z0-9_.:-]` and is scoped to your API key
and the route.

* **Same key, same body:** the original status and body, with
  `Idempotent-Replayed: true`.
* **Same key, different body:** 409 `IDEMPOTENCY_KEY_REUSED`, and nothing is processed.
* **Same key while the first request is running:** 409 `IDEMPOTENCY_IN_PROGRESS`, with
  `Retry-After`.
* **A failed first attempt** (non-2xx) releases the key.

Independently of the header, the `event_id` itself is idempotent (Stage 8).

## 5. Assessments

`GET /v1/assessments/{id}`:

```json
{
  "api_version": "fraud-api-1.0.0",
  "assessment_id": "9d3f1e2a-4b5c-4d6e-8f70-a1b2c3d4e5f6",
  "event_id": "5b0c2f8e-0d4e-4c2b-9a51-3f1f6f0e9a11",
  "assessment_version": 1,
  "supersedes_assessment_id": null,
  "latest_assessment_id": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
  "mode": "live",
  "decision": "STEP_UP_AUTHENTICATION",
  "risk_level": "elevated",
  "reason_codes": ["SCORE_BAND_ELEVATED"],
  "action_type": "STEP_UP_AUTHENTICATION",
  "policy_version": "risk-policy-1.0.0",
  "model_version": "gradient-boosting-1.0.0",
  "fallback_used": false,
  "assessed_at": "2026-07-01T12:00:00.120000Z",
  "step_up_required": false,
  "review_required": false,
  "review": null,
  "authentication": {"attempts": 1, "latest_result": "SUCCESS", "method": "webauthn",
                      "completed": true,
                      "followup_assessment_id": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"}
}
```

`latest_assessment_id` leads to the follow-up. `step_up_required` is true only while the
step-up is still open.

## 6. Step-up

The details are in [AUTHENTICATION.md](AUTHENTICATION.md).

### 6.1 WebAuthn (passkeys)

```http
POST /v1/step-up/9d3f1e2a-…/webauthn/challenge
{"session_id": "sess-synthetic-42"}
→ 200 {"challenge_id": "…", "expires_at": "…", "public_key": {PublicKeyCredentialRequestOptions}}
```

Pass `public_key` to `navigator.credentials.get({publicKey})` in the client, send the
serialised credential to your backend, then:

```http
POST /v1/step-up/webauthn/verify
{"challenge_id": "…", "session_id": "sess-synthetic-42", "credential": {…}}
→ 200 {"result": "SUCCESS", "attempt_number": 1, "failure_reason": null,
       "attempts_remaining": 0,
       "followup": {"assessment_id": "…", "assessment_version": 2,
                    "decision": "ALLOW_WITH_MONITORING", "reason_codes": ["STEP_UP_SUCCESS"],
                    "followup_policy_version": "step-up-followup-1.0.0", …},
       "note": "authentication is additional evidence, never proof of legitimacy"}
```

A failed verification also returns 200, with `"result": "FAILED"` and a `failure_reason`;
the attempt is recorded. Errors (409) are:

* `CHALLENGE_INVALID`: unknown, used, replayed, or another key's challenge;
* `STEP_UP_NOT_REQUIRED`, `STEP_UP_ALREADY_COMPLETED`, `ATTEMPTS_EXHAUSTED`;
* `NO_CREDENTIALS`, `SESSION_MISMATCH`.

Registration: `POST /v1/webauthn/registrations/challenge` with `{"user_id"}`, then
`navigator.credentials.create`, then `POST /v1/webauthn/registrations` with
`{"challenge_id", "credential"}`, which returns 201 `{"credential_ref", "status"}`.

### 6.2 External payment authentication

```http
POST /v1/step-up/9d3f1e2a-…/payment
{"token_reference": "tok_psp_synthetic_123", "amount_minor": 4250, "currency": "GBP"}
→ 200 {"request_id": "…", "provider": "fake", "status": "pending",
       "next_action": {"type": "fake_challenge", "note": "DEVELOPMENT FAKE - not 3-D Secure"}}
```

The provider later POSTs its signed result to `/v1/callbacks/payment/{provider}`. The
response looks like `{"accepted": true, "status": "authenticated", "result": "SUCCESS"}`.

* A duplicate callback gets 409 `DUPLICATE_CALLBACK`; a replayed one gets 401
  `REPLAYED_SIGNATURE`.
* If the provider is down or times out, the response is **200 with `"status":
  "unavailable"`** and `next_action.type = "authentication_unavailable"`. That is never an
  allow.
* Without a configured provider, the request gets 503 `PAYMENT_AUTH_NOT_CONFIGURED`.
* **Stage 10:** a correctly signed callback for an event type that does not change state
  (for example Stripe `payment_intent.created`) gets **200
  `{"accepted": false, "status": "ignored"}`**. Nothing is recorded, and it is never
  treated as success.
* **Stage 10:** `PAYMENT_AUTH_PROVIDER=stripe` selects the Stripe **test-mode** adapter
  (`/v1/callbacks/payment/stripe`, `Stripe-Signature`). The response carries
  `next_action.type = "stripe_authentication"` with the PaymentIntent client secret for the merchant's
  front end. It has never been run against Stripe; see AUTHENTICATION.md §3.

`token_reference` is the processor's token, which is stored only as a keyed hash. Never
send card numbers, CVV or PINs: the event contract refuses them.

## 7. Reviews

```http
GET /v1/reviews?status=open&limit=50          → {"items": [{review_id, assessment_id, priority, …}]}
GET /v1/reviews/{review_id}                   → {"review", "assessment", "outcomes"}
POST /v1/reviews/{review_id}/resolve          {"resolution": "legitimate" | "fraud" | "needs_more_information",
                                               "note": "customer confirmed by phone"}
```

* Notes that look like personal data or secrets get 422.
* A resolved item gets 409 `ALREADY_RESOLVED`.
* Resolving never changes the assessment.

## 8. Investigation (optional, analyst-triggered)

`POST /v1/assessments/{id}/investigate` runs the Stage 7 pipeline in its own thread pool,
with its own timeout (`LOCAL_LLM_TIMEOUT` + 10 s). It is never part of scoring.

| Outcome | Response |
|---|---|
| explanation stored | 200 `{investigation_id, explanation_version, runtime, model, explanation}` |
| no runtime configured or reachable | 503 `LLM_UNAVAILABLE` ("scoring and decisions are unaffected") |
| output failed validation (nothing stored) | 502 `INVESTIGATION_FAILED` |
| timeout | 504 `LLM_TIMEOUT` |
| no stored predictions | 409 `INVESTIGATION_NOT_POSSIBLE` |

## 9. Operations

* `GET /v1/health` returns `{"status": "ok"}`.
* `GET /v1/ready` returns 200 or 503 with these checks:
  * `database` and `migrations`;
  * `active_policy`;
  * `primary_model`: the artefact loaded and SHA-256-verified, re-verified when it changes
    and every `READINESS_REVERIFY_SECONDS`;
  * `shared_state` (Stage 10; `not_required` with the memory backend);
  * `signing_key` (Stage 10);
  * `llm` (always `not_required`).
* `GET /v1/metrics` exposes these series:
  * `fraud_api_requests_total{route,method,status}`;
  * `fraud_api_request_duration_seconds`;
  * `fraud_api_decisions_total{decision}`;
  * `fraud_api_auth_failures_total{reason}`;
  * `fraud_api_rate_limited_total{route}`;
  * `fraud_api_idempotent_replays_total`;
  * `fraud_api_stepup_results_total{method,result}`;
  * `fraud_api_investigations_total{outcome}`;
  * `fraud_api_review_queue{status}`;
  * Stage 10: `fraud_api_signature_failures_total{code}`,
    `fraud_api_signatures_verified_total{key_version}`,
    `fraud_api_state_unavailable_total{what}`, `fraud_state_operation_seconds{op}`,
    `fraud_state_errors_total{op}`, `fraud_db_ping_seconds`, `fraud_db_query_seconds`,
    `fraud_db_pool_checked_out`, `fraud_model_verification_seconds`,
    `fraud_model_verification_failures_total`, `fraud_model_cache_loads`,
    `fraud_model_cache_load_failures`, `fraud_api_fallbacks_total{category}` and
    `fraud_api_policy_decisions_total{policy_version,decision}`.

  Metrics are per worker process.

  Labels are route templates and enums: never ids, keys or addresses.

## 10. Error codes

| HTTP | Codes |
|---|---|
| 400 | `BAD_REQUEST`, `INVALID_JSON`, `INVALID_IDEMPOTENCY_KEY`, `SIGNING_NOT_CONFIGURED` |
| 401 | `UNAUTHENTICATED`, `MISSING_SIGNATURE`, `INVALID_SIGNATURE`, `EXPIRED_SIGNATURE`, `REPLAYED_SIGNATURE`, `UNKNOWN_PROVIDER`, `INVALID_CALLBACK` |
| 403 | `INSUFFICIENT_SCOPE` |
| 404 | `NOT_FOUND` |
| 409 | `EVENT_CONFLICT`, `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_IN_PROGRESS`, `CHALLENGE_INVALID`, `STEP_UP_NOT_REQUIRED`, `STEP_UP_ALREADY_COMPLETED`, `ATTEMPTS_EXHAUSTED`, `NO_CREDENTIALS`, `NO_USER`, `SESSION_MISMATCH`, `CREDENTIAL_EXISTS`, `DUPLICATE_CALLBACK`, `ALREADY_RESOLVED`, `INVESTIGATION_NOT_POSSIBLE` |
| 410 | `CHALLENGE_EXPIRED` (registration) |
| 413 | `REQUEST_TOO_LARGE` |
| 415 | `UNSUPPORTED_MEDIA_TYPE` |
| 422 | `VALIDATION_ERROR`, `INVALID_EVENT`, `UNTRUSTED_SIGNAL`, `VERIFICATION_FAILED`, `INVALID_NOTE` |
| 429 | `RATE_LIMITED` (with `Retry-After`) |
| 500 | `INTERNAL_ERROR` (generic; the correlation id finds the log line) |
| 502 / 503 / 504 | `INVESTIGATION_FAILED`, `SCORING_UNAVAILABLE`, `SCORING_TIMEOUT`, `POLICY_UNAVAILABLE`, `PAYMENT_AUTH_NOT_CONFIGURED`, `LLM_UNAVAILABLE`, `LLM_TIMEOUT` |
| 503 (Stage 10) | `DATABASE_UNAVAILABLE` (database or pool unavailable; `Retry-After`), `STATE_UNAVAILABLE` (Redis unavailable), `SIGNING_UNAVAILABLE` (signatures required, no key configured) |

A 503 means **not decided**. Callers must take their own conservative path and never treat
it as an allow.

## 11. Direct library use

The HTTP layer is optional. `FraudScoringService.score_event(event)` and the CLI
(`fraud-ai realtime score|replay`) work unchanged. The step-up operations are plain
functions in `fraud_ai.stepup` and take a SQLAlchemy session.
