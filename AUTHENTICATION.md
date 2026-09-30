# Step-up and operator authentication (Stages 9-12)

Stage 8 decides *whether* extra authentication is needed: a `STEP_UP_AUTHENTICATION`
assessment. Stage 9 *executes* the step-up through one of two standard mechanisms, records
the result and issues a **new, immutable follow-up assessment**.

> **Scope and non-claims.**
> * fraud-ai does **not** authenticate cardholders. It is not an issuer, it does not
>   implement 3-D Secure, and it never sees, stores or asks for a PAN, CVV, PIN or track
>   data.
> * Payment authentication is **requested from an external provider** through an
>   adapter. Two providers are bundled: a clearly labelled **development fake**, and
>   (Stage 10) a **Stripe test-mode adapter** that has **never been run against Stripe**
>   (§3).
> * No custom cryptography: WebAuthn is verified by the maintained
>   [py_webauthn](https://github.com/duo-labs/py_webauthn) library.
> * Successful authentication is **additional evidence, not proof** that a transaction
>   is legitimate.
> * Nothing here is production-ready or certified.

## 1. The flow

```
POST /v1/score ──► assessment v1: STEP_UP_AUTHENTICATION  (immutable)
      │
      ├─ WebAuthn:  challenge ─► client ceremony (navigator.credentials.get) ─► verify
      │                                                 │
      └─ Payment:   request ─► external provider ─► signed callback
                                                        ▼
                          authentication_attempts row (append-only)
                          {assessment, method, result, attempt n, reason, credential/provider ref}
                                                        ▼
                   terminal? ──► assessment v2 (step_up_followup, supersedes v1)
                                 scores copied verbatim · decision from step-up-followup-1.0.0
```

* Only the event's **latest** assessment, when it is a `STEP_UP_AUTHENTICATION`, can be
  stepped up. A second step-up after completion is refused
  (`STEP_UP_ALREADY_COMPLETED`), and so is a step-up on any other decision
  (`STEP_UP_NOT_REQUIRED`).
* Each attempt is numbered. At most `STEP_UP_MAX_ATTEMPTS` (default 3) are allowed per
  assessment.

### Follow-up policy `step-up-followup-1.0.0`

| Result | Terminal? | Follow-up decision |
|---|---|---|
| `SUCCESS` | always | `ALLOW_WITH_MONITORING`: the control completed, but the risk evidence stands, so the case is monitored rather than fully allowed |
| `CANCELLED` | always | `MANUAL_REVIEW` (review item, priority 2) |
| `FAILED` | once attempts are exhausted | `MANUAL_REVIEW` |
| `EXPIRED` | once attempts are exhausted | `MANUAL_REVIEW` |
| `UNAVAILABLE` (provider down or timeout) | once attempts are exhausted | `MANUAL_REVIEW` (`fallback_used`) |

A non-terminal failure leaves the STEP_UP in force, and the client may request a new
challenge. **No step-up path ever produces `ALLOW`.**

### Immutability and "adapters never change the model"

* The follow-up is a new `risk_assessments` row: version n+1, `mode="step_up_followup"`,
  `supersedes_assessment_id` set to the original.
* It copies `ml_probability`, `calibrated_score`, `final_risk_score`, `risk_level`,
  `model_scores` and `triggered_rules` **verbatim**. No authentication adapter can
  change a model probability.
* The original row is never updated. Tests compare every column before and after.
* `action` records the follow-up policy, the method, the result, the attempt id and the
  note "authentication is additional evidence, not proof of legitimacy".

## 2. WebAuthn / passkeys

### What is stored

`webauthn_credentials`:

* the credential id (base64url);
* the **COSE public key**, the signature counter and transports;
* the user reference, status (`active` or `revoked`), `created_at` and `last_used_at`.

The private key never leaves the user's authenticator, so the platform cannot store it.

`authentication_challenges`:

* purpose (`registration` or `authentication`);
* the **SHA-256 of the challenge**, never the challenge itself;
* the user, session, assessment and API key it is bound to;
* `created_at`, `expires_at` and `consumed_at`.

### Challenge rules

* **Random:** 64 bytes from the library's CSPRNG (`secrets`).
* **Short-lived:** `WEBAUTHN_CHALLENGE_TTL`, default 120 s. An expired answer is recorded
  as `EXPIRED`.
* **Single use.** The challenge is consumed atomically with
  `UPDATE … SET consumed_at=now WHERE id=? AND consumed_at IS NULL`, and exactly one
  caller wins. Replays and concurrent duplicates get `CHALLENGE_INVALID`: of six
  parallel verifications, exactly one is processed (tested on SQLite and PostgreSQL). A
  challenge stays consumed even when verification fails.
* **Bound:**
  * to the assessment and its user;
  * to the **session** (the assessed event's `session_id` must match, and so must the
    verify call's);
  * to the **API key** that created it; another key cannot use it.

### Verification (py_webauthn)

1. The challenge inside the client's `clientDataJSON` is hashed and must match the stored
   hash (`challenge_mismatch` otherwise).
2. `verify_authentication_response` checks:
   * the signature over `authenticatorData || SHA-256(clientDataJSON)` with the stored
     public key;
   * the RP ID hash (`WEBAUTHN_RP_ID`) and the origin (`WEBAUTHN_ORIGIN`);
   * **user presence and user verification** (`require_user_verification=True`);
   * the **signature counter**. A regression suggests a cloned authenticator and gives
     `FAILED/sign_count_regression`.
3. On success, the counter and `last_used_at` are updated.

Any error is a recorded `FAILED` attempt with a reason:

* `malformed_credential`, `unknown_credential`, `session_mismatch`;
* `challenge_mismatch`, `verification_failed`, `sign_count_regression`.

Nothing authenticates silently.

**User handle and name.** The user handle is a one-way hash of the user id. The name shown
to authenticators is a pseudonym (`user-<hash>`). No personal data goes to the client.

**Registration** follows the same rules: a single-use, TTL-bound challenge; `"none"`
attestation accepted; user verification required; and duplicate credentials refused.
Registration requires the `webauthn:write` scope. The integrator is responsible for
making sure the user is authenticated *before* enrolling a passkey.

## 3. External payment authentication

### The adapter contract

```python
class PaymentAuthenticationProvider(Protocol):
    name: str
    def request_authentication(self, *, reference, token_reference, amount_minor, currency) -> ProviderResponse
    def get_status(self, provider_reference) -> PaymentAuthStatus
    def verify_callback(self, headers, body, *, now, max_age) -> CallbackEvent
```

A real integration would wrap a payment processor's authentication API; that is where
3-D Secure lives. fraud-ai only:

* **sends** the processor's token reference. It is stored as a keyed hash
  (`token_ref_hash`), and card data never enters the platform.
* **receives** a terminal status: `authenticated`, `failed`, `cancelled`, `timeout` or
  `unavailable`.

### `FakePaymentAuthProvider`: DEVELOPMENT FAKE

It is deterministic, and the token-reference suffix chooses the outcome:

| Suffix | Outcome |
|---|---|
| `-authenticated` (or none) | authenticated |
| `-failed` | failed |
| `-cancelled` | cancelled |
| `-timeout` | the provider hangs until the adapter timeout fires |
| `-unavailable` | the provider errors |

Every response carries `"note": "DEVELOPMENT FAKE - not 3-D Secure"`. Settings **refuse**
the fake in production. Since Stage 10, staging accepts it only with
`PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true`; the staging stack sets that, and its
documentation marks the provider as a fake. `simulate_callback()` produces the signed callback a
provider would send, for tests and demos.

### `StripePaymentAuthProvider`: Stripe TEST MODE (Stage 10)

**Status (Stage 12): REAL STRIPE TEST NOT PERFORMED.** This environment has no Stripe
test-mode credentials (`STRIPE_API_KEY` unset), and its network policy refuses
`api.stripe.com` (`CONNECT tunnel failed, response 403`). No request reached Stripe, and
none was faked as a success. The operator checklist below is what remains. The versions the adapter targets and was contract-tested with are the SDK `stripe`
**15.6.1**, pinned API version **`2026-08-26.dahlia`**.

**Status: implemented, not exercised against Stripe.** The code targets the official
`stripe` Python SDK (15.x) and Stripe's documented PaymentIntents and webhook APIs.

* **Why untested:** no Stripe test-mode credentials were available.
* **What is tested:** a stub client stands in for the API calls, and callback signatures
  are generated and verified by the SDK's own `WebhookSignature`.
* **What was not done:** no undocumented API was guessed, and no external call was faked
  as a success.

Enable it with:

* `PAYMENT_AUTH_PROVIDER=stripe`;
* `STRIPE_API_KEY` (`sk_test_`/`rk_test_` only; live keys are refused);
* `PAYMENT_AUTH_WEBHOOK_SECRET`: the endpoint's `whsec_…` signing secret;
* optionally, `STRIPE_RETURN_URL`.

Install the extra with `pip install -e ".[stripe]"`.

| Step | Behaviour |
|---|---|
| request | `PaymentIntent.create(amount, currency, payment_method=<pm_… token reference>, confirm=True, capture_method="manual", payment_method_options.card.request_three_d_secure="any")` with an idempotency key derived from the step-up reference. Nothing is captured. |
| `requires_action` | `pending`; `next_action = {"type": "stripe_authentication", "payment_intent", "client_secret"}` for Stripe.js `handleNextAction`. The client secret is returned once, never stored or logged (log redaction masks `pi_…_secret_…`). |
| `requires_capture` / `succeeded` (frictionless) or any other status | `pending` with `{"type": "wait", "stripe_status": …}`: only the signed webhook changes state |
| `CardError` (decline) | `failed` |
| network, API, rate-limit or other Stripe errors | provider **unavailable**, never an allow |
| webhook | `Stripe-Signature` verified by the SDK (tolerance `SIGNATURE_MAX_AGE`). Terminal events: `payment_intent.amount_capturable_updated` and `.succeeded` authenticate; `.payment_failed` fails; `.canceled` cancels. Other events get 200 `{"accepted": false, "status": "ignored"}`, and nothing changes. |

`tests/test_stripe_provider.py` covers:

* the valid flow;
* bad signature, expired, replayed and duplicate callbacks;
* an unknown reference;
* timeout and outage;
* declines;
* test-key enforcement.

### Operator checklist for the real Stripe test (not yet run)

Run this on a machine that can reach `api.stripe.com`, with a Stripe account in **test
mode**:

* **Test data only.** Use Stripe's documented test PaymentMethods (`pm_…`). Never type,
  send or store a card number, CVV or PIN anywhere in fraud-ai. The event contract refuses
  them, and the adapter only ever sends a `pm_…` token reference.
* **Live mode is refused.** The settings refuse any key that is not `sk_test_` or
  `rk_test_`. Do not work around that.

1. **Prerequisites.**
   * `pip install -e ".[stripe]"`.
   * The Stripe CLI, logged in to the test account (`stripe login`).
   * A restricted test key (`rk_test_…`) with write access to PaymentIntents only.
   * Record the SDK version (`python -c "import stripe; print(stripe.VERSION)"`) and the
     account's default API version. The adapter pins `2026-08-26.dahlia`.
2. **Webhook forwarding.** Run
   `stripe listen --forward-to https://<service>/v1/callbacks/payment/stripe` (or the
   127.0.0.1 URL). Copy the printed `whsec_…` into `PAYMENT_AUTH_WEBHOOK_SECRET`.
3. **Configuration.** Set these, then start the service and check that `/v1/ready` is
   `ready`:
   * `PAYMENT_AUTH_PROVIDER=stripe`;
   * `STRIPE_API_KEY=rk_test_…` (from a secret file, not the shell history);
   * `STRIPE_RETURN_URL` if used.
4. **Cases.** Score an event that gets `STEP_UP_AUTHENTICATION`, then
   `POST /v1/step-up/{id}/payment` with `token_reference` set to the test PaymentMethod.
   Take the PaymentMethod ids from Stripe's current testing page (docs.stripe.com/testing):

   | # | Test PaymentMethod | Expected |
   |---|---|---|
   | a | 3-D Secure required, then **completed** in the test challenge page | `pending` with `stripe_authentication`. After the webhook: attempt `SUCCESS`, and a follow-up assessment |
   | b | 3-D Secure required, then **failed** in the challenge | attempt `FAILED`. Another attempt is allowed; after the maximum, `MANUAL_REVIEW` |
   | c | frictionless (no challenge) | `pending` `wait`, then success only through the signed webhook |
   | d | declined card | `failed` (CardError), with no follow-up allow |
   | e | a `pm_…` id that does not exist | provider error, so `unavailable`; never an allow |

5. **Callback hardening with real deliveries.** Each must be refused and change nothing:
   * resend an event (`stripe events resend evt_…`): `REPLAYED_SIGNATURE` or
     `DUPLICATE_CALLBACK`;
   * change one byte of a captured body: `INVALID_SIGNATURE`;
   * deliver an event older than `SIGNATURE_MAX_AGE`: `EXPIRED_SIGNATURE`;
   * deliver `payment_intent.created`: `200 {"accepted": false, "status": "ignored"}`.
6. **Outage.** Point the service at a blocked network, or set `PAYMENT_AUTH_TIMEOUT=0.01`:
   the attempt must be `UNAVAILABLE`, and `next_action` must be
   `authentication_unavailable`.
7. **Clean-up.** Cancel any uncaptured PaymentIntents, since the adapter uses
   `capture_method=manual` and never captures. Revoke the restricted key. Delete the
   `stripe listen` secret.
8. **Evidence to record** in HARDENING.md, replacing the NOT PERFORMED status:
   * the date, SDK version and API version;
   * for each case: the PaymentIntent id, the attempt result and the follow-up decision;
   * the callback refusal codes;
   * confirmation that nothing about a card except the `pm_…` reference was sent.

### Timeouts and failures

* Every provider call runs in a worker thread with a hard timeout
  (`PAYMENT_AUTH_TIMEOUT`, default 5 s).
* A timeout or error records an **`UNAVAILABLE`** attempt and returns
  `next_action.type = "authentication_unavailable"`. It never allows.
* When attempts run out, the follow-up is `MANUAL_REVIEW` with `fallback_used`.

### Callback validation

In order:

The steps below describe the HMAC scheme of the fake provider. The Stripe adapter uses
`Stripe-Signature` through the SDK, then follows the same replay, reference and
state-transition rules.

1. `x-provider-id` must match the configured provider (`UNKNOWN_PROVIDER`).
2. The HMAC-SHA256 signature (`x-provider-signature`, keyed by
   `PAYMENT_AUTH_WEBHOOK_SECRET`) must match, and the timestamp must be within
   `SIGNATURE_MAX_AGE` (`INVALID_SIGNATURE` / `EXPIRED_SIGNATURE`).
3. The body must be well formed with a terminal status (`INVALID_CALLBACK`).
4. **Replay.** The signature is stored (or claimed in Redis with `STATE_BACKEND=redis`,
   Stage 10), so the same callback again gets 401 `REPLAYED_SIGNATURE`.
5. The provider reference must exist (404).
6. **State transition.** Only `pending` → terminal is allowed. A second, newly signed
   callback for a completed request gets 409 `DUPLICATE_CALLBACK`.

Then the attempt is recorded, together with the follow-up if it is terminal. Polling
(`GET /v1/step-up/payment/{id}`) is **read-only**: only a signed callback changes state.

## 4. Records

`authentication_attempts` is append-only. Each row holds:

* `assessment_id` and `attempt_number` (unique together);
* `method` (`webauthn` or `payment_authentication`);
* `result` (`SUCCESS`, `FAILED`, `EXPIRED`, `CANCELLED` or `UNAVAILABLE`);
* `failure_reason` and `credential_ref` (the credential id or provider reference);
* `challenge_id` / `payment_request_id`, `followup_assessment_id` and `created_at`.

`payment_auth_requests` holds the provider, the provider reference (unique per provider),
`token_ref_hash`, the status, the attempt number, and `created_at` / `completed_at`.

## 5. What is deliberately not here

* **Not implemented:**
  * no OTP, SMS or e-mail codes;
  * no cardholder authentication of any kind;
  * no issuer or ACS behaviour;
  * no custom challenge-response crypto.
* **Not claimed:** no claim that step-up reduces fraud by any amount. That can only be
  measured on real traffic with real labels.
* **Not built (by design):** no browser UI. The client ceremony is the integrator's page
  calling `navigator.credentials.*`. The test suite uses a TEST-ONLY software
  authenticator (EC P-256, `"none"` attestation) to drive real verification.

## 6. Operator authentication (Stage 12)

Before Stage 12, `OPERATOR_ID` was plain configuration: anyone who could run the CLI could
claim to be anyone. Stage 12 adds a **minimal real authentication boundary** for people
performing administrative actions. **It is not an IAM platform:** it has no user directory,
no SSO, no sessions and no password store.

### Mechanism: signed operator assertions

* Each operator has their **own Ed25519 key**. They keep the private key; only the public
  key is registered.
* The **registry** (`OPERATOR_REGISTRY_FILE`, JSON) lists each operator's id, **roles**
  and public keys. It is deployed as configuration: in staging, read-only at
  `/config/operators.json`.
  * A key belongs to exactly one operator.
  * Operator keys must differ from the model, audit and release keys
    (`operators registry-check`).
* For each action, the operator signs a short-lived **assertion**: a JWT (RFC 7519) signed
  with EdDSA (RFC 8037), in the manner of `private_key_jwt` (RFC 7523). Its claims:

| Claim | Meaning |
|---|---|
| `iss` = `sub` | the operator id; must be the owner of the signing key (`kid`) |
| `aud` | `OPERATOR_AUDIENCE` (default `fraud-ai-admin`) |
| `iat`, `nbf`, `exp` | lifetime at most `OPERATOR_ASSERTION_MAX_SECONDS` (default 300), leeway `OPERATOR_ASSERTION_LEEWAY_SECONDS` (30) |
| `jti` | single use: recorded in the append-only `operator_assertions` table (unique) |
| `act` | the action |
| `tgt` | the target (policy version, review id, key id, …) |
| `bnd` | a binding to the exact content (below) |

**Roles come from the registry, never from the token.** An assertion only proves *who*
signed it. What they may do is looked up afterwards.

| Action | Role | Target | Binding |
|---|---|---|---|
| `review.resolve` (API header `X-Fraud-Operator-Assertion`, or CLI) | `reviewer` | review id | `resolution` |
| `policy.approve` | `policy_approver` | policy version | `definition_sha256`, `note_sha256` |
| `policy.activate` | `policy_activator` | policy version | `definition_sha256` |
| `service_key.manage` (API key create, revoke, rotate) | `security_admin` | key name or id | – |
| `signing_key.rotate` (`keys rotate`, Vault only) | `security_admin` | purpose | – |
| `retention.execute` | `security_admin` | `retention` | `mode=execute` |
| `release.sign` | `security_admin` | git commit | `manifest_sha256` |
| `privacy.export` | `security_admin` | pseudonym | – |
| `operator.check` (`operators whoami`) | any role | `whoami` | – |

### Using it

```bash
fraud-ai operators keygen --id alice --out alice.pem          # prints the registry entry
fraud-ai operators registry-check                             # schema + key separation
fraud-ai policy approve risk-policy-1.1.0 --note "reviewed" --operator-key alice.pem
# or produce the assertion elsewhere (e.g. on a hardware-backed machine) and pass it:
fraud-ai operators assert --key alice.pem --id alice --action policy.approve \
    --target risk-policy-1.1.0 --bind definition_sha256=… --bind note_sha256=…
FRAUD_AI_OPERATOR_ASSERTION=<token> fraud-ai policy approve risk-policy-1.1.0 --note "reviewed"
```

`OPERATOR_AUTH_REQUIRED` defaults to **true in staging and production**. There, every
action above without a valid assertion is refused. The service refuses to start if the
registry is required but unreadable.

### Refusals

Each refusal is a stable code. The API returns 401 `OPERATOR_AUTH_REQUIRED` when the
assertion is missing. Otherwise it returns `OPERATOR_AUTH_FAILED` with the code in the
message: HTTP 403 for `FORBIDDEN`, 401 for everything else.

| Code | Cause |
|---|---|
| `BAD_ALGORITHM` | not EdDSA (`none`, HS256 and RS256 are refused) |
| `UNKNOWN_KEY` | the key is not in the registry |
| `OPERATOR_DISABLED` | the operator is disabled |
| `IDENTITY_MISMATCH` | the token names a different operator than the key's owner (**impersonation**) |
| `WRONG_AUDIENCE` | the token is for another audience |
| `EXPIRED_ASSERTION` | expired |
| `NOT_YET_VALID` | issued in the future |
| `LIFETIME_TOO_LONG` | lifetime above the maximum |
| `WRONG_ACTION`, `WRONG_TARGET`, `WRONG_BINDING` | a token for something else, e.g. approving another policy version or another note |
| `FORBIDDEN` | the operator lacks the role |
| `REPLAYED_ASSERTION` | the `jti` was already used |
| `MALFORMED_ASSERTION`, `INVALID_ASSERTION` | unparsable, or a bad signature |

### Two-person approval with authenticated principals

* An approval stores the verified operator id, the key id, the `jti` (unique index) and the
  **assertion itself** (`policy_approvals`, append-only).
* At activation, `EvidenceCheck` **re-verifies every stored assertion**. It checks the
  signature against the current registry, the action and target, the binding to the
  definition hash, and validity at the approval's own time. Only approvals that pass
  count:
  * two **distinct** operators are required: the same person twice is refused;
  * rows inserted directly into the database without a valid assertion do not count;
  * an approval whose operator was later disabled or removed does not count;
  * an expired approval (`POLICY_APPROVAL_TTL_HOURS`) does not count.
* The activator needs `policy_activator`. An approver cannot activate unless they hold that
  role too, which the staging registry does not grant.

### Audit

These events are audited:

* `operator.authenticated`: operator, key id, `jti`, action, target;
* `operator.authentication_failed`: the action, the target and the refusal code;
* `policy.approved` and `policy.activated`;
* `signing_key.rotated`;
* `audit.anchored` and `audit.anchor_failed`;
* `retention.executed`;
* `release.signed`;
* `privacy.exported`.

**Tokens, private keys and secrets are never logged or audited.** The audit layer refuses
detail keys that look like secrets.

### Limits

* Key custody is the operator's. A stolen operator key is a stolen identity until it is
  removed from the registry. Keep keys on hardware tokens where possible; that is not
  integrated.
* The registry file is trusted configuration. Whoever can change it can add operators, so
  protect it like the other public-key configuration (read-only mount, change control).
* No revocation list beyond editing the registry, no MFA, no SSO or OIDC.
