# Service security (Stages 9-12)

This document describes how the HTTP boundary protects the fraud engine and what it
deliberately does **not** claim. It is a research system on synthetic data. It is not
production-ready, not penetration-tested, not certified and not PCI-assessed.

Stage 10 and 11 additions are summarised here. The details, measurements and remaining
risks are in [HARDENING.md](HARDENING.md), [TRUST_CHAIN.md](TRUST_CHAIN.md) and
[THREAT_MODEL.md](THREAT_MODEL.md).

**Stage 11 in one paragraph.**

* **Requests:** signature **v2** binds method, path, query, timestamp and body digest, with
  downgrade protection (`SIGNATURE_MIN_VERSION`).
* **Models:** only models carrying a **trusted Ed25519 signature** load (required in
  staging/production). They are verified from the exact bytes that are deserialised.
* **Audit:** the chain is **anchored externally** under a separate key.
* **Policies:** activation can require **two different operators**.
* **Database:** the service can use a **least-privilege role** that cannot alter history.
* **Free text:** it is checked for personal data and secrets.

## 1. Threat model (summary)

| Threat | Control |
|---|---|
| unauthenticated callers | API keys on every non-health route; the same 401 for every failure |
| a stolen key used for the wrong purpose | per-key **scopes**, least privilege by default |
| key theft from the database | only salted SHA-256 hashes stored; secrets shown once |
| request tampering or replay | HMAC signatures with a timestamp window and **persisted** replay tokens |
| duplicate submission | `Idempotency-Key` plus Stage 8 `event_id` idempotency, backed by unique constraints |
| flooding | token-bucket rate limits per key and route; auth-failure throttling; size limits |
| a merchant whitewashing risk signals | intelligence fields need `signals:trusted` (422 otherwise) |
| spoofed client addresses | forwarding headers ignored unless the peer is a trusted proxy |
| information leakage | sanitised errors; safe response views; no ids in metrics; secrets never logged |
| cross-origin browser abuse | CORS disabled by default; no cookies; `no-store`; strict CSP |
| a dependency or the LLM failing | scoring never uses the LLM; failures fall back to `MANUAL_REVIEW`, never `ALLOW` |
| authentication bypass | standard WebAuthn verification (py_webauthn); challenges single-use, short-lived and bound; attempts capped |
| a fake or duplicate provider callback | provider signature, timestamp and replay token; a pending→terminal transition only |

## 2. API keys

* **Format:** `fak_<16 hex>.<43 url-safe characters>`. The id is public; the secret has
  256 random bits (`secrets.token_urlsafe(32)`).
* **Storage:** `service_api_keys` holds the key id, name, a per-key random salt,
  `SHA-256(salt:secret)`, scopes, `created_at` and `revoked_at`. **The plaintext secret is
  never stored.**
  * A fast hash is appropriate because the secret is high-entropy random data, not a
    password.
* **Verification:**
  * the comparison is `hmac.compare_digest` (constant time);
  * an unknown or malformed key still performs a hash and a comparison, so timing does
    not reveal which ids exist;
  * missing, malformed, unknown, wrong and revoked keys all get the identical 401
    `UNAUTHENTICATED` with `WWW-Authenticate: Bearer`.
* **Lifecycle:** `fraud-ai service-key create --name N --scope S … [--expires-in-days D]`
  prints the credential **once**.
  * `service-key list` shows ids, scopes, status (`active`/`expired`/`revoked`), expiry,
    last use and rotation parent, never secrets.
  * `service-key revoke <key-id>` takes effect on the next request (keys are checked
    against the database on every request).
  * `service-key rotate <key-id>` (Stage 10) issues a successor and expires the old key
    after `SERVICE_KEY_ROTATION_GRACE_HOURS`. The old secret is never shown again.
  * Create, revoke and rotate are written to the audit log.
* **Expiry (Stage 10):** an expired key gets exactly the same 401 as an unknown or revoked
  one; the reason is never disclosed. `last_used_at` is updated at most once a minute.
* **Logging:** the credential and the signing secret never appear in logs, errors or
  metrics. This is tested with `caplog` over key creation, valid, invalid and replayed
  requests.

### Scopes

| Scope | Allows |
|---|---|
| `score:write` | `POST /v1/score` |
| `score:replay` | a recorded `arrival_time` (backfill tooling only) |
| `signals:trusted` | network-intelligence fields (the operator's enrichment only) |
| `assessment:read` | assessment views |
| `review:read` / `review:write` | the review queue / resolving items |
| `policy:read` | active policy versions |
| `stepup:write` | WebAuthn and payment step-up |
| `webauthn:write` | passkey registration |
| `investigation:write` | analyst-triggered LLM explanations |
| `metrics:read` | Prometheus metrics |

Give a checkout backend `score:write assessment:read stepup:write` and nothing more.

## 3. Signatures and replay protection

* **Scheme:** `v1 = HMAC-SHA256(signing_secret, "<unix ts>." + raw_body)`. See
  [API.md](API.md) §3.
* **Per-key signing secret:** `HMAC-SHA256(SERVICE_SIGNING_MASTER_KEY, "fraud-ai-signing:"
  + key_id)`. It is recomputable by the server and never stored. Rotating the master key
  rotates every signing secret.
* **Key versions (Stage 10):**
  * `SERVICE_SIGNING_KEY_VERSION` names the current master key;
  * `SERVICE_SIGNING_PREVIOUS_KEY` (with its version and expiry) stays valid during a
    rotation grace period;
  * clients may send `X-Fraud-Key-Version`;
  * `fraud_api_signatures_verified_total{key_version}` shows when old-key traffic stops;
  * signatures required but no key configured gives 503 `SIGNING_UNAVAILABLE`.
* **Enforcement:**
  * `SERVICE_REQUIRE_SIGNATURES=true` makes signatures mandatory;
  * otherwise they are verified whenever the headers are present, so a bad signature is
    never ignored;
  * without a master key, signature headers are refused (400).
* **Checks:**
  * the timestamp must be within `SIGNATURE_MAX_AGE` in either direction;
  * the HMAC is compared in constant time.
* **Replay tokens:**
  * accepted signatures are stored in `request_replay_tokens` (a unique hash) **and
    committed before processing**;
  * a replay fails even if the first request later errored;
  * two concurrent replays cannot both pass (tested on SQLite and PostgreSQL);
  * expired tokens are pruned on insert.
  * **Stage 10:** with `STATE_BACKEND=redis`, the claim is an atomic Redis `SET NX` shared
    by every worker and instance, so exactly one accepts a signature. A Redis failure
    gives 503 `STATE_UNAVAILABLE`, never acceptance.
* **Signature v2 (Stage 11):** `v2=HMAC(secret, "fraud-ai-v2\nMETHOD\nCANONICAL_TARGET\n
  TIMESTAMP\nhex(SHA-256(body))")` binds the method, path and query. A header may carry both
  versions during a migration; only the strongest present is verified, with no fallback.
  Below `SIGNATURE_MIN_VERSION` the response is **401 `SIGNATURE_VERSION_REJECTED`**.
  The minimum defaults to `v2` in production and `v1` elsewhere. Canonicalisation is
  defined in [TRUST_CHAIN.md](TRUST_CHAIN.md) §2.

## 4. Rate limiting and request limits

* **Buckets:** one token bucket per (API key, method, route template):
  `RATE_LIMIT` (default `120/minute`) sustained, `RATE_LIMIT_BURST` (default 30) burst.
  Exceeding it returns 429 with `Retry-After`.
* **Identity:** the client address is **never** the identity for rate limits. It only
  throttles repeated authentication *failures* (abuse control).
* **Deployment scope:**
  * `InMemoryRateLimiter` is per process;
  * **Stage 10:** `SharedStateRateLimiter` over Redis (an atomic Lua token bucket using
    the server clock) shares buckets across workers and instances;
  * staging and production refuse several workers without it.
* **Request limits:**
  * `REQUEST_SIZE_LIMIT` (default 64 KiB). A `Content-Length` over it is refused before
    reading. Streamed or chunked bodies are counted and cut off. Both give 413.
  * The event contract then rejects:
    * unknown fields, event types and schema versions;
    * malformed UUIDs;
    * naive or future timestamps;
    * forbidden data.

## 5. Transport, headers and CORS

* **TLS is required in production.** The service speaks plain HTTP and must sit behind a
  TLS-terminating reverse proxy or load balancer (see [DEPLOYMENT.md](DEPLOYMENT.md)).
  Plain HTTP is acceptable only on localhost for development.
* **Security headers on every response:**
  * `X-Content-Type-Options: nosniff`;
  * `Cache-Control: no-store`;
  * `X-Frame-Options: DENY`;
  * `Referrer-Policy: no-referrer`;
  * `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`;
  * `Cross-Origin-Resource-Policy: same-origin`.
* **HSTS** is added only when `SERVICE_HSTS=true`, which you should set behind TLS.
* **Server header:** uvicorn's `Server` header is disabled.
* **CORS** is **disabled by default**. The API is machine-to-machine, and a browser should
  never hold an API key. `SERVICE_CORS_ORIGINS` enables it for listed origins only,
  without credentials.

## 6. Client addresses and network-signal integrity

* **Server-observed address:**
  * the TCP peer by default;
  * `X-Forwarded-For` or `Forwarded` are honoured **only** when the peer is in
    `TRUSTED_PROXIES`. The chain is then walked right to left, skipping trusted hops.
    A malformed chain falls back to the peer.
  * uvicorn runs with `proxy_headers=False`, so it never rewrites the peer from headers.
  * The address is not stored, logged or labelled in metrics.
* **Client claims:**
  * `metadata.network.ip`, ASN and country are what the merchant saw; they are features,
    as in Stages 1-8.
  * **Intelligence flags** (`is_known_vpn`, `is_tor`, `is_datacenter`, `is_known_proxy`,
    `proxy_confidence`, `network_type`, `is_mobile_network`, `intel_source`) change risk,
    so they are only accepted with `signals:trusted`. A merchant sending
    `"is_known_vpn": false` gets 422 `UNTRUSTED_SIGNAL`.
* **What the platform does not do:**
  * unmask VPN or proxy users;
  * fingerprint devices;
  * treat a VPN alone as fraud (the Stage 8 rules already refuse that).

## 7. Errors, logs and metrics

* **Errors** are always `{"error": {"code", "message", "correlation_id"}}`.
  * Validation errors name fields and never echo input values; ids in messages are
    redacted.
  * An unexpected exception becomes `500 INTERNAL_ERROR "internal error"`. Only its
    *type* is logged, with the correlation id. There are no tracebacks, SQL, paths or
    secrets in responses (tested).
* **Correlation ids:** a client value is reused only if it matches `[A-Za-z0-9._-]{8,64}`,
  so log injection is impossible. Otherwise a uuid is generated.
* **Logs:** access logs are off because they would carry client addresses. Decision logs
  are the Stage 8 pseudonymised JSON lines.
* **Metrics:** labels are route templates, methods, statuses and enum values only. They
  never carry event, user, assessment or key ids, or addresses (tested).

## 8. Failure safety

| Failure | Result |
|---|---|
| scoring exceeds `SERVICE_REQUEST_TIMEOUT` | 503 `SCORING_TIMEOUT`, `fallback_decision: MANUAL_REVIEW` |
| database unavailable | 503 `SCORING_UNAVAILABLE`, `fallback_decision: MANUAL_REVIEW` |
| a model, policy or calibration problem | Stage 8 fallbacks (never `ALLOW`) |
| payment provider down or timeout (`PAYMENT_AUTH_TIMEOUT`) | an `UNAVAILABLE` attempt; `authentication_unavailable`; review once attempts are exhausted |
| WebAuthn verification error | a `FAILED` attempt (never silent success) |
| LLM missing, down or slow | 503 `LLM_UNAVAILABLE` / 504 on the investigate endpoint only |
| database down before scoring (auth, idempotency) or pool exhausted (Stage 10) | 503 `DATABASE_UNAVAILABLE`, sanitised, with `Retry-After` |
| Redis down with `STATE_BACKEND=redis` (Stage 10) | 503 `STATE_UNAVAILABLE` |
| signatures required, no signing key (Stage 10) | 503 `SIGNING_UNAVAILABLE` |
| invalid configuration or failed readiness at start-up (Stage 10) | the worker refuses to start |

The full fail-closed matrix is in [HARDENING.md](HARDENING.md) §8.

**SQLite concurrency.** SQLite has one writer. The service serialises every write on the
engine's process-wide write lock, shared with the Stage 8 scorer, which avoids SQLite's
immediate "database is locked" deadlocks. SQLite is a single-process development backend.
Use PostgreSQL for anything concurrent or multi-process: there the unique constraints
decide races.

## 9. Secrets and configuration

Production secrets come only from the environment, from files (`NAME_FILE`, Stage 10),
or from a secret manager. No secret has a default.

| Secret | Notes |
|---|---|
| `PSEUDONYMISATION_KEY` | required outside development/test |
| `SERVICE_SIGNING_MASTER_KEY` | at least 32 characters |
| `PAYMENT_AUTH_WEBHOOK_SECRET` | at least 32 characters; required with a provider |
| `SERVICE_SIGNING_PREVIOUS_KEY` | rotation only; needs a version and an expiry |
| `STRIPE_API_KEY` | test-mode keys only (`sk_test_`/`rk_test_`) |
| `REDIS_URL`, `DATABASE_URL` | treated as secrets (they carry passwords) |

Staging and production refuse:

* the fake payment provider (staging may opt in with
  `PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true`; production never);
* a non-https `WEBAUTHN_ORIGIN` (the service refuses to start; batch and CLI jobs are unaffected);
* SQLite;
* **Stage 10:**
  * default- or placeholder-looking secrets and database/Redis passwords;
  * CORS `*` or non-https origins;
  * several workers with per-process state.
* **Stage 10, production only:**
  * the reference LLM template (unless `ALLOW_REFERENCE_LLM`);
  * unsigned requests.

The Docker image contains no secrets, `.env` files, databases, models or LLM weights.

## 10. Known limitations (not claimed)

* **Not in scope yet:**
  * no mTLS between merchant and service;
  * no *automatic* key rotation (expiry and `rotate` exist since Stage 10);
  * no per-tenant data isolation (one tenant per deployment);
  * no WAF or bot protection.
* **Retention:** short-lived records have opt-in retention jobs since Stage 10
  (HARDENING.md §9). Core records have no retention policy.
* **Assurance:** the security tests are unit and integration tests, not a penetration
  test. No compliance certification (PCI DSS, GDPR, SOC 2, ISO, …) is claimed.
* **Database role (Stage 11):** run the service as `fraud_service` (DEPLOYMENT.md §2b). It
  cannot drop, alter or truncate tables, disable triggers, create objects or roles, or
  update or delete history rows. This is verified against PostgreSQL by
  `tests/test_pg_privileges.py`.
* **Stage 12:**
  * The staging service runs as `fraud_service` (`db check-privileges`: 28 probes, 0
    unexpected rights). It holds **no** Vault token, S3 credential or private key: signing
    and anchoring run in separate `ops` and `anchor` containers.
  * Review resolution needs the reviewer's own signed operator assertion
    (`X-Fraud-Operator-Assertion`, API.md §7). The API key identifies the calling system,
    never the person.
  * The service refuses to start when operator authentication is required and the
    registry is missing or unreadable.
  * Not in scope: mTLS, SSO/OIDC, hardware-backed operator keys.
