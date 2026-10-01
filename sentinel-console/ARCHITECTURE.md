# SENTINEL console architecture

## 1. Shape

```
 browser ──same origin──►  Next.js server (the console)  ──signed v2──►  fraud-ai service (/v1)
  React UI                  /api/fraud/*   allow-listed proxy
  (no secrets)              /api/reviews/{id}/resolve
                            /api/session   what the browser may know
                            /api/demo/*    DEMO MODE only ──► demo supervisor (scripts/demo.mjs)
                                                                 └─► fraud-ai demo reset | start
```

The console is a **backend-for-frontend**:

* **The browser talks only to the console's own server.** The CSP sets
  `connect-src 'self'`.
* **The console server holds the API key and its signing secret**, from the environment or
  0600 files. It signs every call with the service's v2 HMAC scheme. Neither value is sent
  to the browser, and a unit test checks that `/api/session` never contains them.
* **The fraud service decides everything.** The console does not score, apply policy,
  infer, review or authenticate. It displays what the service returns and forwards the
  analyst's resolution.

## 2. Server side (`src/lib/server`, `src/app/api`)

| Module | Role |
|---|---|
| `config.ts` | Reads the environment on every call, so a rotated credential file takes effect without a restart. A demo operator key outside DEMO MODE is ignored and reported. |
| `signing.ts` | The v2 canonical string and HMAC, byte-compatible with `fraud_ai/service/signatures.py`. It is tested against vectors produced by the Python code. `TimestampAllocator` never reuses a timestamp for an identical request, because the service refuses replayed signatures. |
| `backend.ts` | `callBackend()` adds the bearer credential and signature and applies timeouts. It maps failures to `BACKEND_NOT_CONFIGURED`, `BACKEND_UNREACHABLE` and `BACKEND_TIMEOUT`. `relay()` normalises errors to `{error: {code, message, status}}`. |
| `allowlist.ts` | The only routes the browser can reach, with per-route query-parameter patterns. `POST /v1/score`, step-up writes, key and policy administration are unreachable. The ID search accepts hex or a UUID only. |
| `request.ts` | Same-origin checks for every state-changing route, and a body size limit. |
| `assertion.ts` | **DEMO MODE only:** signs the demo reviewer's EdDSA assertion, bound to `review.resolve`, the review id and the resolution. It is verified by the Python verifier in the tests. |
| `demo.ts`, `demoControl.ts` | Read the demo catalogue and talk to the local demo supervisor. Both refuse outside DEMO MODE. The catalogue must be marked `synthetic`. |

Routes:

* `/api/fraud/[...path]`: the allow-listed proxy. It keeps `/v1/ready`'s check body when
  the service answers 503.
* `/api/reviews/[id]/resolve`: validates the body (the three outcomes, a note of at most
  500 characters, an optional assertion). In DEMO MODE it signs the demo assertion;
  otherwise it forwards the analyst's own.
* `/api/session`: the console version, environment, DEMO MODE, whether a backend is
  configured, the operator mode, and configuration problems.
* `/api/demo/{scenarios,scenarios/[label]/play,reset,status}`: DEMO MODE only. `play`
  scores the catalogue case through the real service, server-side. `reset` needs the typed
  `RESET DEMO` phrase and goes to the supervisor.

## 3. The supervisor (Stage 14: `scripts/localrun/`)

RESET DEMO has to stop the service, rebuild the database and start the service again. A
web server should not do that itself. Since Stage 14 one supervisor serves `sentinel-start`,
`npm run demo` (now a thin wrapper, `scripts/demo.mjs`) and the end-to-end tests. It:

* starts the service and the console, each under a lifeline that stops it if the supervisor
  disappears, and records each with its PID and creation time;
* serves `GET /status` and `POST /reset` (Demo only), plus `POST /shutdown`, on 127.0.0.1,
  on a random port, behind a random bearer token that only the console server and the local
  tooling (a 0600 file) know. The `/status` and `/reset` protocol is unchanged from Stage 13;
* runs a reset as stop → `fraud-ai demo reset` → start. `fraud-ai demo reset` is the
  existing guarded command: it refuses unless DEMO_MODE, the development profile, a
  `*_demo.db` database and the demo marker all hold;
* rewrites the credential files after a reset, because the demo world issues a new key;
* redacts API keys from everything it logs (`.runtime/logs/`).

See [../LOCAL_SETUP.md](../LOCAL_SETUP.md) and the repository's ARCHITECTURE.md §19.

## 4. Client side (`src/lib/api`, `src/features`, `src/components`)

* **One request layer (`lib/api/client.ts`).** It handles timeouts, retry of transient
  GET failures (never POSTs) and error classification: unavailable, timeout, unauthorised,
  forbidden, not found, conflict, rate limited (with Retry-After), invalid, LLM
  unavailable, server, schema. ESLint bans `fetch()` in components, features and pages.
* **Every response is parsed with Zod (`lib/api/schemas.ts`).** A shape the console does
  not understand becomes `SCHEMA_MISMATCH`; it is never rendered on a guess. A contract
  test parses real responses captured from the demo service.
* **Queries (`lib/api/queries.ts`) use TanStack Query.** Polling intervals:

  | Data | Interval |
  |---|---|
  | health, readiness | 10 s |
  | queue, feed | 5 s |
  | summary | 10 s |
  | system | 30 s |

  Polling stops while the tab is hidden. Structural sharing keeps unchanged rows
  referentially equal, and rows are memoised, so a poll re-renders only what changed.
* **Liveness (`lib/hooks/useLiveness.ts`)** labels every polled view LIVE, STALE (a failed
  poll, or data older than three intervals), OFFLINE or PAUSED. Stale data is labelled
  with its age and never shown as live.
* **System health (`features/system/groups.ts`, `features/system/checks.ts`)** is a pure
  function of `/v1/ready`, `/v1/analyst/system` and `/api/session`, and only of each
  source's latest successful poll. No answer means CHECKING; a failed source means
  OFFLINE. The start-up screen, top bar and Overview show the seven groups (`groups.ts`);
  the System page adds the detailed checks (`checks.ts`). The start-up screen leaves by
  itself only when every group is ONLINE or NOT USED.
* **Code splitting.** Pages are split per route by the App Router. The chart is loaded with
  `next/dynamic`.

## 5. Backend additions (Stage 13)

The console needed views the `/v1` API did not have. They were added to the service as
small, **read-only** endpoints under a new scope, `analyst:read`
(`fraud_ai/service/analyst.py`, tests in `tests/test_analyst_api.py`):

| Endpoint | Purpose |
|---|---|
| `GET /v1/analyst/feed` | recent assessments with review and step-up status |
| `GET /v1/analyst/reviews` | the queue joined with its assessments |
| `GET /v1/analyst/cases/{assessment_id}` | the case: reasons (from the catalogue), rule evidence, stored model scores, curated indicators, timeline, step-up, activity, latest investigation |
| `GET /v1/analyst/summary` | counts, latency percentiles, shadow agreement, hourly series |
| `GET /v1/analyst/system` | policy, models and signatures, migrations, security settings, audit chain and anchor, LLM runtime, reason catalogue |
| `GET /v1/analyst/search` | exact or prefix lookup of review, assessment and event IDs only |

They write nothing, and the tests assert that reading them creates no rows. They return
pseudonymous references only; the tests check a list of fields that must never appear.
Outcomes now also carry the verified `reviewer`. No scoring, policy or review logic
changed.

## 6. Security headers

| Header | Value |
|---|---|
| Content-Security-Policy | `default-src 'self'`, `connect-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'` |
| X-Frame-Options | DENY |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | no-referrer |
| Cross-Origin-Opener-Policy | same-origin |
| Permissions-Policy | camera, microphone, geolocation and payment disabled |

* Scripts are limited to `'self' 'unsafe-inline'`, which Next.js hydration needs.
* The development build also allows `'unsafe-eval'` for React's debugging tools; the
  production build does not.
* A test checks that the production client bundle contains no credential, key path or
  signing code.
