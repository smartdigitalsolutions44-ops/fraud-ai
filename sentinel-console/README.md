# SENTINEL — Fraud Intelligence & Response

**SENTINEL // Analyst Console** is the analyst interface for the `fraud-ai` service (Stage 13).
It is a Next.js, React and TypeScript application. It is a **client** of the existing
`/v1` API and duplicates none of the backend's logic: no scoring, risk policy, model
inference, review logic or authentication happens in the console.

![Case workspace](docs/screenshots/04-case.png)

| | |
|---|---|
| Start-up checks | ![Start-up](docs/screenshots/01-startup.png) |
| Overview | ![Overview](docs/screenshots/02-overview.png) |
| Review queue | ![Queue](docs/screenshots/03-queue.png) |
| Model comparison and investigation | ![Models](docs/screenshots/05-model-comparison.png) |
| System health | ![System](docs/screenshots/06-system.png) |

All screenshots show the **synthetic demo world** only. They are captured by the end-to-end
test (`npm run screenshots`).

## What it does

| Page | What it shows | Source |
|---|---|---|
| Start-up | the seven readiness checks: CHECKING, then ONLINE / DEGRADED / OFFLINE (or NOT USED) | `/v1/ready`, `/v1/analyst/system` |
| Overview | assessments, review queue, step-up, temporary blocks, fallbacks, latency, primary model, decision distribution, recent flagged assessments, model disagreement, backlog, system health | `/v1/analyst/summary`, `/feed`, `/system` |
| Live Feed | every assessment, newest first; polled every 5 s; can be paused | `/v1/analyst/feed` |
| Review Queue | filters (decision, reason, age, step-up, safe ID) and sorts (priority, newest, oldest); opens the case workspace | `/v1/analyst/reviews` |
| Case workspace | timeline (left), evidence, models, indicators and investigation (centre), analyst decision, step-up and audit trail (right) | `/v1/analyst/cases/{id}` |
| Investigations | lookup by case, assessment or event ID; recent cases | `/v1/analyst/search` |
| Metrics | operational metrics and an accessible hourly chart | `/v1/analyst/summary` |
| System | readiness, models and signatures, active policy and bands, security controls, audit chain and anchor, LLM runtime | `/v1/analyst/system`, `/v1/ready` |
| Demo (DEMO MODE only) | the ten deterministic scenarios, scoring them, and a guarded RESET DEMO | the demo catalogue, `/v1/score` (server-side), `fraud-ai demo reset` |

What it deliberately does **not** do:

* **Invent data.** Business metrics such as "money saved" or "fraud prevented" are not
  measured by the service, so none are shown.
* **Derive scores.** There is no consensus or combined model score. Each model is shown
  against its own threshold, and disagreement is stated, not resolved.
* **Explain beyond the service.** Reason codes are described only by the service's own
  catalogue.
* **Change the platform.** No policy, model or key can be changed from the console.
* **Assign cases.** The service has no case assignment, so the console does not pretend to
  have one.

## Running it

```bash
# The demo: the synthetic world, the real service and the console in DEMO MODE
cd sentinel-console
npm ci
npm run demo            # needs the Python package: pip install -e ".[dev]" at the repo root
# → http://127.0.0.1:3000
```

`npm run demo` runs `scripts/demo.mjs`, which:

1. runs the existing, guarded `fraud-ai demo reset` if no demo world exists;
2. starts `fraud-ai demo start` on 127.0.0.1:8080;
3. starts the console in DEMO MODE on 127.0.0.1:3000, passing the demo API key through
   0600 files that only the console server reads;
4. listens on a local control endpoint (random port, random bearer token). RESET DEMO
   reaches it through the console server.

Options: `DEMO_ROOT`, `PYTHON`, `FRAUD_API_PORT`, `CONSOLE_PORT`, `CONSOLE_MODE=start`
(serves `npm run build` output) and `DEMO_RESET_ON_START=true`.

Against any other fraud-ai service:

```bash
export FRAUD_API_BASE_URL=https://fraud-api.internal
export FRAUD_API_CREDENTIAL_FILE=/run/secrets/console-api-key        # scopes below
export FRAUD_API_SIGNING_SECRET_FILE=/run/secrets/console-signing-secret
export SENTINEL_ENVIRONMENT=staging
npm run build && npm start
```

| Variable | Meaning |
|---|---|
| `FRAUD_API_BASE_URL` | the service (default `http://127.0.0.1:8080`) |
| `FRAUD_API_CREDENTIAL` / `_FILE` | the console's API key. It stays in the server process |
| `FRAUD_API_SIGNING_SECRET` / `_FILE` | its v2 request-signing secret. It stays in the server process |
| `FRAUD_API_TIMEOUT_MS` | default timeout for calls to the service (10 000) |
| `SENTINEL_ENVIRONMENT` | the label shown in the UI |
| `SENTINEL_DEMO_MODE` | `true` only for the synthetic demo world |
| `SENTINEL_DEMO_ROOT`, `SENTINEL_DEMO_CONTROL_URL`, `SENTINEL_DEMO_CONTROL_TOKEN` | set by `npm run demo` |
| `SENTINEL_OPERATOR_ID`, `SENTINEL_OPERATOR_KEY_FILE` | **DEMO MODE only**: the demo reviewer key. Ignored, and reported, outside DEMO MODE |
| `SENTINEL_OPERATOR_AUDIENCE` | the operator-assertion audience (default `fraud-ai-admin`) |

### The console's API key

Create the key with the scopes below. Nothing else is needed:

```bash
fraud-ai service-key create --name sentinel-console --expires-in-days 90 --show-signing-secret \
  --scope analyst:read --scope assessment:read --scope review:read --scope review:write \
  --scope policy:read --scope investigation:write
```

`analyst:read` is new in Stage 13. It is read-only and covers `GET /v1/analyst/*`.

### Resolving reviews

* **DEMO MODE:** the console server signs a reviewer assertion with the demo operator
  `rita`'s key. The UI says so wherever this happens.
* **Everywhere else:** the console holds no operator key. Each resolution needs the
  analyst's own single-use assertion. The confirmation dialog shows the exact command:

  ```bash
  fraud-ai operators assert --key YOUR_KEY --id YOUR_ID --action review.resolve \
    --target <review_id> --bind resolution=<resolution>
  ```

The service verifies the assertion, records the verified reviewer (`operator:<id>`) and
refuses to rewrite a resolved outcome. The console shows that outcome as final.

## Keyboard

| Key | Action |
|---|---|
| <kbd>Ctrl</kbd>/<kbd>⌘</kbd> <kbd>K</kbd> | command palette: go to a page, look up an ID, refresh, density |
| <kbd>J</kbd> / <kbd>K</kbd> | next / previous row. Inside a queue case: next / previous case |
| <kbd>Enter</kbd> | open the selected row |
| <kbd>Esc</kbd> | close a dialog, clear the selection, or return to the queue |
| <kbd>R</kbd> | inside a case: run the investigation (analyst assistance; changes no decision). Elsewhere: refresh the data |

No single key performs an irreversible action. Resolutions and RESET DEMO always need a
button and a confirmation. RESET DEMO also needs the typed phrase.

## Development

```bash
npm run dev          # next dev (needs FRAUD_API_* in the environment)
npm run lint         # eslint (next core-web-vitals + typescript); fetch() is banned outside src/lib/api
npm run typecheck    # tsc --noEmit (strict, noUncheckedIndexedAccess)
npm test             # vitest: unit, component, API client, server routes, contract
npm run build        # production build
npm run e2e          # Playwright against a freshly reset demo world (build first)
npm run screenshots  # the same, writing docs/screenshots/*.png
```

The tests (`tests/`) cover:

* **Contract:** responses captured from the running demo service must parse with the
  console's schemas.
* **Signing:** the TypeScript v2 signer matches vectors produced by the Python service.
  The demo assertion is accepted by the Python verifier when it is importable.
* **Proxy:** the allow-list, same-origin checks, unconfigured and unreachable backends.
* **Session:** the session never exposes secrets.
* **Demo guards:** every demo control is refused outside DEMO MODE; reset needs the phrase.
* **Honest states:** CHECKING until answered; OFFLINE when unreachable; degraded audit
  anchor; permission denied.
* **Error states:** service unavailable, rate limited, not found, LLM unavailable, timeout,
  schema mismatch.
* **Components:**
  * no consensus score;
  * reason descriptions come only from the service;
  * confirmation is required and a resolution submits once;
  * a resolved case is final;
  * the command palette holds no dangerous commands.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the console is built and
[DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) for the visual language.
