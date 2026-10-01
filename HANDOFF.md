# Handoff

Everything a new developer or AI agent needs to work on this repository without the old
conversation history. Keep it short and current. No secrets belong here.

## What this is

**SENTINEL — Fraud Intelligence & Response**: a real-time fraud-decision service
(`fraud-ai`, Python) and its analyst console (`sentinel-console/`, Next.js). Portfolio
project on synthetic data; release candidate `v0.15.0-rc1`; branch
`claude/tender-lovelace-lplx5d`. The planned build (Stages 1–15) is complete; see
[PROJECT_STATUS.md](PROJECT_STATUS.md). New work should come from real users, data,
integrations or a security review, not from new stages.

## Architecture in one paragraph

A merchant sends a signed `POST /v1/score`. The FastAPI service (`fraud_ai/service/`)
authenticates the key, checks the HMAC v2 signature and replay claim, validates the event
(`fraud_ai/core/events.py`), ingests it with its arrival time (`ingestion/`), computes 107
point-in-time features (`features/`), scores it with signature-verified cached models
(`models/`, `realtime/cache.py`), calibrates, evaluates rules (`rules/`), applies the
active immutable policy (`risk/`), and writes an immutable assessment
(`realtime/service.py`). MANUAL_REVIEW creates a review item; STEP_UP runs WebAuthn or an
external payment-auth adapter (`stepup/`), whose result is a *new* assessment. The console's
server (backend-for-frontend) signs read-only `/v1/analyst/*` calls; the browser never sees
a credential. A local LLM layer (`llm/`) explains stored evidence on request and never
decides. Trust: Ed25519 signing (`trust/`), hash-chained audit log with external anchors
(`audit.py`), operator authentication and two-person policy approval (`risk/approvals.py`),
least-privilege PostgreSQL roles, Redis shared state (`state/`).

## Important directories

| Path | Contents |
|---|---|
| `fraud_ai/` | the backend package (see the paragraph above) |
| `fraud_ai/cli/` | the `fraud-ai` CLI ([CLI.md](CLI.md)) |
| `fraud_ai/demo/` | the deterministic demo world and its reset guard |
| `migrations/` | Alembic migrations (10) |
| `tests/` | pytest suite (SQLite always; PostgreSQL and Redis when available) |
| `sentinel-console/src/` | the console: `app/` routes and BFF API routes, `features/`, `components/`, `lib/api` (client, Zod schemas, queries), `lib/server` (signing, allow-list) |
| `sentinel-console/tests/`, `e2e/` | Vitest tests; the Playwright analyst flow (also writes the screenshots) |
| `scripts/localrun/` | the local run tooling behind `setup-local` and `sentinel-*` (`.ps1` and `.sh` wrappers in `scripts/`) |
| `deploy/staging/` | the staging stack (Docker Compose, Vault, Caddy TLS, RustFS Object Lock) |
| `.github/workflows/ci.yml` | CI: lint, test, security, container, console, local-scripts, local-windows |
| `release/` | signed release manifests |
| `.runtime/`, `data/`, `models/`, `evaluation/` | local runtime state and generated artefacts; git-ignored, never commit |

## Key commands

```bash
./scripts/setup-local.sh                      # once (Windows: .\scripts\setup-local.ps1)
./scripts/sentinel-start.sh --mode demo       # service :8080 + console :3000, synthetic world
./scripts/sentinel-status.sh
./scripts/sentinel-reset-demo.sh              # type RESET DEMO
./scripts/sentinel-stop.sh
./scripts/sentinel-start.sh --mode dev        # Docker PostgreSQL + Redis
fraud-ai --help                               # the backend CLI (inside .venv)
```

## Test commands

```bash
scripts/check.sh                                         # ruff, format check, mypy strict, pytest
TEST_POSTGRES_URL=postgresql+psycopg://…/fraud_ai_test \
TEST_PG_ADMIN_URL=postgresql+psycopg://…/postgres \
python -m pytest -q --cov=fraud_ai --cov-fail-under=95   # what CI runs (redis-server must be on PATH)
python -m pytest -q tests/test_localrun.py tests/test_windows_files.py   # local tooling
cd sentinel-console && npm ci && npm run lint && npm run typecheck && npm test && npm run build
cd sentinel-console && npm run e2e                       # Playwright on a fresh demo world (ports 8181/3100)
cd sentinel-console && npm run screenshots               # the same, writing docs/screenshots/
python scripts/security_checks.py pip-audit|bandit|secrets|sbom
```

## Security invariants (do not break these)

1. **The LLM never scores, decides, blocks or changes labels, thresholds, rules or
   policies.** It only explains stored evidence, cites it, and is validated before storage.
2. **Assessments are immutable.** Step-up results and resolutions create new records.
3. **Models load only after their digest and Ed25519 signature are verified** over the exact
   bytes loaded; staging and production refuse unsigned models.
4. **Requests outside development are signed (v2) and single-use.** Replay claims are
   atomic; if Redis is unavailable the service fails closed (503), never open.
5. **Every failure is conservative.** An unavailable database or model means "not decided"
   or a stricter decision, never ALLOW.
6. **Operator identity comes from a signed, single-use assertion and the operator registry,
   never from the request.** Policy activation needs two distinct authenticated approvers
   plus an activator; approvals are re-verified at activation.
7. **The browser never holds an API key, signing secret or operator key.** The console's
   server signs; its proxy is allow-listed.
8. **No PAN, CVV or PIN is ever stored.** Free-text PII rules and keyed pseudonyms apply;
   exports redact nested keys.
9. **The demo reset only touches a demo database** (`*_demo.db` / `*_demo`, first audit event
   `demo.world_created`, `DEMO_MODE=true`, development/test profile).
10. **The local tooling only stops processes it started** (PID plus creation time).
11. **Windows-only branches never weaken POSIX behaviour** (`fraud_ai/utils/winfs.py`).
12. **Never skip, disable or loosen a test or a CI gate to get green.** CI steps run with
    `pipefail`.

## Current limitations

Synthetic data only; most demo fraud is allowed at the hand-set bands; no real Stripe test;
the small local LLMs failed the structured-output benchmark (the reference template is the
default); no penetration test; single-host load and staging tests; operator keys are files;
erasure designed but not executed; documented base-image CVEs without upstream fixes; a
weaker check-to-open guarantee on Windows. Full list:
[PORTFOLIO.md §10](PORTFOLIO.md#10-limitations).

## Where to look next

[PROJECT_STATUS.md](PROJECT_STATUS.md) (state and verification) ·
[docs/ai-workflow.md](docs/ai-workflow.md) (low-context workflow and escalation template) ·
[ARCHITECTURE.md](ARCHITECTURE.md) · [TRUST_CHAIN.md](TRUST_CHAIN.md) ·
[LOCAL_SETUP.md](LOCAL_SETUP.md) · [DEMO.md](DEMO.md)
