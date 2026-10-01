# Project status

**SENTINEL — Fraud Intelligence & Response** (`fraud-ai` backend + `sentinel-console`).

| | |
|---|---|
| Current release | **`v0.15.0-rc1`**: final portfolio release candidate (not v1.0, not production) |
| Build stages | 1–15 complete; no further stage is planned |
| Branch | `claude/tender-lovelace-lplx5d` |
| Release commit | the commit tagged `v0.15.0-rc1` |
| Signed release manifest | `release/v0.15.0-rc1.json`, signed for the release commit and added by the release-record commit that follows it |
| Data | synthetic only |

## What works

* **One-command local run** on Windows (PowerShell 7 and 5.1), Linux and macOS:
  `setup-local`, then `sentinel-start` in Demo (SQLite, no Docker), Dev (Docker PostgreSQL
  and Redis) or StagingLike (the staging stack); `sentinel-status`, `sentinel-reset-demo`,
  `sentinel-stop`.
* **The fraud-decision service:** signed and replay-protected API, point-in-time features,
  signature-verified models, calibration, rules, a versioned policy, immutable
  assessments, the review queue, WebAuthn and payment step-up, the anchored audit log,
  two-person policy activation, least-privilege database roles.
* **The SENTINEL console:** start-up checks, overview, live feed, review queue, case
  workspace (timeline, reasons, model comparison, analyst assistance, resolution), system,
  metrics and demo pages.
* **A deterministic demo** with ten measured cases and a 5–8 minute interview script
  ([DEMO.md](DEMO.md)).

## Verification status (at the release commit)

| Check | Result |
|---|---|
| CI (7 jobs: lint, test, security, container, console, local-scripts, local-windows) | run on the release commit; the run id and result are recorded by the release-record commit that follows it |
| Backend tests (SQLite, PostgreSQL 16, Redis, least-privilege roles) | 1,140 passed, 4 skipped (need a live Vault or signed-image evidence); coverage 95.8 % (gate 95 %) |
| Console | ESLint, TypeScript, 144 Vitest tests, production build; Playwright 2/2 with a WCAG 2.1 AA audit of 8 views |
| Security scans | pip-audit, bandit, detect-secrets, gitleaks, SBOM, Trivy: see the CI security and container jobs |
| Container image | built, signed with cosign, SLSA provenance and SBOM attested, verified; a tampered image is refused (CI container job) |
| Fresh-clone acceptance | setup → Demo → console walkthrough → reset → stop, on Linux (this project's sandbox) and in CI on Linux and Windows |

## Known limitations

Synthetic data only; most demo fraud is allowed at the hand-set bands; no real Stripe test;
the small local LLMs failed the structured-output benchmark, so the reference template is
the default; no penetration test or external review; single-host load and staging tests;
operator keys are files; erasure designed but not executed; base-image CVEs without
upstream fixes; a weaker check-to-open guarantee on Windows. Details:
[PORTFOLIO.md §10](PORTFOLIO.md#10-limitations).

## How to start it

```bash
./scripts/setup-local.sh && ./scripts/sentinel-start.sh --mode demo   # Linux / macOS
```

```powershell
.\scripts\setup-local.ps1; .\scripts\sentinel-start.ps1 -Mode Demo    # Windows
```

Then open `http://127.0.0.1:3000`. More: [LOCAL_SETUP.md](LOCAL_SETUP.md).

## Future optional work

Only in response to real feedback, not as new stages:

* a real labelled dataset (label delay, selection bias, re-derived bands, shadow mode first);
* a real payment-authentication (3-D Secure) integration test;
* an external security review or penetration test;
* hardware-backed operator keys and single sign-on; multi-analyst case assignment;
* a multi-host deployment test; erasure execution with its missing safeguards;
* a larger or GPU-hosted local LLM with constrained decoding.

For a new developer or AI agent: [HANDOFF.md](HANDOFF.md).
