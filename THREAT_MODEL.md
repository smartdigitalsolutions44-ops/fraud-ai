# Threat model (Stage 10)

This is the threat model for the fraud-ai service, a **deployment-hardened prototype**, as
deployed in `deploy/staging/`. It lists what an attacker could want, how, what the code
does about it, and what remains.

"Remaining risk" is honest, not exhaustive. Nothing here claims PCI DSS, GDPR or SOC 2
compliance, and no penetration test has been done.

## Scope and trust boundaries

```text
merchant backend ──TLS──▶ reverse proxy ──(private net)──▶ fraud-ai workers ──▶ PostgreSQL
payment provider ──TLS──▶ (callbacks)                           │            ──▶ Redis
operators ──shell/CLI (fraud-ai …)──────────────────────────────┘            ──▶ model files (ro)
                                                                             ──▶ local LLM (optional)
```

**Trusted:**

* the host and the orchestrator;
* the PostgreSQL and Redis instances on the private network;
* operators with CLI access;
* the model directory, which is mounted read-only.

**Untrusted:**

* anything arriving over HTTP, including authenticated merchants beyond their scopes;
* provider callbacks until their signature has been verified;
* LLM output.

## Assets

| Asset | Why it matters |
|---|---|
| A1 Scoring decisions and assessment history | Fraud outcomes; an attacker wants ALLOW for fraud |
| A2 API keys and the signing master key | Impersonating a merchant integration |
| A3 Pseudonymisation key | Re-identifying hashed IPs, devices and addresses |
| A4 Payment step-up state and webhook secret | Forging a successful step-up |
| A5 Policies, models, calibrations, deployments | Silently changing decisions |
| A6 Audit log | Hiding administrative actions |
| A7 Personal data (pseudonymous ids, hashed identifiers, optional raw IP) | Privacy |
| A8 Availability | Denial of fraud checks becomes an ALLOW if callers fail open |

## Threats, mitigations and remaining risk

| # | Asset | Threat | Mitigation (implemented) | Remaining risk |
|---|---|---|---|---|
| T1 | A2 | Stolen API key used from elsewhere | Per-key scopes; optional expiry; rotation with grace; revocation; `last_used_at` tracking; auth-failure metrics and alerts; required request signatures in production (a stolen bearer token alone is not enough) | A key plus its signing secret stolen together (e.g. from the merchant host) works until revoked; no IP allow-listing or mTLS |
| T2 | A2 | Guessing or enumerating keys | 256-bit random secrets, salted SHA-256, constant-time compare, identical 401 for unknown/expired/revoked, rate limiting | – |
| T3 | A1 | Replay of a captured signed request | 300 s timestamp window; single-use claim per signature (Redis `SET NX` across workers, DB table single-process); Idempotency-Key | v1 signature excludes method/path. The single-use claim prevents reuse, but a MITM able to *intercept before delivery* could redirect a body to another route (needs TLS broken) → v2 signature |
| T4 | A4 | Forged or replayed payment callback | HMAC (fake) / Stripe SDK signature verification with tolerance; replay claim; unknown references 404; non-terminal events ignored; terminal state is final | Webhook secret compromise allows forging until rotated (DISASTER_RECOVERY.md) |
| T5 | A1 | Flooding to exhaust capacity so the merchant fails open | Per-key and per-route distributed rate limit; request size and time limits; pool timeout gives 503; documented "do not fail open" contract for callers | No global/adaptive DoS protection; a caller that treats 503 as ALLOW defeats the system (integration responsibility) |
| T6 | A1/A8 | Redis or DB outage used to bypass checks | Fail closed: 503 `STATE_UNAVAILABLE` / `DATABASE_UNAVAILABLE`; readiness fails (section 8 of HARDENING.md) | Availability loss during the outage |
| T7 | A5 | Tampered model artefact (backdoored pickle) | SHA-256 recorded at training and verified before unpickling; readiness re-verification; `torch.load(weights_only=True)`; read-only mount | Time-of-check/time-of-use between hashing and `joblib.load` for someone with write access to the model directory; pickle remains code execution if the digest record itself is altered in the DB |
| T8 | A5 | Unauthorised or unsafe policy change | CLI-only activation (no API); feature-version, calibration and artefact checks; promotion shadow → evaluation → candidate with approval in staging/production; activator stored and audited | Operators with DB write access can bypass the CLI; no two-person rule |
| T9 | A6 | Rewriting audit history | Hash chain; UPDATE/DELETE triggers; `audit verify` detects edits and gaps | A DB superuser can drop the triggers and rebuild a consistent chain → anchor the chain head externally (Stage 11) |
| T10 | A3/A7 | Re-identification of pseudonymised data | HMAC with a secret key (not plain hashes); raw IP off by default and 30-day retention; logs redact IPs | Key compromise allows dictionary attacks on IPv4 space; no key-rotation tooling (would break linkage) |
| T11 | A2/A3 | Secrets leaking through logs, errors, images, git | `SecretStr`; log redaction (keys, bearer tokens, signatures, provider secrets, URL passwords); sanitised errors with correlation ids; image checks (no secrets in env/history); gitleaks + detect-secrets in CI; `*_FILE` secrets | Secrets in process environment are visible to anyone with host/container access; prefer `*_FILE` |
| T12 | A1 | Spoofed client IP to evade network features | `X-Forwarded-For`/`Forwarded` honoured only from `TRUSTED_PROXIES`; network signals marked untrusted unless the key has `signals:trusted` | A compromised trusted proxy can spoof |
| T13 | A1 | Prompt injection via event data into the LLM | LLM is analyst-only; never scores or decides; output validated/grounded; evidence redacted; endpoint restricted to loopback/private | Misleading explanations to analysts remain possible |
| T14 | A7 | Personal data exposure through metrics | No personal data, key ids or IPs in labels (bounded label sets) | – |
| T15 | all | Vulnerable dependencies / base image | pip-audit (0 findings), bandit (0), Trivy report, SBOM; installers removed from the image | 8 unfixed Debian CVEs in the base image (not reachable via the service); rebuild when patched |
| T16 | A8 | Configuration mistakes in production (fake provider, default secrets, http origins, CORS *) | Fail-closed profile validation at start-up (HARDENING.md section 6); `fraud-ai config check` | Checks catch known-bad patterns, not every misconfiguration |
| T17 | A4 | Cardholder data captured by the service | Only provider token references and non-sensitive card attributes; PAN/CVV/PIN keys and card-like numbers redacted before storage; Stripe adapter never receives card numbers | Merchants could put card data in free-text fields not recognised by the patterns |
| T18 | A1 | Container escape / host compromise via the service | Non-root uid 10001, read-only root, `cap_drop: ALL`, `no-new-privileges`, no shell user, no package installers | Kernel/runtime vulnerabilities; no seccomp/AppArmor profile beyond the runtime defaults |

## Open items for Stage 11

1. External anchoring of the audit chain (a write-once store or a signed chain head).
2. A signature v2 covering method, path and a nonce; optional mTLS between the proxy and
   the service.
3. Minimal or distroless base image; runtime seccomp profile.
4. Signed model artefacts (a signature, not only a digest held in the same database).
5. A two-person rule for policy activation.
6. Pseudonymisation-key rotation and data erasure tooling.
7. An independent penetration test.
