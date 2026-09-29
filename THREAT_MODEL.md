# Threat model (Stages 10-11)

This is the threat model for the fraud-ai service, a **deployment-hardened prototype**, as
deployed in `deploy/staging/`. Stage 11 revisions are marked **(S11)**; the trust
mechanisms are described in [TRUST_CHAIN.md](TRUST_CHAIN.md). It lists what an attacker could want, how, what the code
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

## Stage 11 revisit

The Stage 10 rows above describe the Stage 10 state. Stage 11 changes these rows:

| # | Threat | Stage 11 mitigation | Remaining risk |
|---|---|---|---|
| T3 (S11) | **Signature substitution:** moving a signed body to another method, path or query | Signature **v2** binds method, canonical path and query, timestamp and body digest. `SIGNATURE_MIN_VERSION=v2` refuses v1 with an explicit code, and there is no fallback from an invalid v2 to a valid v1 | Clients on v1 during the migration window are still exposed to the v1 gap (mitigated by the single-use claim); the canonical path is the one the service receives, so a path-rewriting proxy must be accounted for |
| T7 (S11) | **Model tampering / substitution** by someone who can write the model directory and the registry row | Ed25519 **model signatures** over every artefact file, with the key outside the database. Required by default in staging and production. **Read-once verified load:** no symlinks, `fstat`-checked regular files, digest and signature over the in-memory bytes, deserialisation from those bytes | A compromised **model signing key** can sign a malicious pickle. That key is code-execution trust (keep it offline). scikit-learn models remain pickles (TRUST_CHAIN.md §4) |
| T9 (S11) | **DB-superuser audit tampering:** a consistent rewrite of the chain | **External anchors** signed with a separate audit key, stored outside the database; `audit verify-anchor` checks each position and detects truncation (tested on PostgreSQL) | Events after the latest anchor; deletion of the newest anchors by someone with write access to the anchor store (use WORM storage) |
| T8 (S11) | **Operator compromise / a single rogue operator** activating a policy | **Two-person rule:** distinct `OPERATOR_ID`s, unexpired approvals pinned to the definition hash, DB unique constraint, append-only approvals, audit. **Least-privilege DB roles:** the service cannot DROP, ALTER, TRUNCATE, disable triggers or change history (tested) | `OPERATOR_ID` is configuration, not authentication: two compromised operator environments, or the migrator/superuser credential, defeat it. No hardware-backed approvals |
| T10/T17 (S11) | **Privacy leakage** through free text | Declared free-text fields with length limits: **reject** PII in operator/analyst text; **sanitise** merchant event text; card numbers refused by the contract | Pattern detection misses names and unusual formats; there is no erasure execution, only a dry-run plan (PRIVACY.md) |
| T15 (S11) | **Supply chain** | pip-audit (a setuptools floor added after CI found PYSEC-2026-3447), bandit, detect-secrets, gitleaks, SBOM; **signed release manifest** pinning commit, migration, policy, model digests and signatures, SBOM hash and image digest (`release verify`); CI builds and scans the real PyTorch image | The manifest is only as good as the release key's custody; there is no image signing (Sigstore/cosign) or SLSA provenance yet; the Debian base CVEs remain until patched |
| new | **Key confusion:** one key used for several purposes | Settings refuse a key trusted for two purposes; domain-separated messages; signing commands check purpose membership | Operators can still store several private keys carelessly; key custody is procedural |

## Open items for Stage 12

1. Hardware-backed or SSO-bound operator identity for approvals, instead of a configured
   `OPERATOR_ID`.
2. Image signing and provenance (cosign / SLSA), verified at deploy time against the
   release manifest.
3. Non-executable model formats for the scikit-learn models, or sandboxed loading.
4. WORM anchor storage wired in (object lock), and anchoring on a schedule with alerting on
   a stale anchor.
5. Pseudonymisation-key rotation and an audited erasure *execution* path, once the legal
   retention rules are defined.
6. An independent penetration test.
