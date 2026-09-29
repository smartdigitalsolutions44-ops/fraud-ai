# Trust chain (Stage 11)

This document explains how fraud-ai establishes **who produced** each thing it trusts, and
**that nothing changed since**. It covers requests, model artefacts, the audit history,
policy activation and releases.

It describes a **security-hardened prototype**. The mechanisms below are implemented and
tested; the evidence levels are in HARDENING.md §24. Nothing here is a certification.
No PCI DSS, GDPR, SOC 2 or ISO compliance is claimed.

## 1. Keys and their separation

| Purpose | Algorithm | Private key lives | Public/verification key lives | Signs |
|---|---|---|---|---|
| Request signing (per API key) | HMAC-SHA256 | derived from `SERVICE_SIGNING_MASTER_KEY` (service secret) | same (symmetric) | merchant requests (v1/v2) |
| **Model** | Ed25519 | offline file, `models sign --key` | `MODEL_SIGNING_PUBLIC_KEYS` | model artefacts |
| **Audit** | Ed25519 | offline file, `audit anchor --key` | `AUDIT_ANCHOR_PUBLIC_KEYS` | audit-chain anchors |
| **Release** | Ed25519 | offline file, `release manifest --key` | `RELEASE_SIGNING_PUBLIC_KEYS` | release manifests |

Separation is enforced in three ways:

* **Distinct trusted sets.** Settings refuse a public key that is trusted for two purposes
  (`check_separation`).
* **Domain-separated messages.** Every Ed25519 signature covers
  `fraud-ai/<purpose>/v1\n` followed by the canonical JSON of the statement. A model
  signature therefore cannot verify as an audit anchor or a release, even with the same key.
* **Membership checks at signing time.** The signing commands refuse a key that is not in
  the matching trusted set (for example an audit key for `models sign`).

**The service never holds a private Ed25519 key.** It needs only public keys, plus the HMAC
master key for request signing. `fraud-ai keys generate --purpose …` writes a new PKCS#8
key:

* mode 0600;
* never overwriting an existing file;
* the private-key loader refuses group- or world-readable files and symlinks.

Keep the private keys off service hosts and out of the repository. `.gitleaks.toml` and
detect-secrets would flag PEM private keys.

Cryptography comes only from the `cryptography` package: Ed25519 (RFC 8032), SHA-256 and
HMAC. There is no home-made primitive; only the statement framing is ours.

## 2. Requests: signature v2

**v1** signs `timestamp + "." + body`. It does not bind the method or the path: a captured
body could in principle be presented to a different route. Reuse was already blocked
because each signature is single-use.

**v2** signs the canonical form:

```text
fraud-ai-v2
METHOD
CANONICAL_PATH[?CANONICAL_QUERY]
TIMESTAMP
hex(SHA-256(body))
```

The HMAC key is the per-API-key signing secret. The header is `X-Fraud-Signature: v2=<hex>`.
Canonicalisation (`fraud_ai/service/signatures.py`):

* **Path:** percent-decoded, then re-encoded with RFC 3986 unreserved characters and `/`
  kept (so `%7e` becomes `~` and `%2f` becomes `/`). An empty path becomes `/`.
* **Query:** parsed with blank values kept, sorted by name and then value, and re-encoded.
  `&`, `=` and `+` inside values are always escaped, so they cannot be smuggled.
* **Body:** SHA-256 of the exact bytes sent. The timestamp is the decimal Unix time.

**Downgrade protection.** `SIGNATURE_MIN_VERSION` (`v1` or `v2`; default `v2` in
production, `v1` elsewhere):

* a request signed only below the minimum gets **401 `SIGNATURE_VERSION_REJECTED`**. It is
  never silently accepted, and it is counted in
  `fraud_api_signature_failures_total{code}`;
* a header may carry `v1=…,v2=…` during a migration. Only the strongest version present is
  verified, and an invalid v2 next to a valid v1 fails: there is no fallback;
* unknown versions, duplicates and malformed values are `INVALID_SIGNATURE`.

**Migration:**

1. Integrators send both versions.
2. Watch `fraud_api_signatures_verified_total`.
3. Set `SIGNATURE_MIN_VERSION=v2`.

Replay protection is unchanged: one claim per signature, in Redis or the database.
Signing-key rotation (current plus previous master key) works for both versions.

## 3. Model artefacts

**The problem.** A SHA-256 digest in the registry proves the files did not change *since
registration*. It does not prove *who* registered them: anyone able to write both the model
directory and the `model_versions` row could substitute a model.

**Signing.** `fraud-ai models sign <model>-<version> --key model.pem` signs a statement
over:

* the model row (id, name, version, feature version);
* the registered digest;
* the SHA-256 of **every file** in the artefact directory.

The signature, key id, algorithm, per-file hashes, signer and time go into
`model_artifact_signatures` (append-only, with triggers). Signing is audited
(`model.signed`).

**Verified load** (`fraud_ai/models/artifact_io.py`, `fraud_ai/models/scoring.py`) reduces
the hash-then-load race:

1. **Read once, safely.** The artefact directory is opened once (`O_DIRECTORY |
   O_NOFOLLOW`). Each file is opened relative to that handle (`O_NOFOLLOW`), checked with
   `fstat` to be a regular file, and read fully into memory, with a 1 GiB cap.
   Symlinks, sub-directories, devices and files changing mid-read are refused.
2. **Digest** of those bytes against the registry.
3. **Signature** over a statement rebuilt from those bytes. The file set must match
   exactly: no file added, removed or changed.
4. **Deserialise from the same in-memory bytes** (`io.BytesIO`). The path is never reopened.

`tests/test_model_signing.py::test_loader_uses_the_verified_bytes_not_the_path` swaps the
estimator on disk after the read: the loader still loads the verified bytes, and a fresh
read refuses the swap.

**Enforcement** (`MODEL_SIGNATURES_REQUIRED`, default on in staging and production):

* **Unsigned, untrusted-key or bad signature:** `ModelSignatureError`.
  * The model is not loaded.
  * Readiness reports `primary_model: failed` and logs the reason.
  * Start-up is refused.
  * If a model fails later, in a worker, scoring takes the existing conservative fallback
    (`MANUAL_REVIEW`, `fallback_used`).
  * There is never a silent "unsigned is fine".
* **Not required** (development): unsigned models load. A present signature by a trusted
  key that fails is still refused, because that is evidence of tampering.

**Cost:** signature verification runs only at load (start-up, cache miss or the readiness
re-check), never per request. Measurements are in HARDENING.md §23.

## 4. Safe serialisation review

| Format | Where | Code execution on load? | Trust assumption / mitigation |
|---|---|---|---|
| JSON (config, preprocessor, manifest, history, metrics) | all models | no | parsed after digest/signature checks |
| PyTorch `state_dict` (`model.pt`) | neural, GRU, Transformer, hybrid, autoencoder | no: `torch.load(weights_only=True)` refuses pickled code | tensors only; strict `load_state_dict` into a network built from verified config |
| joblib/pickle (`estimator.joblib`) | logistic regression, random forest, gradient boosting | **yes, unpickling runs code** | loaded only after its bytes match the registered digest **and** (where required) a trusted Ed25519 signature; from memory, not a path |

**Not done, deliberately.** The scikit-learn estimators are not converted to a
non-executable format (for example `skops` or ONNX):

* it would add a dependency;
* it would change every registered digest.

**The rule is instead:** never load a pickle that is not signed by a key you trust. Treat
`MODEL_SIGNING_PUBLIC_KEYS` as code-execution trust.

## 5. Audit history: external anchors

**The problem.** The hash chain in `audit_events` detects edits, and triggers block
UPDATE/DELETE. A database superuser, or the table owner, can still drop the triggers and
rewrite the chain *consistently*.

**The fix.** `fraud-ai audit anchor` works in four steps:

1. Verify the chain.
2. Append and commit an `audit.anchored` event.
3. Sign a statement (purpose `audit`) with the dedicated audit key. The statement holds
   the head sequence, the head event hash, the anchor number, a timestamp, and the
   previous anchor's hash.
4. Write it to an `AuditAnchorProvider`.

The bundled provider, `FileAnchorStore`, writes one create-only (`O_EXCL`) JSON file per
anchor. **Point it at storage the database administrator cannot write**: a WORM or
object-lock bucket, another host, or an append-only mount.

`fraud-ai audit verify-anchor` checks:

* the database chain;
* every anchor signature;
* the anchor numbering and links;
* **position:** the event at each anchored sequence still has the anchored hash;
* **no missing section:** the chain still reaches every anchored sequence.

`tests/test_trust_chain.py` (SQLite and PostgreSQL) shows the effect. A DBA-style rewrite
drops the trigger, edits event 2 and recomputes every later hash. It **passes** the
internal check and **fails** the anchor check. Truncation, a forged anchor, a missing anchor
and an anchor signed by the wrong key are also detected.

**Limits:**

* events after the latest anchor are unprotected until the next anchor, so anchor
  frequently (for example from cron);
* someone who can delete the *newest* anchor files can hide the latest period, which is why
  the store must be write-once.

## 6. Policy activation: two people

With `POLICY_APPROVALS_REQUIRED=2` (the default in production), activation requires three
things:

* **promotion:** the policy reached `candidate` through shadow → evaluation → candidate
  (Stage 10);
* **two approvals:** from **different** operators (`fraud-ai policy approve <v> --note …`);
* **validity:** each approval is unexpired (`POLICY_APPROVAL_TTL_HOURS`, 72 by default) and
  pinned to the definition's SHA-256.

**Operator identity** is `OPERATOR_ID` from the operator's trusted CLI configuration. It is
not a login system. `OPERATOR_ALLOWLIST` optionally limits who may approve.

The same operator approving twice is refused twice over: by the code, and by the unique
constraint `(policy_version, operator)`. Approvals are append-only (with triggers) and
audited (`policy.approved`); activation records the approvers.

**Limit:** whoever controls `OPERATOR_ID` in two environments, or has direct database
write access, can impersonate a second approver. The rule stops a single operator acting
alone *through the tooling*.

## 7. Releases

`fraud-ai release manifest --out release.json --sbom sbom/fraud-ai.cdx.json
--image-digest sha256:… --key release.pem` records:

* the git commit and the migration revision;
* the API, feature and sequence versions;
* the active policy (and its definition hash) and the shadow policies;
* every active-set model's digest and signature;
* the SBOM SHA-256 and the image digest.

It is signed with the release key.

`fraud-ai release verify release.json [--sbom …] [--no-database]` checks every hash and
signature available in the environment: signature, commit, SBOM, migration, policy, model
digests and files, model signatures. Anything it cannot check is reported **skipped**,
never passed.

## 8. Key compromise quick reference

The full runbooks are in DISASTER_RECOVERY.md.

* **Model key:** remove its public key from `MODEL_SIGNING_PUBLIC_KEYS`. Every model it
  signed then refuses to load (fail closed). Re-sign the known-good artefacts with a new key.
* **Audit key:** rotate it; keep the old public key only to verify old anchors. Re-anchor
  with the new key.
* **Release key:** rotate it; re-issue the manifests that matter.
* **API signing master key:** see Stage 10 (rotation with previous-key grace; no grace on
  compromise).
