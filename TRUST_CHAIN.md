# Trust chain (Stages 11-12)

This document explains how fraud-ai establishes **who produced** each thing it trusts, and
**that nothing changed since**. It covers requests, model artefacts, the audit history,
policy activation and releases.

It describes a **security-hardened prototype**. The mechanisms below are implemented and
tested; the evidence levels are in HARDENING.md §24 and §37. Nothing here is a certification.
No PCI DSS, GDPR, SOC 2 or ISO compliance is claimed.

## 1. Keys and their separation

| Purpose | Algorithm | Private key lives | Public/verification key lives | Signs |
|---|---|---|---|---|
| Request signing (per API key) | HMAC-SHA256 | derived from `SERVICE_SIGNING_MASTER_KEY` (service secret) | same (symmetric) | merchant requests (v1/v2) |
| **Model** | Ed25519 | offline file, `models sign --key` | `MODEL_SIGNING_PUBLIC_KEYS` | model artefacts |
| **Audit** | Ed25519 | offline file, `audit anchor --key` | `AUDIT_ANCHOR_PUBLIC_KEYS` | audit-chain anchors |
| **Release** | Ed25519 | offline file, `release manifest --key` | `RELEASE_SIGNING_PUBLIC_KEYS` | release manifests |
| **Image** (Stage 12) | ECDSA P-256 (cosign) | Vault transit `fraud-ai-image` (non-exportable) or a cosign key | `IMAGE_SIGNING_PUBLIC_KEY_FILE` | container image digests and their attestations |
| **Operator** (Stage 12) | Ed25519, one key per person | the operator's own file (or a hardware token, not integrated) | `OPERATOR_REGISTRY_FILE` | administrative assertions (AUTHENTICATION.md §6) |

### Key providers (Stage 12)

`KEY_PROVIDER` selects where the model, audit and release private keys live
(`fraud_ai/trust/kms.py`). Core code sees only a `Signer` (public key, key id, `sign_raw`).
No vendor is hard-coded.

* **`local`**: PKCS#8 files, as in Stage 11.
* **`vault`**: HashiCorp Vault **transit** keys: one per purpose (`VAULT_KEY_MODEL`,
  `…_AUDIT`, `…_RELEASE`, `…_IMAGE`), type `ed25519`, `exportable=false`. The key version is
  pinned when opened, and every signature returned by Vault is **verified locally**
  against the trusted public key before use. The staging stack gives each purpose its own
  Vault policy and token: the model token gets 403 on the audit key.
* **Fail closed.** `KMS_REQUIRED` defaults to true in production. With it, or with
  `KEY_PROVIDER=vault`, a `--key` file or `*_PRIVATE_KEY_FILE` setting is **refused**.
  There is no silent fallback from an unreachable Vault to local files; a Vault error
  aborts the signing command.
* **Purpose separation** extends to the image and operator keys. The image key must not
  be the model, audit, release or API key. Settings refuse identical key names or
  secrets, and the registry check refuses an operator key that is also a signing key.
* **Rotation:** `fraud-ai keys rotate --purpose <p>` (Vault only; `security_admin`;
  audited as `signing_key.rotated`) creates a new key version. Add its public key to the
  trusted set before relying on it; old versions stay usable for verification.

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

Two stores implement it:

* **`file`** (`FileAnchorStore`): one create-only (`O_EXCL`) JSON file per anchor. It
  suits development and the demo.
* **`s3`** (Stage 12, `S3ObjectLockAnchorStore`, `AUDIT_ANCHOR_STORE=s3`): an S3 bucket
  with **versioning and Object Lock in COMPLIANCE mode**. Nobody, including the bucket
  owner or root, can shorten the retention or delete a locked version before it expires.
  * The store **refuses** a bucket without versioning or not in COMPLIANCE mode.
  * Each anchor is written with an explicit retention (`ANCHOR_RETENTION_DAYS`), read
    back and checked.
  * Verification reads the **oldest** version of each object and reports any later
    version, delete marker, stray object or missing lock as a problem.
  * The writer credential may put and set retention, but not delete. The verifier's
    credential is read-only.
  * Staging uses RustFS 1.0.0 with COMPLIANCE enforced. **Honest limit:** that is WORM at
    the S3 API; the files sit on the same host, so a host administrator could remove
    them. For real separation, use a different account or provider (S3 in another AWS
    account, with a least-privilege policy; DEPLOYMENT.md §2c).

**Scheduling.** `fraud-ai audit anchor-now` anchors only when there are new events
(`--always` forces it) and prints one JSON line:

* the timestamp;
* the head sequence and hash;
* the anchor number;
* the signing key id;
* the destination.

Run it on a schedule: every 5-15 minutes, or the staging `anchor` service loop
(`ANCHOR_INTERVAL`). `fraud-ai audit anchor-status --max-age-minutes N` exits non-zero
when events have waited unanchored for more than N minutes, or the store is unhealthy;
alert on it. An idle, fully anchored log is not flagged, because nothing is unprotected. A
store failure records `audit.anchor_failed` and exits non-zero.

**The staging drill** (`scripts/audit_tamper_drill.py`, HARDENING.md §29):

1. back up as `fraud_backup`;
2. restore into a clone;
3. rewrite event 2 as a superuser and re-chain.

The clone's internal chain **verified OK**, and `verify-anchor` **reported anchors 1-3 as
rewritten**. The live database was untouched.

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

**Operator identity (Stage 12)** is **authenticated**. Each approval carries a signed,
single-use assertion from the operator's own key, bound to the policy version, the
definition hash and the note. Roles come from the registry: only `policy_approver`s
approve, and only a `policy_activator` activates. At activation every stored assertion is
re-verified, so rows written straight into the database, disabled operators and expired
approvals do not count (AUTHENTICATION.md §6). With `OPERATOR_AUTH_REQUIRED=false`
(development only), `OPERATOR_ID` from the CLI configuration is used as before, and
`OPERATOR_ALLOWLIST` optionally limits it.

The same operator approving twice is refused twice over: by the code, and by the unique
constraint `(policy_version, operator)`. Approvals are append-only (with triggers) and
audited (`policy.approved`); activation records the approvers.

**Limit:** whoever holds two approvers' private keys, or can edit the registry, can act as
two people. Direct database write access no longer creates valid approvals. It can still
do anything else the migrator role can do.

## 7. Releases

`fraud-ai release manifest --out release.json --sbom sbom/fraud-ai.cdx.json
--image-digest sha256:… --key release.pem` records:

* the git commit and the migration revision;
* the API, feature and sequence versions;
* the active policy (and its definition hash) and the shadow policies;
* every active-set model's digest and signature;
* the SBOM SHA-256 and the image digest.

It is signed with the release key.

**Stage 12 (manifest version 2)** adds:

* `image_evidence`: the image digest, the cosign signature reference, the provenance and
  SBOM attestation references and their predicate digests, and the image-key fingerprint.
  Built with `--image-evidence image-evidence.json` from `scripts/image_sign.sh`;
* `audit_anchor`: the latest anchor's number, head sequence and signing key id;
* the migration revision, as before.

Signing a manifest is a `security_admin` action bound to the manifest's SHA-256, audited
as `release.signed`.

`fraud-ai release verify release.json [--sbom …] [--image-key cosign.pub] [--no-database]` checks every hash and
signature available in the environment: signature, commit, SBOM, migration, policy, model
digests and files, model signatures. Anything it cannot check is reported **skipped**,
never passed. With `--image-key` it also verifies the image evidence (§8), and it checks
that the anchor key id is a trusted audit key.

## 8. Container images (Stage 12)

`scripts/image_sign.sh <image> <registry/repo> <key> <pub> <out>` addresses everything by
**digest**, never by tag:

1. pushes the image and resolves its registry digest;
2. generates a **CycloneDX SBOM** (Trivy) and a **SLSA v1 provenance** predicate
   (`scripts/provenance.py`): git commit and ref, workflow and run, builder, base-image
   digest, SBOM digest as a by-product;
3. `cosign sign` the digest, then `cosign attest` both predicates, with the dedicated
   image key;
4. reads the attestations back, verifies them, and writes `image-evidence.json`.

`fraud-ai release verify-image image-evidence.json --key cosign.pub [--commit C]` checks
four things. The image fails verification if any one fails:

| Check | Fails when |
|---|---|
| `image_key` | the key's fingerprint differs from the one recorded |
| `image_signature` | no valid signature on that digest (a rebuilt or tampered image has another digest) |
| `image_provenance` | the attestation is missing or unsigned, its predicate digest differs from the evidence, or its commit differs from `--commit` |
| `image_sbom` | the SBOM attestation is missing or its digest differs |

Tested locally with a Vault transit image key:

* a correct image passed;
* a wrong commit, a tampered image (one added label) and a wrong key all **failed**.

CI repeats the sign-and-verify steps and the tampered-image failure on every run.

**Limits:**

* no Rekor transparency-log upload (`--tlog-upload=false`; the registry is private);
* no admission controller enforcing verification at deploy time;
* CI uses an **ephemeral** key unless the repository secret `COSIGN_PRIVATE_KEY` is set,
  so its signatures prove the pipeline works, not a durable identity.

## 9. Key compromise quick reference

The full runbooks are in DISASTER_RECOVERY.md.

* **Model key:** remove its public key from `MODEL_SIGNING_PUBLIC_KEYS`. Every model it
  signed then refuses to load (fail closed). Re-sign the known-good artefacts with a new key.
* **Audit key:** rotate it; keep the old public key only to verify old anchors. Re-anchor
  with the new key.
* **Release key:** rotate it; re-issue the manifests that matter.
* **Image key:** rotate the Vault key (`keys rotate --purpose image`) or replace the cosign
  key. Distribute the new public key, and re-sign the images still deployed.
* **Operator key:** remove or disable the entry in the registry. The operator's future
  assertions fail, and any approvals they made stop counting at activation.
* **API signing master key:** see Stage 10 (rotation with previous-key grace; no grace on
  compromise).
