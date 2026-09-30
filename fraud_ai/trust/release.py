"""Signed release manifests (Stage 11).

A release manifest pins everything that determines what the service will do. It is signed
with a **release** key (purpose ``release``), separate from the model, audit and API keys.
It records:

* the git commit and the migration revision;
* the API, feature and sequence versions;
* the active policy (with its definition hash) and the shadow policies;
* every model of the active set: artefact digest, signature key id and value;
* the SBOM hash;
* the container image digest, when one is given;
* (Stage 12) the container image evidence: image reference and digest, the cosign
  signature reference and the image-signing key fingerprint, the SLSA provenance reference
  and digest, and the image SBOM digest (from ``scripts/image_sign.sh``);
* (Stage 12) the newest audit anchor: number, sequence, chain head, audit-key id and
  destination.

``fraud-ai release manifest`` writes ``{"manifest": {...}, "signature": {...}}``.
``fraud-ai release verify <file>`` checks, as far as the environment allows:

1. the manifest signature against ``RELEASE_SIGNING_PUBLIC_KEYS``;
2. with a database: the migration revision, the active policy and its definition hash,
   and each model's registered digest;
3. with model files: each model's files hash to the recorded digest. Where
   ``MODEL_SIGNING_PUBLIC_KEYS`` is set, each model signature verifies;
4. the SBOM file's SHA-256 (when given);
5. the git commit (when run inside the repository).

Anything that could not be checked is reported as ``skipped``, never as passed.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess  # nosec B404 - only `git rev-parse HEAD`, fixed argv, no shell
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from fraud_ai import __version__
from fraud_ai.trust import keys as tk
from fraud_ai.trust.keys import Signature, Signer, TrustError

PURPOSE = "release"
MANIFEST_VERSION = 2  # Stage 12: image evidence and audit anchor


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _revision(session: Session) -> str | None:
    from alembic.migration import MigrationContext

    return MigrationContext.configure(session.connection()).get_current_revision()


def git_commit(root: Path | None = None) -> str | None:
    git = shutil.which("git")
    if git is None:
        return None
    proc = subprocess.run(  # nosec B603 # noqa: S603 - fixed binary, argument list
        [git, "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or None if proc.returncode == 0 else None


def _models(session: Session) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.risk.registry import active_deployment, get_policy_record

    deployment = active_deployment(session)
    if deployment is None:
        return None, []
    refs = [slot.ref for slot in deployment.policy.slots().values()]
    for shadow in deployment.shadow_policies:
        refs += [slot.ref for slot in shadow.slots().values()]
    refs += list(deployment.shadow_models)
    models = []
    for ref in dict.fromkeys(refs):
        record = resolve_model(session, ref)
        signature = record.signatures[0] if record.signatures else None
        models.append(
            {
                "ref": ref,
                "model_id": str(record.model_version_id),
                "feature_version": record.feature_version,
                "artifact_sha256": record.artifact_sha256,
                "signature": None
                if signature is None
                else {
                    "key_id": signature.key_id,
                    "algorithm": signature.algorithm,
                    "signature": signature.signature,
                },
            }
        )
    policy = deployment.policy.policy_version
    return (
        {
            "policy_version": policy,
            "definition_sha256": get_policy_record(session, policy).definition_sha256,
            "shadow_policies": sorted(p.policy_version for p in deployment.shadow_policies),
            "deployment": deployment.deployment.sequence,
        },
        models,
    )


IMAGE_EVIDENCE_FIELDS = (
    "image",
    "digest",
    "signature_ref",
    "signing_key_fingerprint",
    "signing_key_ref",
    "provenance_ref",
    "provenance_sha256",
    "provenance_predicate_type",
    "sbom_ref",
    "sbom_sha256",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_image_evidence(path: Path) -> dict[str, Any]:
    """The evidence file written by ``scripts/image_sign.sh`` (strictly checked)."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise TrustError(f"cannot read image evidence {path}: {exc}") from None
    if not isinstance(data, dict):
        raise TrustError("image evidence must be a JSON object")
    missing = [f for f in IMAGE_EVIDENCE_FIELDS if not data.get(f)]
    if missing:
        raise TrustError(f"image evidence lacks {', '.join(missing)}")
    if not _DIGEST.match(str(data["digest"])):
        raise TrustError("image evidence digest must be sha256:<64 hex>")
    return {f: str(data[f]) for f in IMAGE_EVIDENCE_FIELDS}


def _anchor(session: Session) -> dict[str, Any] | None:
    from fraud_ai.trust.anchors import latest_status

    last = latest_status(session)
    if last is None:
        return None
    return {
        "anchor_number": last.anchor_number,
        "sequence": last.sequence,
        "head_sha256": last.head_sha256,
        "key_id": last.key_id,
        "destination": last.destination,
        "anchored_at": last.anchored_at.isoformat(),
    }


def build_manifest(
    session: Session,
    database_url: str,
    *,
    sbom: Path | None = None,
    image_digest: str | None = None,
    image_evidence: dict[str, Any] | None = None,
    commit: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    from fraud_ai.database import migrations as mig
    from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION
    from fraud_ai.sequences.definition import SEQUENCE_VERSION
    from fraud_ai.service.schemas import API_VERSION

    policy, models = _models(session)
    if image_evidence is not None:
        if image_digest is not None and image_digest != image_evidence["digest"]:
            raise TrustError("--image-digest differs from the image evidence digest")
        image_digest = image_evidence["digest"]
    return {
        "manifest_version": MANIFEST_VERSION,
        "product": "fraud-ai",
        "package_version": __version__,
        "git_commit": commit or git_commit(),
        "migration_revision": _revision(session),
        "code_head_revision": mig.head_revision(database_url),
        "api_version": API_VERSION,
        "feature_version": DEFAULT_FEATURE_VERSION,
        "sequence_version": SEQUENCE_VERSION,
        "policy": policy,
        "models": models,
        "sbom": None if sbom is None else {"path": sbom.name, "sha256": _sha256_file(sbom)},
        "container_image": {"digest": image_digest} if image_digest else None,
        "image_evidence": image_evidence,
        "audit_anchor": _anchor(session),
        "created_at": (now or datetime.now(UTC)).isoformat(timespec="seconds"),
    }


def sign_manifest(
    manifest: dict[str, Any], pair: Signer, trusted: dict[str, Ed25519PublicKey] | None = None
) -> dict[str, Any]:
    if trusted is not None and pair.key_id not in trusted:
        raise TrustError(f"key {pair.key_id} is not in RELEASE_SIGNING_PUBLIC_KEYS")
    return {"manifest": manifest, "signature": tk.sign(PURPOSE, pair, manifest).to_dict()}


@dataclass
class ReleaseReport:
    checks: dict[str, str] = field(default_factory=dict)  # name -> ok | FAILED: … | skipped: …

    @property
    def ok(self) -> bool:
        return not any(v.startswith("FAILED") for v in self.checks.values())


def verify_release(
    document: dict[str, Any],
    trusted: dict[str, Ed25519PublicKey],
    *,
    session: Session | None = None,
    database_url: str | None = None,
    sbom: Path | None = None,
    model_trust: Any = None,
    repo: Path | None = None,
    image_check: Any = None,
    anchor_keys: dict[str, Ed25519PublicKey] | None = None,
) -> ReleaseReport:
    report = ReleaseReport()
    try:
        manifest = dict(document["manifest"])
        signature = Signature.from_dict(document["signature"])
    except (KeyError, TypeError, TrustError):
        report.checks["signature"] = "FAILED: not a signed release manifest"
        return report
    try:
        key = tk.verify(PURPOSE, trusted, manifest, signature)
        report.checks["signature"] = f"ok (key {key})"
    except TrustError as exc:
        report.checks["signature"] = f"FAILED: {exc}"
        return report  # nothing else in an unauthenticated manifest is worth checking

    commit = git_commit(repo)
    if commit is None:
        report.checks["git_commit"] = "skipped: not in a git checkout"
    elif commit == manifest.get("git_commit"):
        report.checks["git_commit"] = "ok"
    else:
        report.checks["git_commit"] = (
            f"FAILED: checkout is {commit[:12]}, manifest {str(manifest.get('git_commit'))[:12]}"
        )

    expected_sbom = manifest.get("sbom")
    if expected_sbom is None:
        report.checks["sbom"] = "skipped: manifest has no SBOM"
    elif sbom is None or not sbom.exists():
        report.checks["sbom"] = "skipped: SBOM file not given"
    elif _sha256_file(sbom) == expected_sbom["sha256"]:
        report.checks["sbom"] = "ok"
    else:
        report.checks["sbom"] = "FAILED: SBOM hash differs"

    image = manifest.get("container_image")
    report.checks["container_image"] = (
        f"recorded {image['digest']} (compare with the deployed image digest)"
        if image
        else "skipped: no image digest recorded"
    )
    evidence = manifest.get("image_evidence")
    if evidence is None:
        report.checks["image_evidence"] = "skipped: no image signature/provenance recorded"
    elif image_check is None:
        report.checks["image_evidence"] = (
            "skipped: recorded; give --image-key to verify signature, provenance and SBOM"
        )
    else:
        for name, result in image_check(evidence).items():
            report.checks[name] = result
    anchor = manifest.get("audit_anchor")
    if anchor is None:
        report.checks["audit_anchor"] = "skipped: no audit anchor recorded"
    elif anchor_keys is None:
        report.checks["audit_anchor"] = f"recorded anchor {anchor['anchor_number']} (no key set)"
    elif anchor.get("key_id") in anchor_keys:
        report.checks["audit_anchor"] = (
            f"ok (anchor {anchor['anchor_number']}, key {anchor['key_id']} is trusted)"
        )
    else:
        report.checks["audit_anchor"] = (
            f"FAILED: anchor key {anchor.get('key_id')} is not in AUDIT_ANCHOR_PUBLIC_KEYS"
        )

    if session is None:
        report.checks["database"] = "skipped: no database"
        return report
    _verify_database(report, manifest, session, database_url, model_trust)
    return report


def _verify_database(
    report: ReleaseReport,
    manifest: dict[str, Any],
    session: Session,
    database_url: str | None,
    model_trust: Any,
) -> None:
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.signing import ModelSignatureError, check_model_signature

    revision = _revision(session)
    report.checks["migration_revision"] = (
        "ok"
        if revision == manifest.get("migration_revision")
        else f"FAILED: database at {revision}, manifest {manifest.get('migration_revision')}"
    )
    policy, _ = _models(session)
    expected = manifest.get("policy")
    if policy == expected:
        report.checks["policy"] = "ok"
    else:
        got = (policy or {}).get("policy_version")
        want = (expected or {}).get("policy_version")
        report.checks["policy"] = f"FAILED: active {got}, manifest {want} (or definition changed)"
    for model in manifest.get("models", []):
        name = f"model {model['ref']}"
        try:
            record = resolve_model(session, model["ref"])
        except Exception as exc:  # a missing model is a failed check, not a crash
            report.checks[name] = f"FAILED: {exc}"
            continue
        if record.artifact_sha256 != model["artifact_sha256"]:
            report.checks[name] = "FAILED: registered digest differs from the manifest"
            continue
        try:
            key = check_model_signature(record, model_trust)
        except ModelSignatureError as exc:
            report.checks[name] = f"FAILED: {exc}"
            continue
        except Exception as exc:  # e.g. artefact directory missing on this host
            report.checks[name] = f"skipped: files not verifiable here ({type(exc).__name__})"
            continue
        signed = model.get("signature")
        if signed is not None and key is not None and signed["key_id"] != key:
            report.checks[name] = f"FAILED: signed by {key}, manifest says {signed['key_id']}"
        else:
            report.checks[name] = "ok (digest and files" + (
                f", signature {key})" if key else "; unsigned)"
            )


def load_document(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise TrustError(f"cannot read manifest {path}: {exc}") from None
    if not isinstance(data, dict):
        raise TrustError("a manifest must be a JSON object")
    return data
