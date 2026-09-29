"""Signed model artefacts (Stage 11).

A SHA-256 digest proves an artefact has not changed since it was registered. It does not
say **who** produced it: anyone able to write both the files and the registry row could
substitute a model. An Ed25519 signature from a key outside the database closes that gap.

**Statement signed** (purpose ``model``, see :mod:`fraud_ai.trust.keys`)::

    {"model_id", "model_name", "model_version", "feature_version",
     "artifact_sha256",              # the registered digest
     "files": {name: sha256, ...}}   # EVERY file in the artefact directory

**Signing:** ``fraud-ai models sign <version> --key <private.pem>``. The private key is
read from a 0600 file and never stored anywhere by this code.

**Verification at load** (:func:`verify_loaded`) works on the exact in-memory bytes the
loader will deserialise (:class:`~fraud_ai.models.artifact_io.ArtifactBytes`):

1. the registered digest must match those bytes (the loader checks it again);
2. a stored signature by a **trusted** key must verify over the statement rebuilt from
   those bytes. The file set must be identical: no file added, removed or changed.

Outcomes:

* **Required** (``MODEL_SIGNATURES_REQUIRED``, the default in staging and production):
  an unsigned model, an untrusted key or a bad signature raise
  :class:`ModelSignatureError`. The model is not loaded, and scoring takes its
  conservative fallback. There is no silent fallback to "unsigned is fine".
* **Not required:** a present signature by a trusted key that fails still raises (it is
  evidence of tampering). Unsigned models load, as before Stage 11.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from fraud_ai import audit
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ModelArtifactSignature, ModelVersion
from fraud_ai.models.artifact_io import ArtifactBytes, ArtifactReadError
from fraud_ai.trust import keys as trust_keys
from fraud_ai.trust.keys import KeyPair, Signature, TrustError

PURPOSE = "model"


class ModelSignatureError(FraudAIError):
    """The model's signature is missing, untrusted or invalid: it must not be loaded."""


@dataclass(frozen=True)
class ModelTrust:
    required: bool
    keys: dict[str, Ed25519PublicKey]

    @classmethod
    def from_settings(cls, settings: Any) -> ModelTrust:
        return cls(
            required=bool(settings.requires_model_signatures),
            keys=trust_keys.parse_public_keys(settings.model_signing_public_keys),
        )

    @classmethod
    def current(cls) -> ModelTrust:
        from fraud_ai.config.settings import get_settings

        return cls.from_settings(get_settings())


def statement(model: ModelVersion, blob: ArtifactBytes) -> dict[str, Any]:
    return {
        "model_id": str(model.model_version_id),
        "model_name": model.model_name,
        "model_version": model.model_version,
        "feature_version": model.feature_version,
        "artifact_sha256": model.artifact_sha256,
        "files": blob.file_hashes(),
    }


def _read(model: ModelVersion) -> ArtifactBytes:
    from pathlib import Path

    try:
        return ArtifactBytes.read(Path(model.model_path))
    except ArtifactReadError as exc:
        raise ModelSignatureError(str(exc)) from None


def sign_model(
    session: Session,
    model: ModelVersion,
    pair: KeyPair,
    *,
    actor: str,
    trusted: dict[str, Ed25519PublicKey] | None = None,
    now: datetime | None = None,
) -> ModelArtifactSignature:
    """Sign the artefact as it is on disk now, after checking the registered digest."""
    if model.artifact_sha256 is None:
        raise ModelSignatureError(f"{model.model_name}-{model.model_version} has no digest")
    if trusted is not None and pair.key_id not in trusted:
        raise ModelSignatureError(
            f"key {pair.key_id} is not in MODEL_SIGNING_PUBLIC_KEYS; the service would "
            "refuse the signature"
        )
    blob = _read(model)
    _check_digest(model, blob)
    body = statement(model, blob)
    sig = trust_keys.sign(PURPOSE, pair, body)
    row = ModelArtifactSignature(
        model_version_id=model.model_version_id,
        artifact_sha256=str(model.artifact_sha256),
        files=body["files"],
        key_id=sig.key_id,
        algorithm=sig.algorithm,
        signature=sig.value,
        signed_at=now or datetime.now(UTC),
        signed_by=actor[:200],
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        "model.signed",
        actor=actor,
        target_type="model",
        target_id=f"{model.model_name}-{model.model_version}",
        details={"key_id": sig.key_id, "artifact_sha256": model.artifact_sha256},
        now=now,
    )
    return row


def _check_digest(model: ModelVersion, blob: ArtifactBytes) -> None:
    from fraud_ai.models.factory import digest_names, kind_for_name

    names = digest_names(kind_for_name(model.model_name), blob)
    if blob.digest(names) != model.artifact_sha256:
        raise ModelSignatureError(
            f"{model.model_name}-{model.model_version}: the files do not match the "
            "registered digest"
        )


def verify_loaded(model: ModelVersion, blob: ArtifactBytes, trust: ModelTrust) -> str | None:
    """Verify the signature over the given bytes; return the key id, or ``None`` when an
    unsigned model is acceptable (signatures not required and none trusted present)."""
    name = f"{model.model_name}-{model.model_version}"
    body = statement(model, blob)
    problems: list[str] = []
    for row in model.signatures:
        sig = Signature(PURPOSE, row.key_id, row.algorithm, row.signature)
        if row.key_id not in trust.keys:
            problems.append(f"signed by untrusted key {row.key_id}")
            continue
        try:
            return trust_keys.verify(PURPOSE, trust.keys, body, sig)
        except TrustError:
            changed = sorted(
                set(row.files) ^ set(body["files"])
                | {f for f in row.files if body["files"].get(f) != row.files[f]}
            )
            detail = f" (changed files: {', '.join(changed)})" if changed else ""
            raise ModelSignatureError(
                f"{name}: the signature by {row.key_id} does not verify{detail}"
            ) from None
    if trust.required:
        reason = "; ".join(problems) or "unsigned"
        raise ModelSignatureError(f"{name}: a trusted signature is required ({reason})")
    return None


def check_model_signature(model: ModelVersion, trust: ModelTrust | None = None) -> str | None:
    """Read the artefact once and verify its signature (``models verify-signature``)."""
    blob = _read(model)
    _check_digest(model, blob)
    return verify_loaded(model, blob, trust or ModelTrust.current())
