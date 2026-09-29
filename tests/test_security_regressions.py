"""Stage 11 security regression tests: fast, direct checks, one per required regression.

Index of the full scenarios (all run in the suite):

* signature downgrade: ``test_downgrade`` here; full:
  ``test_signature_v2.py::test_downgrade_to_v1_is_refused_not_ignored``
* method/path tampering: ``test_method_path_tampering``; full:
  ``test_signature_v2.py::test_service_accepts_v2_and_refuses_tampering``
* unsigned model: ``test_unsigned_model``; full:
  ``test_model_signing.py::test_service_refuses_unsigned_models_when_required``
* wrong model signing key: ``test_wrong_model_key``; full:
  ``test_model_signing.py::test_wrong_or_untrusted_signing_key``
* expired policy approval: ``test_trust_chain.py::test_approvals_expire``
* same-person double approval: ``test_trust_chain.py::test_two_person_rule``
* audit-anchor tampering: ``test_anchor_tampering``; full:
  ``test_trust_chain.py::test_consistent_rewrite_is_caught_by_the_anchor``
* PII in free text: ``test_pii_in_free_text``; full: ``test_privacy.py``
* restricted DB privileges: ``test_pg_privileges.py`` (real PostgreSQL)
* release-manifest tampering: ``test_release_manifest_tampering``; full:
  ``test_release.py::test_tampering_is_detected``
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fraud_ai.models.artifact_io import ArtifactBytes
from fraud_ai.models.signing import PURPOSE as MODEL_PURPOSE
from fraud_ai.models.signing import ModelSignatureError, ModelTrust, statement, verify_loaded
from fraud_ai.privacy import freetext
from fraud_ai.service.signatures import (
    RequestTarget,
    SignatureError,
    check_signature,
    sign,
    sign_v2,
)
from fraud_ai.trust import keys as tk
from fraud_ai.trust.anchors import SignedAnchor
from fraud_ai.trust.release import sign_manifest, verify_release

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
TS = int(NOW.timestamp())
SECRET = "regression-signing-secret-0123456789abcd"


def _check(header: str, target: RequestTarget, min_version: str = "v2") -> datetime:
    return check_signature(
        SECRET, str(TS), header, b"{}", now=NOW, max_age=300, target=target,
        min_version=min_version,
    )  # fmt: skip


def test_downgrade() -> None:
    with pytest.raises(SignatureError) as err:
        _check(sign(SECRET, TS, b"{}"), RequestTarget("POST", "/v1/score"))
    assert err.value.code == "SIGNATURE_VERSION_REJECTED"


def test_method_path_tampering() -> None:
    header = sign_v2(SECRET, "POST", "/v1/score", TS, b"{}")
    assert _check(header, RequestTarget("POST", "/v1/score")) == NOW
    for target in (RequestTarget("PUT", "/v1/score"), RequestTarget("POST", "/v1/scores")):
        with pytest.raises(SignatureError, match="does not match"):
            _check(header, target)


def _artifact(tmp_path: Path) -> tuple[Any, ArtifactBytes]:
    d = tmp_path / "m"
    d.mkdir()
    (d / "estimator.joblib").write_bytes(b"weights")
    (d / "preprocessor.json").write_text("{}")
    model = SimpleNamespace(
        model_version_id=uuid.uuid4(),
        model_name="gradient-boosting",
        model_version="1.0.0",
        feature_version="fraud-features-1.0.0",
        artifact_sha256="0" * 64,
        signatures=[],
    )
    return model, ArtifactBytes.read(d)


def test_unsigned_model(tmp_path: Path) -> None:
    model, blob = _artifact(tmp_path)
    pair = tk.generate()
    with pytest.raises(ModelSignatureError, match="unsigned"):
        verify_loaded(model, blob, ModelTrust(True, {pair.key_id: pair.public}))  # type: ignore[arg-type]


def test_wrong_model_key(tmp_path: Path) -> None:
    model, blob = _artifact(tmp_path)
    trusted, attacker = tk.generate(), tk.generate()
    sig = tk.sign(MODEL_PURPOSE, attacker, statement(model, blob))  # type: ignore[arg-type]
    model.signatures = [
        SimpleNamespace(
            key_id=trusted.key_id,
            algorithm="ed25519",
            signature=sig.value,
            files=blob.file_hashes(),
        )
    ]  # claims the trusted key id, but was made with another key
    with pytest.raises(ModelSignatureError, match="does not verify"):
        verify_loaded(model, blob, ModelTrust(True, {trusted.key_id: trusted.public}))  # type: ignore[arg-type]
    # A valid signature from an audit key is not a model signature (domain separation).
    audit_sig = tk.sign("audit", trusted, statement(model, blob))  # type: ignore[arg-type]
    model.signatures[0].signature = audit_sig.value
    with pytest.raises(ModelSignatureError):
        verify_loaded(model, blob, ModelTrust(True, {trusted.key_id: trusted.public}))  # type: ignore[arg-type]


def test_anchor_tampering() -> None:
    pair = tk.generate()
    body = {"chain": "fraud-ai-audit", "sequence": 5, "head_sha256": "a" * 64,
            "anchor_number": 1, "previous_anchor_sha256": None}  # fmt: skip
    anchor = SignedAnchor(body, tk.sign("audit", pair, body))
    assert tk.verify("audit", {pair.key_id: pair.public}, anchor.statement, anchor.signature)
    forged = SignedAnchor({**body, "head_sha256": "b" * 64}, anchor.signature)
    with pytest.raises(tk.TrustError):
        tk.verify("audit", {pair.key_id: pair.public}, forged.statement, forged.signature)
    with pytest.raises(tk.TrustError, match="cannot be used"):
        tk.verify("model", {pair.key_id: pair.public}, body, anchor.signature)


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("mail jane.doe@example.org", "email address"),
        ("call 07700 900123", "phone number"),
        ("from 198.51.100.7", "IP address"),
        ("card 4111-1111-1111-1111", "card number"),
        ("token=abcd1234secret", "secret"),
        ("Bearer eyJhbGciOiJIUzI1NiJ9abc", "secret"),
    ],
)
def test_pii_in_free_text(text: str, kind: str) -> None:
    assert kind in freetext.detect(text)
    with pytest.raises(freetext.FreeTextError):
        freetext.check("review.note", text)
    assert kind not in freetext.detect(freetext.sanitise(text)[0])


def test_release_manifest_tampering() -> None:
    release = tk.generate()
    doc = sign_manifest({"git_commit": "abc", "models": []}, release)
    trusted = {release.key_id: release.public}
    assert verify_release(doc, trusted).checks["signature"].startswith("ok")
    doc["manifest"]["git_commit"] = "def"
    assert verify_release(doc, trusted).checks["signature"].startswith("FAILED")
    assert not verify_release({"manifest": {}}, trusted).ok
