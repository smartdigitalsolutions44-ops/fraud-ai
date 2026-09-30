"""Stage 12 container image verification (signature, digest, SLSA provenance, SBOM).

Unit tests drive :func:`fraud_ai.trust.images.verify_image` with a stand-in ``cosign``
that prints what real cosign prints; ``TEST_IMAGE_EVIDENCE`` (with ``TEST_IMAGE_PUBLIC_KEY``)
additionally checks a real signed image with real cosign."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from fraud_ai.trust.images import canonical_sha256, key_fingerprint, verify_image
from fraud_ai.trust.keys import TrustError
from fraud_ai.trust.release import load_image_evidence

DIGEST = "sha256:" + "ab" * 32
COMMIT = "c0ffee" + "0" * 34
PROVENANCE = {
    "buildDefinition": {
        "buildType": "x",
        "resolvedDependencies": [{"uri": "git+repo", "digest": {"gitCommit": COMMIT}}],
    },
    "runDetails": {"builder": {"id": "local:test"}},
}
SBOM = {"bomFormat": "CycloneDX", "components": [{"name": "fraud-ai"}]}

FAKE_COSIGN = """#!/usr/bin/env python3
import base64, json, os, sys
args = sys.argv[1:]
state = json.load(open(os.environ["FAKE_COSIGN_STATE"]))
ref = args[-1]
digest = ref.split("@", 1)[1]
if digest not in state["signed"]:
    print("Error: no signatures found", file=sys.stderr); sys.exit(1)
if args[0] == "verify":
    print(json.dumps([{"critical": {"image": {"docker-manifest-digest": digest}}}]))
    sys.exit(0)
kind = args[args.index("--type") + 1]
predicate = state["predicates"][kind]
statement = {"subject": [{"digest": {"sha256": digest.split(":")[1]}}], "predicate": predicate}
payload = base64.b64encode(json.dumps(statement).encode()).decode()
print(json.dumps({"payloadType": "application/vnd.in-toto+json", "payload": payload}))
"""


@pytest.fixture
def pub(tmp_path: Path) -> Path:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    path = tmp_path / "cosign.pub"
    path.write_bytes(
        key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return path


@pytest.fixture
def cosign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "cosign"
    script.write_text(FAKE_COSIGN)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {"signed": [DIGEST], "predicates": {"slsaprovenance1": PROVENANCE, "cyclonedx": SBOM}}
        )
    )
    monkeypatch.setenv("COSIGN_BINARY", str(script))
    monkeypatch.setenv("FAKE_COSIGN_STATE", str(state))
    return state


def _evidence(pub: Path, **overrides: Any) -> dict[str, Any]:
    evidence = {
        "image": "localhost:5000/fraud-ai",
        "digest": DIGEST,
        "signature_ref": "localhost:5000/fraud-ai:sha256-ab.sig",
        "signing_key_fingerprint": key_fingerprint(pub.read_bytes()),
        "signing_key_ref": "hashivault://fraud-ai-image",
        "provenance_ref": "localhost:5000/fraud-ai:sha256-ab.att",
        "provenance_sha256": canonical_sha256(PROVENANCE),
        "provenance_predicate_type": "https://slsa.dev/provenance/v1",
        "sbom_ref": "localhost:5000/fraud-ai:sha256-ab.att",
        "sbom_sha256": canonical_sha256(SBOM),
    }
    evidence.update(overrides)
    return evidence


def _failed(checks: dict[str, str]) -> set[str]:
    return {name for name, result in checks.items() if result.startswith("FAILED")}


def test_fingerprint_and_canonical_digest(pub: Path) -> None:
    fp = key_fingerprint(pub.read_bytes())
    assert fp.startswith("sha256:") and len(fp) == 71
    assert canonical_sha256({"b": 1, "a": [2]}) == canonical_sha256({"a": [2], "b": 1})
    with pytest.raises(TrustError, match="PEM public key"):
        key_fingerprint(b"not a key")


def test_verified_image(pub: Path, cosign: Path) -> None:
    checks = verify_image(_evidence(pub), public_key=pub, expected_commit=COMMIT)
    assert not _failed(checks), checks
    assert set(checks) == {"image_key", "image_signature", "image_provenance", "image_sbom"}


def test_every_tampering_fails(pub: Path, cosign: Path, tmp_path: Path) -> None:
    # Another image digest (e.g. a rebuilt or modified image): nothing is signed for it.
    other = _evidence(pub, digest="sha256:" + "cd" * 32)
    assert _failed(verify_image(other, public_key=pub)) == {
        "image_signature",
        "image_provenance",
        "image_sbom",
    }
    # Provenance or SBOM changed after the release was recorded.
    edited = _evidence(pub, provenance_sha256="0" * 64, sbom_sha256="1" * 64)
    assert _failed(verify_image(edited, public_key=pub)) == {"image_provenance", "image_sbom"}
    # Provenance for another commit.
    assert "image_provenance" in _failed(
        verify_image(_evidence(pub), public_key=pub, expected_commit="f" * 40)
    )
    # A different verification key than the release names.
    other_pub = tmp_path / "other.pub"
    other_pub.write_bytes(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert "image_key" in _failed(verify_image(_evidence(pub), public_key=other_pub))


def test_evidence_file_is_strictly_checked(pub: Path, tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(_evidence(pub)))
    assert load_image_evidence(path)["digest"] == DIGEST
    path.write_text(json.dumps(_evidence(pub, digest="latest")))
    with pytest.raises(TrustError, match="sha256"):
        load_image_evidence(path)
    bad = _evidence(pub)
    del bad["provenance_sha256"]
    path.write_text(json.dumps(bad))
    with pytest.raises(TrustError, match="lacks provenance_sha256"):
        load_image_evidence(path)


def test_missing_cosign_is_an_error_not_a_pass(pub: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COSIGN_BINARY", "")
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(TrustError, match="cosign is not installed"):
        verify_image(_evidence(pub), public_key=pub)


@pytest.mark.skipif(not os.environ.get("TEST_IMAGE_EVIDENCE"), reason="TEST_IMAGE_EVIDENCE not set")
def test_real_signed_image() -> None:
    evidence = load_image_evidence(Path(os.environ["TEST_IMAGE_EVIDENCE"]))
    key = Path(os.environ["TEST_IMAGE_PUBLIC_KEY"])
    assert not _failed(verify_image(evidence, public_key=key))
    tampered = {**evidence, "digest": "sha256:" + base64.b16encode(os.urandom(32)).decode().lower()}
    assert "image_signature" in _failed(verify_image(tampered, public_key=key))
