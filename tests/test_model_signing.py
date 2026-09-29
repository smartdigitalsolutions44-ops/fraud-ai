"""Stage 11: signed model artefacts and the read-once verified load."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import select

from fraud_ai.cli.main import cli
from fraud_ai.database.models import ModelArtifactSignature, ModelVersion
from fraud_ai.models.artifact_io import ArtifactBytes, ArtifactReadError
from fraud_ai.models.estimators import ArtifactIntegrityError
from fraud_ai.models.factory import kind_for_name, load_model
from fraud_ai.models.scoring import load_registered_model
from fraud_ai.models.signing import (
    ModelSignatureError,
    ModelTrust,
    check_model_signature,
    sign_model,
)
from fraud_ai.trust import keys as tk
from tests.realtime_world import GB, World, open_world
from tests.service_helpers import make_harness


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


@pytest.fixture(scope="module")
def pair() -> tk.KeyPair:
    return tk.generate()


def _trust(pair: tk.KeyPair, *, required: bool = True) -> ModelTrust:
    return ModelTrust(required=required, keys={pair.key_id: pair.public})


def _model(w: World, name: str = "gradient-boosting") -> ModelVersion:
    with w.session() as s:
        row = s.scalar(select(ModelVersion).where(ModelVersion.model_name == name))
        assert row is not None
        s.expunge(row)
        return row


def _sign_all(w: World, pair: tk.KeyPair) -> None:
    with w.session() as s:
        for model in s.scalars(select(ModelVersion)):
            sign_model(s, model, pair, actor="cli:test")
        s.commit()


def test_signed_model_loads_and_unsigned_is_refused_when_required(
    w: World, pair: tk.KeyPair
) -> None:
    with pytest.raises(ModelSignatureError, match="unsigned"):
        load_registered_model(_model(w), trust=_trust(pair))
    # Not required: an unsigned model still loads (development).
    assert load_registered_model(_model(w), trust=_trust(pair, required=False))
    _sign_all(w, pair)
    model = _model(w)
    assert load_registered_model(model, trust=_trust(pair)) is not None
    assert check_model_signature(model, _trust(pair)) == pair.key_id
    with w.session() as s:
        row = s.scalar(select(ModelArtifactSignature))
        assert row is not None and row.algorithm == "ed25519" and row.key_id == pair.key_id
        assert "estimator.joblib" in row.files and "manifest.json" in row.files
        from fraud_ai import audit

        signed = audit.list_events(s, action="model.signed", limit=10)
        assert signed and signed[0].details["key_id"] == pair.key_id
        assert audit.verify_chain(s).ok


def test_wrong_or_untrusted_signing_key(w: World, pair: tk.KeyPair) -> None:
    other = tk.generate()
    _sign_all(w, other)  # signed, but by a key the service does not trust
    with pytest.raises(ModelSignatureError, match="untrusted key"):
        load_registered_model(_model(w), trust=_trust(pair))
    # A different key with the *same key id claim* cannot pass either: the stored signature
    # is verified with the trusted public key.
    with w.session() as s:
        forged = ModelArtifactSignature(
            model_version_id=_model(w).model_version_id,
            artifact_sha256=str(_model(w).artifact_sha256),
            files={},
            key_id=pair.key_id,
            algorithm="ed25519",
            signature=tk.sign("model", other, {"x": 1}).value,
            signed_by="attacker",
        )
        s.add(forged)
        s.commit()
    with pytest.raises(ModelSignatureError, match="does not verify"):
        load_registered_model(_model(w), trust=_trust(pair))


def test_any_file_change_breaks_the_signature(w: World, pair: tk.KeyPair) -> None:
    _sign_all(w, pair)
    directory = Path(_model(w).model_path)
    # metrics.json is NOT covered by the registered digest, but it is covered by the
    # signature: a changed, added or removed file is refused.
    (directory / "metrics.json").write_text('{"tampered": true}')
    with pytest.raises(ModelSignatureError, match=r"metrics\.json"):
        load_registered_model(_model(w), trust=_trust(pair))
    (directory / "metrics.json").unlink()
    with pytest.raises(ModelSignatureError, match=r"metrics\.json"):
        load_registered_model(_model(w), trust=_trust(pair))
    (directory / "metrics.json").write_text("{}")
    (directory / "extra.bin").write_bytes(b"x")
    with pytest.raises(ModelSignatureError):
        load_registered_model(_model(w), trust=_trust(pair))


def test_digest_is_checked_before_the_signature(w: World, pair: tk.KeyPair) -> None:
    _sign_all(w, pair)
    estimator = Path(_model(w).model_path) / "estimator.joblib"
    estimator.write_bytes(estimator.read_bytes() + b"x")
    with pytest.raises(ArtifactIntegrityError, match="registered digest"):
        load_registered_model(_model(w), trust=_trust(pair))


def test_loader_uses_the_verified_bytes_not_the_path(w: World) -> None:
    """Swapping a file after verification cannot change what is deserialised."""
    model = _model(w)
    directory = Path(model.model_path)
    blob = ArtifactBytes.read(directory)
    (directory / "estimator.joblib").write_bytes(b"not a pickle at all")  # swapped on disk
    loaded = load_model(
        kind_for_name(model.model_name), directory, str(model.artifact_sha256), blob
    )
    assert loaded.estimator is not None  # type: ignore[attr-defined]
    with pytest.raises(ArtifactIntegrityError):  # a fresh read sees the swap and refuses
        load_model(kind_for_name(model.model_name), directory, str(model.artifact_sha256))


def test_gru_loads_from_verified_bytes(w: World, pair: tk.KeyPair) -> None:
    _sign_all(w, pair)
    gru = _model(w, "gru")
    assert load_registered_model(gru, trust=_trust(pair)) is not None
    weights = Path(gru.model_path) / "model.pt"
    weights.write_bytes(weights.read_bytes()[:-10])
    with pytest.raises(Exception, match="digest"):
        load_registered_model(_model(w, "gru"), trust=_trust(pair))


def test_symlinks_and_subdirectories_are_refused(tmp_path: Path) -> None:
    good = tmp_path / "a"
    good.mkdir()
    (good / "f.json").write_text("{}")
    assert ArtifactBytes.read(good).json("f.json") == {}
    (good / "link.json").symlink_to(good / "f.json")
    with pytest.raises(ArtifactReadError, match="refused"):
        ArtifactBytes.read(good)
    (good / "link.json").unlink()
    (good / "sub").mkdir()
    with pytest.raises(ArtifactReadError):
        ArtifactBytes.read(good)
    (good / "sub").rmdir()
    linked_dir = tmp_path / "b"
    linked_dir.symlink_to(good)
    with pytest.raises(ArtifactReadError):
        ArtifactBytes.read(linked_dir)
    with pytest.raises(ArtifactReadError, match="exceeds"):
        ArtifactBytes.read(good, limit=1)


def test_service_refuses_unsigned_models_when_required(w: World, pair: tk.KeyPair) -> None:
    trusted = tk.encode_public(pair.public)
    h = make_harness(
        w.url, engine=w.engine, model_signatures_required=True, model_signing_public_keys=trusted
    )
    try:
        ready = h.get("/v1/ready", None).json()
        assert ready["checks"]["primary_model"] == "failed"
        from fraud_ai.service.startup import startup_problems

        assert any("primary_model" in p for p in startup_problems(h.container))
        cred = h.key()
        for event in w.events:
            r = h.score(cred, event)
            if event["event_type"] == "TRANSACTION_CREATED":
                body = r.json()
                assert body["decision"] == "MANUAL_REVIEW" and body["fallback_used"] is True
                break
    finally:
        h.container.close()
    _sign_all(w, pair)
    h = make_harness(
        w.url, engine=w.engine, model_signatures_required=True, model_signing_public_keys=trusted
    )
    try:
        assert h.get("/v1/ready", None).json()["checks"]["primary_model"] == "ok"
    finally:
        h.container.close()


# ------------------------------------------------------------------ CLI and keys
def _run(env: dict[str, str], *args: str) -> Any:
    from fraud_ai.config.settings import get_settings

    get_settings.cache_clear()  # each invocation reads its own environment
    try:
        return CliRunner().invoke(cli, list(args), env=env, catch_exceptions=False)
    finally:
        get_settings.cache_clear()


def test_keys_and_sign_cli(w: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = {"DATABASE_URL": w.url, "MODEL_DIRECTORY": str(w.root / "models")}
    key = tmp_path / "model.pem"
    out = _run(env, "keys", "generate", "--purpose", "model", "--out", str(key))
    assert out.exit_code == 0 and "public key" in out.output
    assert oct(key.stat().st_mode)[-3:] == "600"
    public = next(line.split()[-1] for line in out.output.splitlines() if "public key" in line)
    again = _run(env, "keys", "generate", "--purpose", "model", "--out", str(key))
    assert again.exit_code != 0 and "refusing to overwrite" in again.output
    trusted = {**env, "MODEL_SIGNING_PUBLIC_KEYS": public}

    unsigned = _run(trusted, "models", "verify-signature", GB)
    assert unsigned.exit_code == 0 and "UNSIGNED" in unsigned.output
    required = _run(
        {**trusted, "MODEL_SIGNATURES_REQUIRED": "true"}, "models", "verify-signature", GB
    )
    assert required.exit_code != 0 and "NOT VERIFIED" in required.output

    signed = _run(trusted, "models", "sign", GB, "--key", str(key))
    assert signed.exit_code == 0, signed.output
    ok = _run({**trusted, "MODEL_SIGNATURES_REQUIRED": "true"}, "models", "verify-signature", GB)
    assert ok.exit_code == 0 and "signature OK" in ok.output

    # Key separation: an audit key is not a model key.
    audit_key = tmp_path / "audit.pem"
    audit_out = _run(env, "keys", "generate", "--purpose", "audit", "--out", str(audit_key))
    audit_public = next(
        line.split()[-1] for line in audit_out.output.splitlines() if "public key" in line
    )
    wrong = _run(trusted, "models", "sign", GB, "--key", str(audit_key))
    assert wrong.exit_code != 0 and "not in MODEL_SIGNING_PUBLIC_KEYS" in wrong.output
    both = _run({**trusted, "AUDIT_ANCHOR_PUBLIC_KEYS": public}, "models", "list")
    assert both.exit_code != 0 or "each purpose needs its own key" in both.output
    assert audit_public != public

    # A private key readable by others is refused.
    os.chmod(key, 0o644)
    loose = _run(trusted, "models", "sign", GB, "--key", str(key))
    assert loose.exit_code != 0 and "chmod 600" in loose.output
