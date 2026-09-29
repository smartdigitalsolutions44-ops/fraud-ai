"""Stage 11 signed release manifests: build, sign, verify, and detect tampering."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import select

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import get_settings
from fraud_ai.database.engine import session_scope
from fraud_ai.database.models import ModelVersion
from fraud_ai.models.signing import ModelTrust, sign_model
from fraud_ai.risk.registry import activate
from fraud_ai.trust import keys as tk
from fraud_ai.trust.release import build_manifest, sign_manifest, verify_release
from tests.realtime_world import P2, World, open_world


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


@pytest.fixture(scope="module")
def release_key() -> tk.KeyPair:
    return tk.generate()


@pytest.fixture(scope="module")
def model_key() -> tk.KeyPair:
    return tk.generate()


def _signed_world(w: World, model_key: tk.KeyPair) -> None:
    with w.session() as s:
        for model in s.scalars(select(ModelVersion)):
            sign_model(s, model, model_key, actor="cli:test")
        s.commit()


def _document(w: World, key: tk.KeyPair, sbom: Path | None = None) -> dict[str, Any]:
    with w.session() as s:
        manifest = build_manifest(s, w.url, sbom=sbom, image_digest="sha256:" + "ab" * 32)
    return sign_manifest(manifest, key)


def test_manifest_contents_and_verification(
    w: World, tmp_path: Path, release_key: tk.KeyPair, model_key: tk.KeyPair
) -> None:
    _signed_world(w, model_key)
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"bomFormat": "CycloneDX"}')
    doc = _document(w, release_key, sbom)
    m = doc["manifest"]
    assert m["migration_revision"] == m["code_head_revision"] == "0009"
    assert m["api_version"] and m["feature_version"] and m["sequence_version"]
    assert m["policy"]["policy_version"] and len(m["policy"]["definition_sha256"]) == 64
    assert {x["ref"] for x in m["models"]} >= {"gradient-boosting-1.0.0", "gru-1.0.0"}
    assert all(x["signature"]["key_id"] == model_key.key_id for x in m["models"])
    assert m["sbom"]["sha256"] and m["container_image"]["digest"].startswith("sha256:")
    trust = ModelTrust(required=True, keys={model_key.key_id: model_key.public})
    with w.session() as s:
        report = verify_release(
            doc, {release_key.key_id: release_key.public}, session=s, sbom=sbom, model_trust=trust
        )
    assert report.ok, report.checks
    assert report.checks["signature"].startswith("ok")
    assert all(v.startswith("ok") for k, v in report.checks.items() if k.startswith("model "))


def test_tampering_is_detected(
    w: World, tmp_path: Path, release_key: tk.KeyPair, model_key: tk.KeyPair
) -> None:
    _signed_world(w, model_key)
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")
    doc = _document(w, release_key, sbom)
    trusted = {release_key.key_id: release_key.public}
    # 1. an edited manifest no longer matches its signature
    edited = json.loads(json.dumps(doc))
    edited["manifest"]["models"][0]["artifact_sha256"] = "0" * 64
    assert verify_release(edited, trusted).checks["signature"].startswith("FAILED")
    # 2. a model key (or any other key) cannot sign releases
    wrong = sign_manifest(doc["manifest"], model_key)
    assert "not trusted" in verify_release(wrong, trusted).checks["signature"]
    with pytest.raises(tk.TrustError, match="RELEASE_SIGNING_PUBLIC_KEYS"):
        sign_manifest(doc["manifest"], model_key, trusted)
    # 3. a changed SBOM
    sbom.write_text('{"changed": true}')
    assert verify_release(doc, trusted, sbom=sbom).checks["sbom"].startswith("FAILED")
    # 4. the environment drifted: another policy was activated after the release
    with session_scope(w.factory) as s:
        activate(s, P2, note="drift")
    with w.session() as s:
        report = verify_release(doc, trusted, session=s)
    assert report.checks["policy"].startswith("FAILED") and not report.ok
    # 5. a model file changed on disk after release
    with w.session() as s:
        gb = s.scalar(select(ModelVersion).where(ModelVersion.model_name == "gradient-boosting"))
        assert gb is not None
        (Path(gb.model_path) / "metrics.json").write_text("{}")
        trust = ModelTrust(required=True, keys={model_key.key_id: model_key.public})
        report = verify_release(doc, trusted, session=s, model_trust=trust)
    assert report.checks["model gradient-boosting-1.0.0"].startswith("FAILED")


def test_release_cli(w: World, tmp_path: Path) -> None:
    def run(env: dict[str, str], *args: str) -> Any:
        get_settings.cache_clear()
        try:
            return CliRunner().invoke(cli, list(args), env=env)
        finally:
            get_settings.cache_clear()

    key = tmp_path / "release.pem"
    out = run({}, "keys", "generate", "--purpose", "release", "--out", str(key))
    public = next(line.split()[-1] for line in out.output.splitlines() if "public key" in line)
    env = {"DATABASE_URL": w.url, "RELEASE_SIGNING_PUBLIC_KEYS": public}
    manifest = tmp_path / "release.json"
    made = run(env, "release", "manifest", "--out", str(manifest), "--key", str(key))
    assert made.exit_code == 0, made.output
    again = run(env, "release", "manifest", "--out", str(manifest), "--key", str(key))
    assert again.exit_code != 0 and "refusing to overwrite" in again.output
    ok = run(env, "release", "verify", str(manifest))
    assert ok.exit_code == 0 and "release manifest verified" in ok.output, ok.output
    assert "unsigned" in ok.output  # models not signed in this world: reported, not hidden
    doc = json.loads(manifest.read_text())
    doc["manifest"]["policy"]["policy_version"] = "risk-policy-9.9.9"
    manifest.write_text(json.dumps(doc))
    bad = run(env, "release", "verify", str(manifest), "--no-database")
    assert bad.exit_code != 0 and "FAILED" in bad.output
