"""Stage 12 demo: the guard that keeps `demo reset` away from any non-demo database, and
one full (small) demo world driven end to end through the real service and CLI."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.config.settings import Environment, reset_settings_cache
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.demo.guard import MARKER, DemoGuardError, check_target
from fraud_ai.trust.operators import OperatorRegistry, check_registry_separation
from tests.service_process import running_service


def _settings(url: str, *, demo: bool = True, env: Environment = Environment.DEVELOPMENT) -> Any:
    return SimpleNamespace(demo_mode=demo, environment=env, resolved_database_url=url)


def _db(tmp_path: Path, name: str, first_action: str | None) -> str:
    url = f"sqlite:///{tmp_path / name}"
    upgrade(url)
    if first_action is not None:
        engine = create_db_engine(url)
        with session_scope(make_session_factory(engine)) as s:
            audit.record(s, first_action, actor="cli:test", target_type="test")
            audit.record(s, MARKER, actor="cli:test", target_type="demo")
        engine.dispose()
    return url


def _check(url: str, **kw: Any) -> None:
    engine = create_db_engine(url)
    try:
        check_target(_settings(url, **kw), engine)
    finally:
        engine.dispose()


def test_guard_accepts_new_empty_and_marked_demo_databases(tmp_path: Path) -> None:
    _check(f"sqlite:///{tmp_path / 'fraud_ai_demo.db'}")  # does not exist yet
    empty = create_db_engine(f"sqlite:///{tmp_path / 'empty_demo.db'}")
    with empty.begin() as conn:
        conn.exec_driver_sql("SELECT 1")  # creates the file, no tables
    empty.dispose()
    _check(f"sqlite:///{tmp_path / 'empty_demo.db'}", env=Environment.TEST)
    _check(_db(tmp_path, "marked_demo.db", MARKER))


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"demo": False}, "DEMO_MODE=true"),
        ({"env": Environment.STAGING}, "refused in the staging profile"),
        ({"env": Environment.PRODUCTION}, "refused in the production profile"),
    ],
)
def test_guard_refuses_without_demo_mode_or_outside_development(
    tmp_path: Path, kw: dict[str, Any], message: str
) -> None:
    with pytest.raises(DemoGuardError, match=message):
        _check(_db(tmp_path, "marked_demo.db", MARKER), **kw)


def test_guard_refuses_databases_not_named_as_demo(tmp_path: Path) -> None:
    with pytest.raises(DemoGuardError, match=r"\*_demo.db"):
        _check(_db(tmp_path, "fraud_ai.db", MARKER))
    with pytest.raises(DemoGuardError, match="must end in _demo"):
        check_target(_settings("postgresql+psycopg://u:p@db/fraud_ai"), engine=None)  # type: ignore[arg-type]
    with pytest.raises(DemoGuardError, match="unsupported demo backend"):
        check_target(_settings("mysql://u:p@db/x_demo"), engine=None)  # type: ignore[arg-type]


def test_guard_refuses_a_demo_named_database_with_other_history(tmp_path: Path) -> None:
    # Named like a demo database, but its FIRST audit event is not the marker (the marker
    # appearing later does not help): refused whatever its name.
    with pytest.raises(DemoGuardError, match="not created by `fraud-ai demo reset`"):
        _check(_db(tmp_path, "real_demo.db", "policy.activated"))
    # Migrated but without any audit history: it may still hold data, so refused too.
    with pytest.raises(DemoGuardError, match="its first audit event is None"):
        _check(_db(tmp_path, "migrated_demo.db", None))
    other = create_db_engine(f"sqlite:///{tmp_path / 'tables_demo.db'}")
    with other.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE users (id INTEGER)")
    other.dispose()
    with pytest.raises(DemoGuardError, match="no demo marker"):
        _check(f"sqlite:///{tmp_path / 'tables_demo.db'}")


def test_demo_reset_cli_refuses_other_databases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    root = tmp_path / "demo"
    refused = runner.invoke(cli, ["demo", "reset", "--root", str(root)])
    assert refused.exit_code != 0 and "DEMO_MODE=true" in refused.output
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'fraud_ai.db'}")
    reset_settings_cache()
    elsewhere = runner.invoke(cli, ["demo", "reset", "--root", str(root)])
    assert elsewhere.exit_code != 0 and "points elsewhere" in elsewhere.output
    assert not (root / "fraud_ai_demo.db").exists()


def test_demo_world_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A small demo world (200 users: the CLI minimum, enough validation fraud to derive
    the policy bands): reset twice (the second passes the marker check),
    then the 9-step walkthrough against the real service. Every scored case must get
    exactly the catalogue's measured decision; missing cases are listed, never faked."""
    from fraud_ai.demo.walkthrough import run
    from fraud_ai.demo.world import load_env

    root = tmp_path / "demo"
    monkeypatch.setenv("DEMO_MODE", "true")
    reset_settings_cache()
    runner = CliRunner()
    first = runner.invoke(cli, ["demo", "reset", "--root", str(root), "--users", "200"])
    assert first.exit_code == 0, first.output
    secrets_before = load_env(root)
    second = runner.invoke(cli, ["demo", "reset", "--root", str(root), "--users", "200"])
    assert second.exit_code == 0, second.output
    env = load_env(root)
    assert env["PSEUDONYMISATION_KEY"] == secrets_before["PSEUDONYMISATION_KEY"]
    assert env["ENVIRONMENT"] == "development" and env["DEMO_MODE"] == "true"

    catalogue = json.loads((root / "catalogue.json").read_text())
    assert catalogue["synthetic"] is True and catalogue["users"] == 200
    labels = {c["label"] for c in catalogue["cases"]}
    assert len(labels) + len(catalogue["missing_cases"]) == 10
    assert not labels & set(catalogue["missing_cases"])
    for private in ("demo.env", "demo-credentials.json"):
        assert stat.S_IMODE((root / private).stat().st_mode) == 0o600
    registry = OperatorRegistry.load(root / "operators.json")
    check_registry_separation(
        registry,
        SimpleNamespace(
            model_signing_public_keys=env["MODEL_SIGNING_PUBLIC_KEYS"],
            audit_anchor_public_keys=env["AUDIT_ANCHOR_PUBLIC_KEYS"],
            release_signing_public_keys=env["RELEASE_SIGNING_PUBLIC_KEYS"],
        ),
    )
    assert set(registry.operators) == {"alice", "bob", "carol", "rita", "sec"}

    lines: list[str] = []
    with running_service(env, workers=1, log_dir=tmp_path) as svc:
        results = run(root, svc.base_url, echo=lines.append)
    steps = results["steps"]
    assert steps["ready"] == "ready", "\n".join(lines)
    decisions = steps.get("decisions", {})
    expected = {c["label"]: c["expected_decision"] for c in catalogue["cases"]}
    scored = {k: v for k, v in decisions.items() if k in expected}
    assert scored == {k: expected[k] for k in scored}, "\n".join(lines)
    assert set(decisions) <= labels
    assert steps["anchors"] and steps["model_signature"] and steps["release"], "\n".join(lines)
    assert steps["llm"] in (200, None) or "llm" not in steps
    assert "SYNTHETIC" in lines[-1]
