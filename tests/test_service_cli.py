"""Stage 9 CLI: ``service-key`` and ``service`` commands."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from sqlalchemy import select

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import reset_settings_cache
from fraud_ai.database.engine import create_db_engine, make_session_factory
from fraud_ai.database.models import ServiceApiKey
from tests.realtime_world import open_world
from tests.service_helpers import MASTER_KEY

Runner = Callable[..., Result]


@pytest.fixture
def run(sqlite_url: str, monkeypatch: pytest.MonkeyPatch) -> Runner:
    monkeypatch.setenv("DATABASE_URL", sqlite_url)

    def _run(*args: str) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), catch_exceptions=False)

    return _run


def test_service_key_lifecycle(
    run: Runner, sqlite_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    created = run(
        "service-key",
        "create",
        "--name",
        "checkout",
        "--scope",
        "score:write",
        "--scope",
        "assessment:read",
    )
    assert created.exit_code == 0, created.output
    credential = next(
        line.split()[1] for line in created.output.splitlines() if line.startswith("credential")
    )
    key_id, secret = credential.split(".", 1)
    assert "not shown again" in created.output
    listed = run("service-key", "list")
    assert key_id in listed.output and "active" in listed.output and secret not in listed.output
    assert secret not in caplog.text
    engine = create_db_engine(sqlite_url)
    with make_session_factory(engine)() as s:
        row = s.scalar(select(ServiceApiKey))
        assert row is not None and secret not in row.secret_sha256
    engine.dispose()
    revoked = run("service-key", "revoke", key_id)
    assert revoked.exit_code == 0 and "revoked" in revoked.output
    assert "revoked" in run("service-key", "list").output
    assert run("service-key", "revoke", "fak_0000000000000000").exit_code != 0
    bad = run("service-key", "create", "--name", "x", "--scope", "root")
    assert bad.exit_code != 0 and "unknown scope" in bad.output
    no_master = run(
        "service-key", "create", "--name", "x", "--scope", "score:write", "--show-signing-secret"
    )
    assert no_master.exit_code != 0
    monkeypatch.setenv("SERVICE_SIGNING_MASTER_KEY", MASTER_KEY)
    signed = run(
        "service-key", "create", "--name", "x", "--scope", "score:write", "--show-signing-secret"
    )
    assert signed.exit_code == 0 and "signing" in signed.output
    assert MASTER_KEY not in signed.output
    scopes = run("service-key", "scopes")
    assert "score:write" in scopes.output and "signals:trusted" in scopes.output


def test_service_key_list_empty(run: Runner) -> None:
    assert "no service keys" in run("service-key", "list").output


def test_service_status_not_ready_on_empty_database(run: Runner) -> None:
    result = run("service", "status")
    assert result.exit_code == 1
    assert "active_policy missing" in result.output and "ready           NO" in result.output
    assert (
        "forwarding headers ignored" in result.output
        and "cors            disabled" in result.output
    )


def test_service_status_ready_on_the_world(
    realtime_world_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for w in open_world(realtime_world_dir, tmp_path):
        monkeypatch.setenv("DATABASE_URL", w.url)
        monkeypatch.setenv("PAYMENT_AUTH_PROVIDER", "fake")
        monkeypatch.setenv("PAYMENT_AUTH_WEBHOOK_SECRET", "w" * 40)
        reset_settings_cache()
        result = CliRunner().invoke(cli, ["service", "status"], catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert "ready           yes" in result.output
        assert "DEVELOPMENT FAKE" in result.output


def test_service_openapi(run: Runner, tmp_path: Path) -> None:
    printed = run("service", "openapi")
    doc = json.loads(printed.output)
    assert "/v1/score" in doc["paths"] and "/v1/ready" in doc["paths"]
    target = tmp_path / "openapi.json"
    assert run("service", "openapi", "--output", str(target)).exit_code == 0
    assert json.loads(target.read_text())["info"]["title"] == "fraud-ai service"


def test_service_run_uses_safe_uvicorn_options(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    seen: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw, app=app))
    result = run("service", "run", "--port", "9999")
    assert result.exit_code == 0, result.output
    assert seen["app"] == "fraud_ai.service.startup:serve_app" and seen["factory"] is True
    assert seen["proxy_headers"] is False and seen["server_header"] is False
    assert seen["host"] == "127.0.0.1" and seen["port"] == 9999
    public = run("service", "run", "--host", "0.0.0.0")  # noqa: S104 - the warning is tested
    assert "TLS is required in production" in public.output


def test_service_run_requires_a_migrated_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    reset_settings_cache()
    result = CliRunner().invoke(cli, ["service", "run"])
    assert result.exit_code != 0 and "not initialised" in result.output


def test_service_commands_refuse_unsafe_production_settings(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@127.0.0.1:1/x")
    for command in (("service", "status"), ("service", "run")):
        reset_settings_cache()
        result = CliRunner().invoke(cli, list(command))
        assert result.exit_code != 0
        assert "https WEBAUTHN_ORIGIN" in result.output
