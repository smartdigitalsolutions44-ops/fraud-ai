import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import reset_settings_cache

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    reset_settings_cache()

    def _run(*args: str, input: str | None = None) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), input=input, catch_exceptions=False)

    return _run


def test_help_lists_only_real_commands(run) -> None:  # type: ignore[no-untyped-def]
    out = run("--help").output
    for command in ("db", "seed", "demo-data", "ingest-event", "system-status"):
        assert command in out
    for future in ("score", "train", "evaluate", "investigate"):
        assert f"  {future} " not in out


def test_db_lifecycle(run) -> None:  # type: ignore[no-untyped-def]
    status = run("db", "status")
    assert status.exit_code == 0 and "<not initialised>" in status.output
    assert run("seed").exit_code != 0  # refuses before init
    init = run("db", "init")
    assert init.exit_code == 0 and "revision 0001" in init.output
    again = run("db", "init")
    assert again.exit_code != 0 and "already initialised" in again.output
    migrate = run("db", "migrate")
    assert migrate.exit_code == 0 and "nothing to do" in migrate.output
    status = run("db", "status")
    assert "up to date: yes" in status.output and "model_predictions" in status.output


def test_db_migrate_from_empty(run) -> None:  # type: ignore[no-untyped-def]
    result = run("db", "migrate")
    assert result.exit_code == 0 and "<empty> -> 0001" in result.output


def test_seed_and_stats(run) -> None:  # type: ignore[no-untyped-def]
    run("db", "init")
    empty = run("demo-data", "stats")
    assert "no synthetic data" in empty.output
    seeded = run("seed", "--users", "12", "--days", "30", "--reference-time", "2026-05-01")
    assert seeded.exit_code == 0, seeded.output
    assert "seeded 12 users" in seeded.output and "account_takeover" in seeded.output
    stats = run("demo-data", "stats")
    assert stats.exit_code == 0
    for scenario in (
        "normal",
        "legitimate_vpn",
        "shared_network",
        "new_home_address",
        "account_takeover",
        "suspicious_velocity",
    ):
        assert scenario in stats.output
    assert "LOGIN_SUCCESS" in stats.output
    twice = run("seed", "--users", "12")
    assert twice.exit_code != 0 and "already contains" in twice.output


def test_ingest_event_file_and_security_rejection(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    run("db", "init")
    sample = ROOT / "scripts" / "sample_events.jsonl"
    first = run("ingest-event", str(sample))
    assert first.exit_code == 0 and "stored 6, duplicates 0, rejected 0" in first.output
    second = run("ingest-event", str(sample))
    assert "stored 0, duplicates 6" in second.output
    bad = {
        "event_type": "PAYMENT_METHOD_ADDED",
        "timestamp": "2026-01-12T00:00:00Z",
        "user_id": "0b8c6f7e-1d2a-4c3b-9e8f-7a6b5c4d0001",
        "source": "api",
        "metadata": {
            "payment_method_id": str(uuid.uuid4()),
            "token_reference": "tok_x_1",
            "card_number": "4111111111111111",
            "cvv": "123",
        },
    }
    rejected = CliRunner().invoke(cli, ["ingest-event", "-"], input=json.dumps([bad]))
    assert rejected.exit_code == 1
    assert "forbidden sensitive data" in rejected.output
    assert "4111111111111111" not in rejected.output


def test_system_status(run) -> None:  # type: ignore[no-untyped-def]
    before = run("system-status")
    assert before.exit_code == 0 and "migration pending" in before.output
    run("db", "init")
    after = run("system-status")
    assert "up to date" in after.output and "active: none" in after.output
    assert "not configured (Stage 7)" in after.output


def test_seed_refused_outside_development(run, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:1/none")
    result = run("seed")
    assert result.exit_code != 0 and "refusing to seed" in result.output


def test_invalid_configuration_reported(run, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ENVIRONMENT", "production")  # with a SQLite URL: invalid
    result = run("db", "status")
    assert result.exit_code != 0 and "invalid configuration" in result.output


def test_python_dash_m_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "fraud_ai", "--version"], capture_output=True, text=True, check=True
    )
    assert "fraud-ai, version 0.1.0" in proc.stdout
