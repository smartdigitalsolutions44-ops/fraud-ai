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
    for command in ("train", "models", "evaluate", "compare-models", "score"):  # Stage 3
        assert f"  {command} " in out
    for command in ("investigate", "llm"):  # Stage 7
        assert f"  {command} " in out
    for command in ("realtime", "policy", "deployment", "review", "monitoring"):  # Stage 8
        assert f"  {command} " in out
    for command in ("service", "service-key"):  # Stage 9
        assert f"  {command} " in out


def test_db_lifecycle(run) -> None:  # type: ignore[no-untyped-def]
    status = run("db", "status")
    assert status.exit_code == 0 and "<not initialised>" in status.output
    assert run("seed").exit_code != 0  # refuses before init
    init = run("db", "init")
    assert init.exit_code == 0 and "revision 0008" in init.output
    again = run("db", "init")
    assert again.exit_code != 0 and "already initialised" in again.output
    migrate = run("db", "migrate")
    assert migrate.exit_code == 0 and "nothing to do" in migrate.output
    status = run("db", "status")
    assert "up to date: yes" in status.output and "model_predictions" in status.output


def test_db_migrate_from_empty(run) -> None:  # type: ignore[no-untyped-def]
    result = run("db", "migrate")
    assert result.exit_code == 0 and "<empty> -> 0008" in result.output


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
    assert "local LLM       not configured (explanations only" in after.output
    assert "investigations 0" in after.output


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


# --------------------------------------------------------------------------- Stage 2
def _seed_small(run) -> None:  # type: ignore[no-untyped-def]
    run("db", "init")
    result = run("seed", "--users", "12", "--days", "30", "--reference-time", "2026-05-01")
    assert result.exit_code == 0, result.output


def test_features_catalog(run) -> None:  # type: ignore[no-untyped-def]
    table = run("features", "catalog")
    assert table.exit_code == 0 and "fraud-features-1.0.0" in table.output
    assert "account_age_days" in table.output
    as_json = json.loads(run("features", "catalog", "--format", "json").output)
    assert len(as_json["features"]) >= 100
    assert "BEGIN GENERATED" in run("features", "catalog", "--format", "markdown").output
    bad = run("features", "catalog", "--version", "nope")
    assert bad.exit_code != 0 and "unknown feature version" in bad.output


def test_features_show_snapshot_validate(run) -> None:  # type: ignore[no-untyped-def]
    _seed_small(run)
    from sqlalchemy import select

    from fraud_ai.config.settings import get_settings
    from fraud_ai.database import engine_from_settings, make_session_factory
    from fraud_ai.database.models import EventRecord
    from fraud_ai.features.context import SCORABLE_EVENT_TYPES

    engine = engine_from_settings(get_settings())
    with make_session_factory(engine)() as s:
        event_id = str(
            s.scalar(
                select(EventRecord.event_id)
                .where(EventRecord.event_type.in_(SCORABLE_EVENT_TYPES))
                .order_by(EventRecord.occurred_at.desc())
            )
        )
    shown = run("features", "show", event_id)
    assert shown.exit_code == 0 and "hash" in shown.output and "<not_" in shown.output
    payload = json.loads(run("features", "show", event_id, "--format", "json").output)
    assert (
        payload["feature_version"] == "fraud-features-1.0.0" and len(payload["feature_hash"]) == 64
    )
    later = json.loads(
        run("features", "show", event_id, "--format", "json", "--as-of", "2026-06-01").output
    )
    assert later["as_of_timestamp"].startswith("2026-06-01")
    assert run("features", "show", "not-a-uuid").exit_code != 0
    missing = run("features", "show", str(uuid.uuid4()))
    assert missing.exit_code != 0 and "unknown event" in missing.output

    assert run("features", "snapshot").exit_code != 0  # needs ids or a range
    first = run("features", "snapshot", "--start", "2026-04-25", "--end", "2026-05-01")
    assert first.exit_code == 0 and " created" in first.output
    again = run("features", "snapshot", "--start", "2026-04-25", "--end", "2026-05-01")
    assert "0 created" in again.output
    by_id = run("features", "snapshot", event_id)
    assert by_id.exit_code == 0 and "0 created, 1 already present" in by_id.output
    ok = run("features", "validate")
    assert ok.exit_code == 0 and "0 failed" in ok.output

    from sqlalchemy import update

    from fraud_ai.database.models import FeatureSnapshot

    with make_session_factory(engine)() as s:
        s.execute(update(FeatureSnapshot).values(feature_hash="0" * 64))
        s.commit()
    engine.dispose()
    broken = run("features", "validate", "--limit", "3")
    assert broken.exit_code == 1 and "3 failed" in broken.output


def test_dataset_build(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _seed_small(run)
    out = tmp_path / "ds"
    result = run(
        "dataset",
        "build",
        "--start",
        "2026-04-01",
        "--end",
        "2026-05-01",
        "--label-cutoff",
        "2026-05-01",
        "--output",
        str(out),
        "--maturity-days",
        "0",
        "--persist-snapshots",
    )
    assert result.exit_code == 0, result.output
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["examples"] > 0 and manifest["snapshots_created"] > 0
    assert (out / "features.jsonl").exists() and (out / "labels.jsonl").exists()
    reuse = run(
        "dataset",
        "build",
        "--start",
        "2026-04-01",
        "--end",
        "2026-05-01",
        "--label-cutoff",
        "2026-05-01",
        "--output",
        str(tmp_path / "ds2"),
        "--use-snapshots",
        "--kind",
        "transaction",
        "--implicit-negatives",
    )
    assert reuse.exit_code == 0, reuse.output
    too_late = run(
        "dataset",
        "build",
        "--start",
        "2026-04-01",
        "--end",
        "2026-05-02",
        "--label-cutoff",
        "2026-05-01",
        "--output",
        str(tmp_path / "x"),
    )
    assert too_late.exit_code != 0 and "label cutoff" in too_late.output


def test_system_status_reports_feature_engine(run) -> None:  # type: ignore[no-untyped-def]
    run("db", "init")
    out = run("system-status").output
    assert "fraud-features-1.0.0" in out and "snapshots" in out
