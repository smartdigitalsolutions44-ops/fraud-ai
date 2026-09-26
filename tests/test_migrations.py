import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect

from fraud_ai.database.base import Base
from fraud_ai.database.engine import create_db_engine
from fraud_ai.database.migrations import (
    downgrade,
    head_revision,
    migrations_directory,
    schema_status,
    upgrade,
)

EXPECTED_TABLES = {
    "users",
    "feature_snapshots",
    "model_calibrations",
    "devices",
    "user_devices",
    "login_events",
    "network_events",
    "network_identities",
    "addresses",
    "payment_methods",
    "transactions",
    "security_events",
    "fraud_signals",
    "risk_assessments",
    "fraud_labels",
    "model_predictions",
    "model_versions",
    "events",
}


def test_single_linear_head() -> None:
    assert migrations_directory().joinpath("env.py").exists()
    assert head_revision("sqlite://") == "0004"


def test_upgrade_creates_all_tables(any_engine: Engine, backend_url: str) -> None:
    status = schema_status(any_engine, backend_url)
    assert status.up_to_date and status.current == "0004"
    assert set(status.tables) == EXPECTED_TABLES
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_migration_matches_models(any_engine: Engine) -> None:
    """The migration and the ORM models must describe exactly the same schema."""
    with any_engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == []


def test_check_constraints_created(any_engine: Engine) -> None:
    names = {c["name"] for c in inspect(any_engine).get_check_constraints("transactions")}
    assert {
        "ck_transactions_amount_non_negative",
        "ck_transactions_currency_iso4217",
        "ck_transactions_transaction_status",
    } <= names


def test_downgrade_to_base_and_back(backend_url: str) -> None:
    upgrade(backend_url)
    downgrade(backend_url, "base")
    engine = create_db_engine(backend_url)
    try:
        status = schema_status(engine, backend_url)
        assert status.current is None and status.tables == []
    finally:
        engine.dispose()
    upgrade(backend_url)
    engine = create_db_engine(backend_url)
    try:
        assert schema_status(engine, backend_url).up_to_date
    finally:
        engine.dispose()


def _check_constraints(engine: Engine) -> dict[str, set[str]]:
    insp = inspect(engine)
    return {
        t: {c["name"] for c in insp.get_check_constraints(t)}
        for t in insp.get_table_names()
        if t != "alembic_version"
    }


def test_migrated_constraints_match_models(any_engine: Engine, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Alembic's autogenerate ignores CHECK constraints; compare them explicitly against a
    schema created directly from the models (this catches batch-migration losses)."""
    fresh = create_db_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    Base.metadata.create_all(fresh)
    try:
        assert _check_constraints(any_engine) == _check_constraints(fresh)
    finally:
        fresh.dispose()


def test_upgrade_0001_to_0002_backfills_existing_data(backend_url: str) -> None:
    """Data written under 0001 survives the table rebuilds and is backfilled correctly."""
    from sqlalchemy import text

    upgrade(backend_url, "0001")
    engine = create_db_engine(backend_url)
    ts = "2026-01-01 10:00:00.000000"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (user_id, external_ref, account_created_at, status, created_at, "
                "updated_at) VALUES (:u, 'r', :t, 'active', :t, :t)"
            ),
            {
                "u": "11111111111141118111111111111111"
                if engine.dialect.name == "sqlite"
                else "11111111-1111-4111-8111-111111111111",
                "t": ts,
            },
        )
        uid = conn.execute(text("SELECT user_id FROM users")).scalar()
        for i, status in enumerate(("APPROVED", "CHARGEBACK", "DECLINED", "PENDING")):
            eid = f"2222222222224222822222222222222{i}"
            tid = f"3333333333334333833333333333333{i}"
            if engine.dialect.name != "sqlite":
                eid = f"{eid[:8]}-{eid[8:12]}-{eid[12:16]}-{eid[16:20]}-{eid[20:]}"
                tid = f"{tid[:8]}-{tid[8:12]}-{tid[12:16]}-{tid[16:20]}-{tid[20:]}"
            conn.execute(
                text(
                    "INSERT INTO events (event_id, event_type, occurred_at, user_id, source, "
                    "metadata, schema_version, ingested_at) VALUES (:e, 'TRANSACTION_CREATED', :t, "
                    ":u, 'api', '{}', 1, :t)"
                ),
                {"e": eid, "t": ts, "u": uid},
            )
            conn.execute(
                text(
                    "INSERT INTO transactions (transaction_id, event_id, user_id, amount_minor, "
                    "currency, channel, status, occurred_at, decided_at) VALUES (:x, :e, :u, 100, "
                    "'GBP', 'web', :s, :t, :d)"
                ),
                {
                    "x": tid,
                    "e": eid,
                    "u": uid,
                    "s": status,
                    "t": ts,
                    "d": None if status == "PENDING" else ts,
                },
            )
    engine.dispose()
    upgrade(backend_url)
    engine = create_db_engine(backend_url)
    with engine.connect() as conn:
        rows = dict(conn.execute(text("SELECT status, decision_outcome FROM transactions")).all())
        assert conn.execute(text("SELECT count(*) FROM events")).scalar() == 4
    engine.dispose()
    assert rows == {
        "APPROVED": "APPROVED",
        "CHARGEBACK": "APPROVED",
        "DECLINED": "DECLINED",
        "PENDING": None,
    }


def test_downgrade_refuses_to_drop_new_event_types(backend_url: str) -> None:
    from sqlalchemy import text

    upgrade(backend_url)
    engine = create_db_engine(backend_url)
    uid = "44444444-4444-4444-8444-444444444444"
    eid = "55555555-5555-4555-8555-555555555555"
    if engine.dialect.name == "sqlite":
        uid, eid = uid.replace("-", ""), eid.replace("-", "")
    ts = "2026-01-01 10:00:00.000000"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (user_id, external_ref, account_created_at, status, created_at, "
                "updated_at) VALUES (:u, 'r2', :t, 'active', :t, :t)"
            ),
            {"u": uid, "t": ts},
        )
        conn.execute(
            text(
                "INSERT INTO events (event_id, event_type, occurred_at, user_id, source, metadata, "
                "schema_version, ingested_at) VALUES (:e, 'EMAIL_CHANGED', :t, :u, 'api', '{}', 1, "
                ":t)"
            ),
            {"e": eid, "t": ts, "u": uid},
        )
    engine.dispose()
    with pytest.raises(Exception):  # noqa: B017 - backend-specific integrity error
        downgrade(backend_url, "0001")
