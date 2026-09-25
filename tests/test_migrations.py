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
    assert head_revision("sqlite://") == "0001"


def test_upgrade_creates_all_tables(any_engine: Engine, backend_url: str) -> None:
    status = schema_status(any_engine, backend_url)
    assert status.up_to_date and status.current == "0001"
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
