"""Stage 10 migration failure and recovery.

A deliberately broken revision (creates a table, then fails) is appended to a copy of the
migrations. Upgrading must fail loudly and leave the schema at the last good revision
without the half-applied change: the whole upgrade runs in one transaction, and both
PostgreSQL and SQLite roll DDL back. The recovery procedure (fix the revision, re-run
``db migrate``) is then exercised. See DISASTER_RECOVERY.md.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from sqlalchemy import Engine, inspect

from fraud_ai.database import migrations as mig

BROKEN = '''"""Deliberately broken test revision.

Revision ID: 0009
Revises: 0008
Create Date: 2026-12-01 00:00:00
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("half_applied", sa.Column("id", sa.Integer(), primary_key=True))
    op.add_column("audit_events", sa.Column("broken_column", sa.Integer(), nullable=True))
    raise RuntimeError("simulated migration failure")


def downgrade() -> None:
    pass
'''


@pytest.fixture
def broken_migrations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "migrations"
    shutil.copytree(
        mig.migrations_directory(), target, ignore=shutil.ignore_patterns("__pycache__")
    )
    (target / "versions" / "20261201_0009_broken.py").write_text(BROKEN)
    monkeypatch.setenv("FRAUD_AI_MIGRATIONS_DIR", str(target))
    return target


def test_failed_migration_leaves_the_last_good_schema(
    any_engine: Engine, backend_url: str, broken_migrations: Path
) -> None:
    assert mig.current_revision(any_engine) == "0008"  # any_engine migrates the real head
    with pytest.raises(RuntimeError, match="simulated migration failure"):
        mig.upgrade(backend_url)
    any_engine.dispose()
    tables = set(inspect(any_engine).get_table_names())
    columns = {c["name"] for c in inspect(any_engine).get_columns("audit_events")}
    assert mig.current_revision(any_engine) == "0008"
    assert "half_applied" not in tables and "broken_column" not in columns
    # Recovery: fix the revision and migrate again.
    fixed = BROKEN.replace('    raise RuntimeError("simulated migration failure")\n', "")
    (broken_migrations / "versions" / "20261201_0009_broken.py").write_text(fixed)
    mig.upgrade(backend_url)
    any_engine.dispose()
    assert mig.current_revision(any_engine) == "0009"
    assert "half_applied" in set(inspect(any_engine).get_table_names())
