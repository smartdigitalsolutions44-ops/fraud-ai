"""Programmatic access to Alembic migrations (used by the CLI and tests)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect

from fraud_ai.utils.logging import get_logger

log = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def migrations_directory() -> Path:
    override = os.environ.get("FRAUD_AI_MIGRATIONS_DIR")
    path = Path(override) if override else PROJECT_ROOT / "migrations"
    if not (path / "env.py").exists():
        raise FileNotFoundError(f"Alembic migrations directory not found at {path}")
    return path


def alembic_config(database_url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_directory()))
    # Escape % for configparser interpolation (URL-encoded passwords).
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    cfg.attributes["configure_logger"] = False
    return cfg


def head_revision(database_url: str) -> str | None:
    return ScriptDirectory.from_config(alembic_config(database_url)).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def upgrade(database_url: str, revision: str = "head") -> None:
    log.info("applying database migrations up to %s", revision)
    command.upgrade(alembic_config(database_url), revision)
    log.info("database migrations complete")


def downgrade(database_url: str, revision: str) -> None:
    log.info("downgrading database to %s", revision)
    command.downgrade(alembic_config(database_url), revision)


@dataclass(frozen=True)
class SchemaStatus:
    current: str | None
    head: str | None
    tables: list[str]

    @property
    def initialised(self) -> bool:
        return self.current is not None

    @property
    def up_to_date(self) -> bool:
        return self.current is not None and self.current == self.head


def schema_status(engine: Engine, database_url: str) -> SchemaStatus:
    tables = sorted(t for t in inspect(engine).get_table_names() if t != "alembic_version")
    return SchemaStatus(
        current=current_revision(engine), head=head_revision(database_url), tables=tables
    )
