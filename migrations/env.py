"""Alembic environment for the fraud database."""

from __future__ import annotations

from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

import fraud_ai.database.models  # noqa: F401 - register all tables on the metadata
from fraud_ai.config.settings import get_settings
from fraud_ai.database.base import Base

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option(
        "sqlalchemy.url", get_settings().resolved_database_url.replace("%", "%%")
    )

target_metadata = Base.metadata


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    assert url is not None
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=_is_sqlite(url),
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = config.get_main_option("sqlalchemy.url")
    assert url is not None
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    sqlite = _is_sqlite(url)
    if sqlite:
        from sqlalchemy import event

        # Batch migrations rebuild tables (copy, drop, rename). With enforcement on,
        # dropping a table other tables reference would fail, so it is disabled for the
        # migration and integrity is verified explicitly afterwards.
        event.listen(connectable, "connect", _disable_sqlite_foreign_keys)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=sqlite,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        if sqlite:
            violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError(f"foreign key violations after migration: {violations[:5]}")


def _disable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=OFF")
    cursor.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
