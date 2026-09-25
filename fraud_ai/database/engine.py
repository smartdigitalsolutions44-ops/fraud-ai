"""Engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai.config.settings import Settings


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_db_engine(url: str, *, echo: bool = False) -> Engine:
    sa_url = make_url(url)
    if sa_url.get_backend_name() == "sqlite":
        database = sa_url.database
        if database and database != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(sa_url, echo=echo)
        # SQLite does not enforce foreign keys unless asked to, per connection.
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        return engine
    return create_engine(sa_url, echo=echo, pool_pre_ping=True)


def engine_from_settings(settings: Settings) -> Engine:
    return create_db_engine(settings.resolved_database_url, echo=settings.database_echo)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any error."""
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
