"""Engine and session management."""

from __future__ import annotations

import contextlib
import threading
import weakref
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
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
        # Concurrent writers (the service's threads) wait for SQLite's single write lock
        # instead of failing immediately.
        engine = create_engine(sa_url, echo=echo, connect_args={"timeout": 30})
        # SQLite does not enforce foreign keys unless asked to, per connection.
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        return engine
    return create_engine(sa_url, echo=echo, pool_pre_ping=True)


def engine_from_settings(settings: Settings) -> Engine:
    return create_db_engine(settings.resolved_database_url, echo=settings.database_echo)


_WRITE_LOCKS: weakref.WeakKeyDictionary[Engine, threading.RLock] = weakref.WeakKeyDictionary()
_WRITE_LOCKS_GUARD = threading.Lock()


def write_lock(engine: Engine | None) -> AbstractContextManager[Any]:
    """The process-wide write lock for an engine.

    SQLite has a single writer. Two *deferred* write transactions that both read first
    can deadlock: SQLite then fails one of them at once with "database is locked", and
    the busy timeout does not help. So every writer in the process that shares an engine
    serialises on one lock: the Stage 8 scorer and the Stage 9 service writes. PostgreSQL
    needs no lock; there the unique constraints decide races.
    """
    if engine is None or engine.dialect.name != "sqlite":
        return contextlib.nullcontext()
    with _WRITE_LOCKS_GUARD:
        lock = _WRITE_LOCKS.get(engine)
        if lock is None:
            lock = _WRITE_LOCKS[engine] = threading.RLock()
        return lock


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


@contextmanager
def write_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """:func:`session_scope` under the engine's write lock (see :func:`write_lock`)."""
    with write_lock(factory.kw.get("bind")), session_scope(factory) as session:
        yield session
