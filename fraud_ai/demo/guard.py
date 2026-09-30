"""The demo safety guard (Stage 12).

``fraud-ai demo reset`` deletes and recreates a database. It must never touch anything else,
so every one of these must hold:

1. ``DEMO_MODE=true`` is set explicitly;
2. the profile is ``development`` or ``test`` (staging and production are refused);
3. the database is recognisably a demo database: a SQLite file named ``*_demo.db``, or a
   PostgreSQL database whose name ends in ``_demo``;
4. the database does not exist or has no tables, or its FIRST audit event is the
   ``demo.world_created`` marker that only a demo reset writes. Any other database (including
   a migrated one with no audit history) is refused, whatever its name.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine, make_url

from fraud_ai.core.exceptions import FraudAIError

MARKER = "demo.world_created"


class DemoGuardError(FraudAIError):
    pass


def demo_database_name(url: str) -> str:
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        return Path(parsed.database or "").name
    return parsed.database or ""


def check_target(settings: object, engine: Engine) -> None:
    """Raise unless the configured database may be (re)created as a demo world."""
    from fraud_ai.config.settings import Environment

    if not getattr(settings, "demo_mode", False):
        raise DemoGuardError("demo commands need DEMO_MODE=true")
    environment = getattr(settings, "environment", None)
    if environment not in (Environment.DEVELOPMENT, Environment.TEST):
        raise DemoGuardError(f"demo commands are refused in the {environment} profile")
    url = str(getattr(settings, "resolved_database_url", ""))
    name = demo_database_name(url)
    backend = make_url(url).get_backend_name()
    if backend == "sqlite" and not name.endswith("_demo.db"):
        raise DemoGuardError(
            f"refusing: SQLite demo databases must be named *_demo.db, not {name!r}"
        )
    if backend == "postgresql" and not name.endswith("_demo"):
        raise DemoGuardError(f"refusing: PostgreSQL demo databases must end in _demo, not {name!r}")
    if backend not in ("sqlite", "postgresql"):
        raise DemoGuardError(f"unsupported demo backend {backend!r}")
    if backend == "sqlite" and not Path(make_url(url).database or "").exists():
        return  # nothing there yet
    tables = set(inspect(engine).get_table_names())
    if not tables:
        return
    if "audit_events" not in tables:
        raise DemoGuardError("refusing: the database has tables but no demo marker")
    with engine.connect() as conn:
        first = conn.execute(
            text("SELECT action FROM audit_events ORDER BY sequence LIMIT 1")
        ).scalar()
    if first != MARKER:
        raise DemoGuardError(
            "refusing: this database was not created by `fraud-ai demo reset` (its first audit "
            f"event is {first!r}, not {MARKER!r})"
        )
