#!/usr/bin/env python
"""Build the synthetic Stage 8 world into a PostgreSQL *template database* once, then clone
it cheaply (``CREATE DATABASE ... TEMPLATE``) for benchmarks and multi-process checks.

    python scripts/pg_world.py build --admin-url postgresql+psycopg://u:p@localhost/postgres \
        --name fraud_ai_world_tpl --models /tmp/world-models
    python scripts/pg_world.py clone --admin-url ... --template fraud_ai_world_tpl --name run1

The role needs CREATEDB. All data is SYNTHETIC. Model artefacts live on disk (the clone
shares them read-only; the registry stores their absolute paths).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai.database.engine import create_db_engine


def db_url(admin_url: str, name: str) -> str:
    return make_url(admin_url).set(database=name).render_as_string(hide_password=False)


def drop(admin_url: str, name: str) -> None:
    engine = create_db_engine(admin_url)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    engine.dispose()


def build(admin_url: str, name: str, root: Path) -> str:
    from fraud_ai.database.migrations import upgrade
    from tests.realtime_world import _populate

    drop(admin_url, name)
    engine = create_db_engine(admin_url)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    engine.dispose()
    url = db_url(admin_url, name)
    upgrade(url)
    root.mkdir(parents=True, exist_ok=True)
    world = create_db_engine(url)
    _populate(world, root)
    world.dispose()
    return url


def clone(admin_url: str, template: str, name: str) -> str:
    drop(admin_url, name)
    engine = create_db_engine(admin_url)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}" TEMPLATE "{template}"'))
    engine.dispose()
    return db_url(admin_url, name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--admin-url", required=True)
    b.add_argument("--name", default="fraud_ai_world_tpl")
    b.add_argument("--root", type=Path, required=True, help="directory for models/, live.jsonl")
    c = sub.add_parser("clone")
    c.add_argument("--admin-url", required=True)
    c.add_argument("--template", default="fraud_ai_world_tpl")
    c.add_argument("--name", required=True)
    args = parser.parse_args()
    if args.cmd == "build":
        print(build(args.admin_url, args.name, args.root))
    else:
        print(clone(args.admin_url, args.template, args.name))


if __name__ == "__main__":
    main()
