#!/usr/bin/env python
"""PostgreSQL logical backup / restore verification (Stage 10).

The workflow DISASTER_RECOVERY.md relies on:

1. fingerprint every table (row count + an order-independent content digest);
2. ``pg_dump --format=custom`` (compressed, restorable table by table);
3. restore into a scratch database with ``pg_restore --exit-on-error``;
4. fingerprint again and compare **every table**; then check the application-level
   invariants on the restored copy: the active policy deployment still hash-verifies, the
   audit chain verifies, the model registry resolves.

A backup is only considered good once this has passed on a restored copy.

    python scripts/backup_restore_check.py --source-url postgresql+psycopg://u:p@h/db \
        --admin-url postgresql+psycopg://u:p@h/postgres --dump /secure/backup.dump
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai.database.engine import create_db_engine, make_session_factory


class BackupError(RuntimeError):
    pass


def _libpq(url: str) -> tuple[list[str], dict[str, str]]:
    """Connection arguments for pg_dump/pg_restore; the password goes via PGPASSWORD."""
    u = make_url(url)
    args = ["--host", u.host or "localhost", "--port", str(u.port or 5432)]
    if u.username:
        args += ["--username", u.username]
    env = {**os.environ}
    if u.password:
        env["PGPASSWORD"] = str(u.password)
    return args, env


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise BackupError(f"{name} is not installed")
    return path


def fingerprint(url: str, schema: str = "public") -> dict[str, dict[str, Any]]:
    engine = create_db_engine(url)
    out: dict[str, dict[str, Any]] = {}
    try:
        tables = sorted(inspect(engine).get_table_names(schema=schema))
        with engine.connect() as conn:
            for table in tables:
                row = conn.execute(
                    text(
                        f"SELECT count(*), md5(coalesce(string_agg(md5(t::text), '' "  # noqa: S608
                        f'ORDER BY md5(t::text)), \'\')) FROM "{schema}"."{table}" t'
                    )
                ).one()
                out[table] = {"rows": int(row[0]), "digest": row[1]}
    finally:
        engine.dispose()
    return out


def dump(url: str, target: Path, schema: str = "public") -> None:
    args, env = _libpq(url)
    db = make_url(url).database or ""
    target.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(  # noqa: S603 - fixed binary, argument list (no shell)
        [
            _tool("pg_dump"),
            *args,
            "--format=custom",
            "--no-owner",
            "--schema",
            schema,
            "--file",
            str(target),
            db,
        ],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise BackupError(f"pg_dump failed: {proc.stderr.strip()[:500]}")
    target.chmod(0o600)


def restore(dump_file: Path, url: str) -> None:
    args, env = _libpq(url)
    db = make_url(url).database or ""
    proc = subprocess.run(  # noqa: S603 - fixed binary, argument list (no shell)
        [
            _tool("pg_restore"),
            *args,
            "--no-owner",
            "--exit-on-error",
            "--dbname",
            db,
            str(dump_file),
        ],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise BackupError(f"pg_restore failed: {proc.stderr.strip()[:500]}")


def create_database(admin_url: str, name: str) -> str:
    drop_database(admin_url, name)
    engine = create_db_engine(admin_url)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    engine.dispose()
    url = make_url(admin_url).set(database=name).render_as_string(hide_password=False)
    # A new database has an empty public schema; the dump recreates it (with its grants).
    fresh = create_db_engine(url)
    with fresh.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
    fresh.dispose()
    return url


def drop_database(admin_url: str, name: str, *, attempts: int = 10) -> None:
    """Drop a scratch database.

    A plain ``DROP DATABASE`` first: PostgreSQL itself cancels autovacuum workers on the
    target (a freshly restored database often has one). ``WITH (FORCE)`` is only the
    fallback for our own lingering sessions: it must terminate *every* backend and fails
    for a non-superuser when one of them (e.g. an autovacuum worker) is not ours, so the
    two are retried briefly.
    """
    import time

    from sqlalchemy.exc import DBAPIError

    engine = create_db_engine(admin_url)
    try:
        for attempt in range(attempts):
            for statement in (
                f'DROP DATABASE IF EXISTS "{name}"',
                f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)',
            ):
                try:
                    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                        conn.execute(text(statement))
                    return
                except DBAPIError:
                    if attempt == attempts - 1 and "FORCE" in statement:
                        raise
            time.sleep(0.5)
    finally:
        engine.dispose()


def invariants(url: str) -> dict[str, Any]:
    """Application-level checks on a restored copy."""
    from fraud_ai import audit
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.risk.registry import active_deployment

    engine = create_db_engine(url)
    try:
        with make_session_factory(engine)() as s:
            deployment = active_deployment(s)  # re-verifies policy and deployment hashes
            chain = audit.verify_chain(s)
            refs = [slot.ref for slot in deployment.policy.slots().values()] if deployment else []
            for ref in refs:
                resolve_model(s, ref)
            return {
                "active_policy": deployment.policy.policy_version if deployment else None,
                "audit_chain_ok": chain.ok,
                "audit_events": chain.events,
                "models_resolved": refs,
            }
    finally:
        engine.dispose()


def verify_roundtrip(
    source_url: str,
    admin_url: str,
    dump_file: Path,
    *,
    scratch: str = "fraud_ai_restore_check",
    schema: str = "public",
) -> dict[str, Any]:
    before = fingerprint(source_url, schema)
    dump(source_url, dump_file, schema)
    target = create_database(admin_url, scratch)
    try:
        restore(dump_file, target)
        if schema != "public":
            target = f"{target}?options=-csearch_path%3D{schema}"
        after = fingerprint(target, schema)
        mismatched = sorted(t for t in before if before[t] != after.get(t))
        missing = sorted(set(before) - set(after))
        report = {
            "tables": len(before),
            "rows": sum(t["rows"] for t in before.values()),
            "mismatched_tables": mismatched,
            "missing_tables": missing,
            "invariants": invariants(target),
            "dump_bytes": dump_file.stat().st_size,
        }
    finally:
        drop_database(admin_url, scratch)
    report["ok"] = (
        not report["mismatched_tables"]
        and not report["missing_tables"]
        and report["invariants"]["audit_chain_ok"]
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--schema", default="public")
    args = parser.parse_args()
    report = verify_roundtrip(args.source_url, args.admin_url, args.dump, schema=args.schema)
    print(json.dumps(report, indent=2, sort_keys=True))
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
