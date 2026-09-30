"""Least-privilege PostgreSQL roles (Stage 11).

* ``fraud_migrator``: owns the schema and every table. Runs migrations and grants; its
  credentials are used at deploy time only. No superuser, no CREATEDB, no CREATEROLE.
* ``fraud_service``: the API service and the operational CLI. Owns nothing. SELECT and
  INSERT everywhere; UPDATE and DELETE on operational tables only. Cannot DROP, ALTER or
  TRUNCATE anything, disable triggers, change history rows, or create objects or roles.
* ``fraud_readonly``: analysts and reporting. SELECT only.
* ``fraud_backup``: ``pg_dump``. SELECT on every table and sequence; no writes.

**History is append-only for the service.** :data:`APPEND_ONLY` lists the tables where
``fraud_service`` has no UPDATE or DELETE privilege (assessments, labels, audit events, model
and policy history, signatures, approvals). The audit/signature/approval triggers are a
second layer on top of that.

**Ownership.** Only the owner can ``ALTER TABLE … DISABLE TRIGGER`` or drop a table. The
owner is ``fraud_migrator``, whose credentials are used only by the migration job. The
remaining risk: a leaked migrator credential or a database superuser can still do all of
this. The external audit anchor (:mod:`fraud_ai.trust.anchors`) detects rewrites after the
fact.

The SQL uses ``psycopg.sql`` composition, so identifiers and passwords are quoted by the
driver and never interpolated as text.

Usage (see DEPLOYMENT.md):

1. As an administrator: :func:`create_roles`.
2. As ``fraud_migrator``: ``fraud-ai db migrate``.
3. As ``fraud_migrator``, after **every** migration: :func:`apply_grants`
   (``fraud-ai db grant-roles``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import psycopg
from psycopg import sql
from sqlalchemy import Engine, inspect

MIGRATOR, SERVICE, READONLY, BACKUP = (
    "fraud_migrator",
    "fraud_service",
    "fraud_readonly",
    "fraud_backup",
)
ROLES = (MIGRATOR, SERVICE, READONLY, BACKUP)

# No UPDATE/DELETE for the service: immutable history (Stages 8-11 invariants).
APPEND_ONLY = frozenset(
    {
        "audit_events",
        "fraud_labels",
        "model_artifact_signatures",
        "model_calibrations",
        "model_predictions",
        "operator_assertions",
        "policy_approvals",
        "policy_deployments",
        "policy_lifecycle_events",
        "risk_assessments",
        "risk_policies",
    }
)

# Column-level exceptions: telemetry written after the immutable row (never the decision).
COLUMN_UPDATES: dict[str, tuple[str, ...]] = {"risk_assessments": ("latency_ms",)}

# Read-only for the service (Stage 12, found by `db check-privileges`): the migration
# revision is written by the migrator only. A service that could UPDATE it could make
# readiness and release verification report a schema version that is not there.
SERVICE_READ_ONLY = frozenset({"alembic_version"})


@dataclass(frozen=True)
class RolePasswords:
    migrator: str
    service: str
    readonly: str
    backup: str

    def items(self) -> Iterable[tuple[str, str]]:
        return (
            (MIGRATOR, self.migrator),
            (SERVICE, self.service),
            (READONLY, self.readonly),
            (BACKUP, self.backup),
        )


def _run(engine: Engine, statements: list[sql.Composed]) -> None:
    raw = engine.raw_connection()
    try:
        conn = raw.driver_connection
        if not isinstance(conn, psycopg.Connection):
            raise TypeError("role management needs a psycopg (PostgreSQL) engine")
        conn.autocommit = True
        with conn.cursor() as cur:
            for statement in statements:
                cur.execute(statement)
    finally:
        raw.close()


def role_statements(
    database: str, schema: str, passwords: RolePasswords, *, existing: set[str]
) -> list[sql.Composed]:
    out: list[sql.Composed] = []
    for role, password in passwords.items():
        verb = "ALTER" if role in existing else "CREATE"
        out.append(
            sql.SQL(
                "{} ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS"
            ).format(sql.SQL(verb), sql.Identifier(role), sql.Literal(password))
        )
    db, sch = sql.Identifier(database), sql.Identifier(schema)
    out.append(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(db))
    for role in ROLES:
        out.append(
            sql.SQL("GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}").format(
                db, sql.Identifier(role)
            )
        )
    out.append(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sch))
    out.append(sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(sch, sql.Identifier(MIGRATOR)))
    out.append(sql.SQL("REVOKE CREATE ON SCHEMA {} FROM PUBLIC").format(sch))
    for role in (SERVICE, READONLY, BACKUP):
        out.append(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sch, sql.Identifier(role)))
    for role in ROLES:
        out.append(
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET search_path = {}").format(
                sql.Identifier(role), db, sch
            )
        )
    return out


def create_roles(admin: Engine, database: str, schema: str, passwords: RolePasswords) -> None:
    """As an administrator (CREATEROLE, or superuser for ``ALTER SCHEMA public``)."""
    with admin.connect() as conn:
        existing = {
            r[0]
            for r in conn.exec_driver_sql(
                "SELECT rolname FROM pg_roles WHERE rolname = ANY(%(names)s)",
                {"names": list(ROLES)},
            )
        }
    _run(admin, role_statements(database, schema, passwords, existing=existing))


def grant_statements(schema: str, tables: Iterable[str]) -> list[sql.Composed]:
    sch = sql.Identifier(schema)
    service, readonly, backup = (sql.Identifier(r) for r in (SERVICE, READONLY, BACKUP))
    out: list[sql.Composed] = [
        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM PUBLIC").format(sch),
        sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}, {}").format(sch, readonly, backup),
        sql.SQL("GRANT SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}, {}").format(
            sch, readonly, backup
        ),
        sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}").format(sch, service),
    ]
    for table in sorted(tables):
        ident = sql.Identifier(schema, table)
        out.append(sql.SQL("REVOKE ALL ON {} FROM {}").format(ident, service))
        if table in SERVICE_READ_ONLY:
            privileges = "SELECT"
        elif table in APPEND_ONLY:
            privileges = "SELECT, INSERT"
        else:
            privileges = "SELECT, INSERT, UPDATE, DELETE"
        out.append(sql.SQL("GRANT " + privileges + " ON {} TO {}").format(ident, service))
        columns = COLUMN_UPDATES.get(table)
        if columns:
            out.append(
                sql.SQL("GRANT UPDATE ({}) ON {} TO {}").format(
                    sql.SQL(", ").join(sql.Identifier(c) for c in columns), ident, service
                )
            )
    return out


def apply_grants(migrator: Engine, schema: str = "public") -> list[str]:
    """As the owner, after every migration: (re)grant exactly the documented privileges."""
    tables = sorted(inspect(migrator).get_table_names(schema=schema))
    _run(migrator, grant_statements(schema, tables))
    return tables
