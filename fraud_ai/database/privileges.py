"""Run-time checks that a database role has exactly its documented privileges (Stage 12).

``fraud-ai db check-privileges --expect <role>`` connects with the *current*
``DATABASE_URL`` and probes what the role can and cannot do. Staging runs it after every
deployment, so a mis-granted role is found before it matters.

**Probes cannot change anything.**

* Writes that are expected to *work* run inside a transaction that is always rolled back.
* Statements that are expected to *fail* also run inside a rolled-back transaction, or a
  savepoint.
* ``CREATE DATABASE``/``CREATE ROLE`` cannot run inside a transaction. If one of them
  unexpectedly succeeds, the object is dropped again at once and the check reports FAIL.

The expectations mirror :mod:`fraud_ai.database.roles` and ``tests/test_pg_privileges.py``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from fraud_ai.database.roles import BACKUP, MIGRATOR, READONLY, SERVICE

_DENIED = ("permission denied", "must be owner", "must be superuser", "append-only")

#: What no application role may do (all four roles; the migrator owns tables, so its list
#: is shorter: it may ALTER its own tables but never become superuser or create roles/DBs).
NEVER = [
    "CREATE ROLE {tmp}",
    "ALTER ROLE CURRENT_USER SUPERUSER",
    "SET session_replication_role = replica",
]
NEVER_AUTOCOMMIT = ["CREATE DATABASE {tmp}"]

SERVICE_DENIED = [
    "DROP TABLE audit_events",
    "ALTER TABLE audit_events DISABLE TRIGGER ALL",
    "ALTER TABLE audit_events ADD COLUMN x integer",
    "TRUNCATE audit_events",
    "UPDATE audit_events SET actor = 'x'",
    "DELETE FROM audit_events",
    "UPDATE risk_assessments SET decision = 'ALLOW'",
    "DELETE FROM risk_assessments",
    "DELETE FROM fraud_labels",
    "UPDATE policy_deployments SET note = 'x'",
    "DELETE FROM policy_approvals",
    "UPDATE model_artifact_signatures SET key_id = 'x'",
    "DELETE FROM operator_assertions",
    "CREATE TABLE fraud_ai_probe (x integer)",
    "UPDATE alembic_version SET version_num = 'x'",
]
READ_DENIED = [
    "INSERT INTO fraud_labels DEFAULT VALUES",
    "UPDATE service_api_keys SET name = 'x'",
    "DELETE FROM review_queue",
    "CREATE TABLE fraud_ai_probe (x integer)",
]
# Reads every role except the migrator's deploy-only use needs.
READS = [
    "SELECT count(*) FROM audit_events",
    "SELECT count(*) FROM risk_assessments",
    "SELECT count(*) FROM policy_deployments",
    "SELECT version_num FROM alembic_version",
]
# Writes the service legitimately makes (each rolled back).
SERVICE_WRITES = [
    "INSERT INTO operator_assertions (assertion_id, jti, operator_id, key_id, action, target, "
    "issued_at, expires_at, used_at, token_sha256) VALUES (gen_random_uuid(), 'probe-{tmp}', "
    "'probe', 'probe', 'probe', 'probe', now(), now(), now(), repeat('0', 64))",
    "UPDATE review_queue SET priority = priority WHERE false",
    "DELETE FROM request_idempotency WHERE false",
    "UPDATE risk_assessments SET latency_ms = latency_ms WHERE false",
]


@dataclass
class PrivilegeReport:
    role: str
    current_user: str
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed


def _denied(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _DENIED)


def _probe_denied(engine: Engine, statement: str, report: PrivilegeReport) -> None:
    with engine.connect() as conn:
        try:
            conn.execute(text(statement))
        except DBAPIError as exc:
            if _denied(str(exc.orig)):
                report.passed.append(f"refused: {statement}")
            else:
                report.failed.append(f"unexpected error for {statement}: {str(exc.orig)[:120]}")
        else:
            report.failed.append(f"ALLOWED (should be refused): {statement}")
        finally:
            conn.rollback()


def _probe_autocommit_denied(
    engine: Engine, statement: str, name: str, report: PrivilegeReport
) -> None:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        try:
            conn.execute(text(statement))
        except DBAPIError as exc:
            if _denied(str(exc.orig)):
                report.passed.append(f"refused: {statement.split(' fraud_ai_probe')[0]}")
            else:
                report.failed.append(f"unexpected error for {statement}: {str(exc.orig)[:120]}")
        else:
            report.failed.append(f"ALLOWED (should be refused): {statement}")
            verb = "DATABASE" if "DATABASE" in statement else "ROLE"
            conn.execute(text(f'DROP {verb} IF EXISTS "{name}"'))


def _probe_allowed(engine: Engine, statement: str, report: PrivilegeReport) -> None:
    with engine.connect() as conn:
        try:
            conn.execute(text(statement))
        except DBAPIError as exc:
            report.failed.append(f"REFUSED (should work): {statement[:80]}: {str(exc.orig)[:100]}")
        else:
            report.passed.append(f"allowed: {statement[:80]}")
        finally:
            conn.rollback()


def check(engine: Engine, expect: str) -> PrivilegeReport:
    """Probe the connected role against the expectations for ``expect``."""
    if engine.dialect.name != "postgresql":
        raise ValueError("privilege checks apply to PostgreSQL only")
    with engine.connect() as conn:
        user = str(conn.execute(text("SELECT current_user")).scalar())
        flags = conn.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one()
    report = PrivilegeReport(expect, user)
    if user != expect:
        report.failed.append(f"connected as {user}, expected {expect}")
    if any(flags):
        report.failed.append(f"{user} has superuser/createdb/createrole/bypassrls/replication")
    else:
        report.passed.append(f"{user} has no superuser, CREATEDB, CREATEROLE, BYPASSRLS")
    tmp = "fraud_ai_probe_" + secrets.token_hex(4)
    for statement in NEVER:
        _probe_denied(engine, statement.format(tmp=tmp), report)
    for statement in NEVER_AUTOCOMMIT:
        _probe_autocommit_denied(engine, statement.format(tmp=tmp), tmp, report)
    if expect in (SERVICE, READONLY, BACKUP):
        for statement in READS:
            _probe_allowed(engine, statement, report)
    if expect == SERVICE:
        for statement in SERVICE_DENIED:
            _probe_denied(engine, statement, report)
        for statement in SERVICE_WRITES:
            _probe_allowed(engine, statement.format(tmp=tmp), report)
    elif expect in (READONLY, BACKUP):
        for statement in READ_DENIED + SERVICE_DENIED:
            _probe_denied(engine, statement, report)
    elif expect == MIGRATOR:
        with engine.connect() as conn:
            owners = {
                r[0]
                for r in conn.execute(
                    text("SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = 'public'")
                )
            }
        if owners == {MIGRATOR}:
            report.passed.append("every table is owned by fraud_migrator")
        else:
            report.failed.append(f"table owners are {sorted(owners)}, expected fraud_migrator only")
    else:
        raise ValueError(f"unknown role {expect!r}")
    return report
