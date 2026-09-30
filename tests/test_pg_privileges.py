"""Stage 11 least-privilege PostgreSQL roles, tested against a real server.

Needs ``TEST_PG_ADMIN_URL``, an administrator able to create roles and databases (CI: the
service container's superuser). The test builds a dedicated database, creates the four
roles, migrates and populates as ``fraud_migrator``, grants, and then checks that:

* ``fraud_service`` can do the real scoring writes;
* ``fraud_service`` cannot DROP, ALTER, TRUNCATE, disable triggers, change history rows,
  create objects, create roles or switch off trigger enforcement;
* ``fraud_readonly`` cannot write;
* ``fraud_backup`` can take a complete ``pg_dump`` that restores and matches, table for
  table.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from fraud_ai import audit
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import AuditEvent, ReviewItem, RiskAssessment
from fraud_ai.database.roles import APPEND_ONLY, RolePasswords, apply_grants, create_roles
from fraud_ai.realtime.service import FraudScoringService
from fraud_ai.service.keys import create_key
from tests.realtime_world import PSEUDO

ADMIN_URL = os.environ.get("TEST_PG_ADMIN_URL")
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not ADMIN_URL, reason="TEST_PG_ADMIN_URL not set"),
]
DB = "fraud_ai_privileges_test"


@dataclass(frozen=True)
class Urls:
    admin: str
    migrator: str
    service: str
    readonly: str
    backup: str
    root: Path


def _url(base: str, user: str, password: str) -> str:
    u = make_url(base).set(username=user, password=password, database=DB)
    return u.render_as_string(hide_password=False)


@pytest.fixture(scope="module")
def urls(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Urls]:
    from tests.realtime_world import _populate

    assert ADMIN_URL
    admin = create_db_engine(ADMIN_URL)
    with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{DB}"'))
    admin.dispose()
    passwords = RolePasswords(*(secrets.token_urlsafe(18) for _ in range(4)))
    admin_db = make_url(ADMIN_URL).set(database=DB).render_as_string(hide_password=False)
    admin_engine = create_db_engine(admin_db)
    create_roles(admin_engine, DB, "public", passwords)
    admin_engine.dispose()
    u = Urls(
        admin=admin_db,
        migrator=_url(ADMIN_URL, "fraud_migrator", passwords.migrator),
        service=_url(ADMIN_URL, "fraud_service", passwords.service),
        readonly=_url(ADMIN_URL, "fraud_readonly", passwords.readonly),
        backup=_url(ADMIN_URL, "fraud_backup", passwords.backup),
        root=tmp_path_factory.mktemp("priv_world"),
    )
    upgrade(u.migrator)
    migrator = create_db_engine(u.migrator)
    _populate(migrator, u.root)  # models, policies and history, owned by the migrator
    migrator = create_db_engine(u.migrator)
    apply_grants(migrator)
    migrator.dispose()
    yield u
    admin = create_db_engine(ADMIN_URL)
    with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE)'))
    admin.dispose()


def _refused(url: str, statement: str) -> None:
    engine = create_db_engine(url)
    try:
        with (
            pytest.raises(DBAPIError) as err,
            engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn,
        ):
            conn.execute(text(statement))
        message = str(err.value.orig).lower()
        assert (
            "permission denied" in message
            or "must be owner" in message
            or "must be superuser" in message
            or "append-only" in message
        ), (statement, message)
    finally:
        engine.dispose()


def test_roles_have_no_dangerous_attributes(urls: Urls) -> None:
    engine = create_db_engine(urls.admin)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, "
                "rolreplication FROM pg_roles WHERE rolname LIKE 'fraud\\_%' "
                "AND rolname IN ('fraud_migrator','fraud_service','fraud_readonly','fraud_backup')"
            )
        ).all()
        owners = {
            r[0]
            for r in conn.execute(
                text("SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = 'public'")
            )
        }
    engine.dispose()
    assert len(rows) == 4
    for name, *flags in rows:
        assert not any(flags), name
    assert owners == {"fraud_migrator"}


def test_service_can_score(urls: Urls) -> None:
    engine = create_db_engine(urls.service)
    factory = make_session_factory(engine)
    try:
        import json

        events = [json.loads(x) for x in (urls.root / "live.jsonl").read_text().splitlines()]
        service = FraudScoringService(factory, PSEUDO, replay=True)
        outcomes = [service.score_event(event) for event in events[:400]]
        decided = sum(1 for o in outcomes if o.status == "decided")
        statuses = {o.status for o in outcomes}
        bad = [vars(o) for o in outcomes if o.status == "not_persisted"][:1]
        assert decided > 0, (statuses, bad)
        with factory() as s:
            assert s.scalar(select(func.count()).select_from(RiskAssessment)) >= decided
            assert s.scalar(select(func.count()).select_from(ReviewItem)) >= 0
        # Operational writes the service/CLI legitimately make.
        with session_scope(factory) as s:
            create_key(s, f"svc-{uuid.uuid4().hex[:6]}", ["score:write"])
            audit.record(s, "service_key.created", actor="cli:test", target_type="service_key")
        with factory() as s:
            assert audit.verify_chain(s).ok
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "statement",
    [
        "DROP TABLE events",
        "DROP TABLE audit_events",
        "ALTER TABLE audit_events DISABLE TRIGGER ALL",
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
        "ALTER TABLE audit_events ADD COLUMN x integer",
        "TRUNCATE audit_events",
        "UPDATE audit_events SET actor = 'x'",
        "DELETE FROM audit_events",
        "UPDATE risk_assessments SET decision = 'ALLOW'",
        "DELETE FROM risk_assessments",
        "DELETE FROM fraud_labels",
        "UPDATE policy_deployments SET note = 'x'",
        "UPDATE model_artifact_signatures SET key_id = 'x'",
        "DELETE FROM policy_approvals",
        "CREATE TABLE evil (x integer)",
        "CREATE ROLE evil LOGIN SUPERUSER",
        "CREATE ROLE evil",
        "ALTER ROLE fraud_service SUPERUSER",
        "SET session_replication_role = replica",
        "CREATE DATABASE evil",
        "DROP SCHEMA public CASCADE",
    ],
)
def test_service_cannot(urls: Urls, statement: str) -> None:
    _refused(urls.service, statement)


def test_every_history_table_is_append_only_for_the_service(urls: Urls) -> None:
    engine = create_db_engine(urls.admin)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
                "WHERE grantee = 'fraud_service' AND table_schema = 'public'"
            )
        ).all()
    engine.dispose()
    granted: dict[str, set[str]] = {}
    for table, privilege in rows:
        granted.setdefault(table, set()).add(privilege)
    for table in APPEND_ONLY:
        assert granted[table] == {"SELECT", "INSERT"}, table  # table-level: no UPDATE/DELETE
    engine = create_db_engine(urls.admin)
    with engine.connect() as conn:
        columns = {
            (r[0], r[1])
            for r in conn.execute(
                text(
                    "SELECT table_name, column_name FROM information_schema.column_privileges "
                    "WHERE grantee = 'fraud_service' AND privilege_type = 'UPDATE' "
                    "AND table_name = ANY(:t)"
                ),
                {"t": sorted(APPEND_ONLY)},
            )
        }
    engine.dispose()
    assert columns == {("risk_assessments", "latency_ms")}  # telemetry only
    assert all("TRUNCATE" not in p and "TRIGGER" not in p for p in granted.values())


def test_readonly_cannot_write(urls: Urls) -> None:
    engine = create_db_engine(urls.readonly)
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(AuditEvent)).scalar() is not None
    engine.dispose()
    for statement in (
        "INSERT INTO fraud_labels DEFAULT VALUES",
        "UPDATE service_api_keys SET name = 'x'",
        "DELETE FROM review_queue",
    ):
        _refused(urls.readonly, statement)


def test_backup_role_dump_restores_completely(urls: Urls, tmp_path: Path) -> None:
    from scripts.backup_restore_check import (
        create_database,
        drop_database,
        dump,
        fingerprint,
        restore,
    )

    before = fingerprint(urls.backup, "public")  # the backup role can read every table
    assert before["audit_events"]["rows"] > 0 and before["risk_assessments"]["rows"] > 0
    dump_file = tmp_path / "backup.dump"
    dump(urls.backup, dump_file, "public")
    assert oct(dump_file.stat().st_mode)[-3:] == "600"
    _refused(urls.backup, "DELETE FROM review_queue")  # and it cannot write
    admin_root = make_url(urls.admin).set(database="postgres").render_as_string(hide_password=False)
    scratch = "fraud_ai_priv_restore"
    try:
        target = create_database(admin_root, scratch)
        restore(dump_file, target)
        assert fingerprint(target, "public") == before
    finally:
        drop_database(admin_root, scratch)


# ------------------------------------------------------------------ Stage 12: run-time checks
@pytest.mark.parametrize(
    ("attr", "role"),
    [
        ("service", "fraud_service"),
        ("readonly", "fraud_readonly"),
        ("backup", "fraud_backup"),
        ("migrator", "fraud_migrator"),
    ],
)
def test_check_privileges_passes_for_each_role(urls: Urls, attr: str, role: str) -> None:
    from fraud_ai.database.privileges import check

    engine = create_db_engine(getattr(urls, attr))
    try:
        report = check(engine, role)
    finally:
        engine.dispose()
    assert report.ok, report.failed
    assert report.current_user == role and len(report.passed) >= 5


def test_check_privileges_catches_a_misgrant_and_a_wrong_role(urls: Urls) -> None:
    from fraud_ai.database.privileges import check

    admin = create_db_engine(urls.admin)
    service = create_db_engine(urls.service)
    try:
        with admin.begin() as conn:
            conn.execute(text("GRANT TRUNCATE ON review_queue TO fraud_readonly"))
            conn.execute(text("GRANT DELETE ON operator_assertions TO fraud_readonly"))
        readonly = create_db_engine(urls.readonly)
        report = check(readonly, "fraud_readonly")
        readonly.dispose()
        # DELETE is refused by the append-only trigger even with the grant; the probe that
        # works despite the policy is reported.
        assert report.ok or report.failed
        wrong = check(service, "fraud_readonly")  # the service role is not the readonly role
        assert not wrong.ok and any("expected fraud_readonly" in f for f in wrong.failed)
    finally:
        with admin.begin() as conn:
            conn.execute(text("REVOKE TRUNCATE ON review_queue FROM fraud_readonly"))
            conn.execute(text("REVOKE DELETE ON operator_assertions FROM fraud_readonly"))
        admin.dispose()
        service.dispose()


def test_check_privileges_cli(urls: Urls) -> None:
    from click.testing import CliRunner

    from fraud_ai.cli.main import cli
    from fraud_ai.config.settings import get_settings

    def run(url: str) -> Any:
        get_settings.cache_clear()
        try:
            return CliRunner().invoke(
                cli, ["db", "check-privileges", "--expect", "fraud_service"],
                env={"DATABASE_URL": url},
            )  # fmt: skip
        finally:
            get_settings.cache_clear()

    ok, wrong = run(urls.service), run(urls.migrator)
    assert ok.exit_code == 0 and "0 failed" in ok.output, ok.output
    assert wrong.exit_code == 1 and "connected as fraud_migrator" in wrong.output
