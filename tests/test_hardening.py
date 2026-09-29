"""Stage 10 hardening on every backend (SQLite, and PostgreSQL when TEST_POSTGRES_URL is
set): key expiry and rotation, the audit chain and its immutability, retention (and what it
never touches), file-based secrets, structured and redacted logging."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.config.secrets import FileSecretsProvider, SecretError, resolve_file_secrets
from fraud_ai.config.settings import Settings, reset_settings_cache
from fraud_ai.core.enums import AuthenticationMethod, AuthenticationResult, ChallengePurpose
from fraud_ai.database.engine import make_session_factory, session_scope
from fraud_ai.database.models import (
    AuditEvent,
    AuthenticationAttempt,
    AuthenticationChallenge,
    NetworkIdentity,
    RequestIdempotency,
    RequestReplayToken,
    RiskAssessment,
    ServiceApiKey,
)
from fraud_ai.retention import (
    CATEGORIES,
    NULLIFY_ONLY,
    PROTECTED_TABLES,
    RetentionError,
    plan,
    run,
)
from fraud_ai.service.keys import ServiceKeyError, create_key, revoke_key, rotate_key, verify_key
from fraud_ai.utils.logging import JsonFormatter, RedactingFilter, get_logger
from tests.service_helpers import Clock, make_harness
from tests.test_service_backends import _seed_step_up

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def factory(any_engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(any_engine)


# ------------------------------------------------------------------ key expiry / rotation
def test_expired_keys_fail_like_unknown_keys(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as s:
        short = create_key(
            s, "short", ["score:write"], expires_at=NOW + timedelta(hours=1), now=NOW
        )
        with pytest.raises(ServiceKeyError, match="future"):
            create_key(s, "past", ["score:write"], expires_at=NOW - timedelta(seconds=1), now=NOW)
    with factory() as s:
        assert verify_key(s, short.credential, now=NOW) is not None
        assert verify_key(s, short.credential, now=NOW + timedelta(hours=1)) is None
        row = s.scalar(select(ServiceApiKey).where(ServiceApiKey.key_id == short.key_id))
        assert row is not None
        assert row.status_at(NOW) == "active"
        assert row.status_at(NOW + timedelta(hours=2)) == "expired"


def test_rotation_has_a_grace_period(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as s:
        old = create_key(s, "checkout", ["score:write", "assessment:read"], now=NOW)
    with session_scope(factory) as s:
        new, _ = rotate_key(s, old.key_id, grace=timedelta(hours=24), now=NOW)
        assert new.key_id != old.key_id and new.secret != old.secret
        assert new.scopes == old.scopes
    with factory() as s:
        successor = s.scalar(select(ServiceApiKey).where(ServiceApiKey.key_id == new.key_id))
        assert successor is not None and successor.rotated_from_key_id == old.key_id
        within = NOW + timedelta(hours=23)
        after = NOW + timedelta(hours=24, seconds=1)
        assert verify_key(s, old.credential, now=within) is not None  # grace
        assert verify_key(s, old.credential, now=after) is None  # expired automatically
        assert verify_key(s, new.credential, now=after) is not None
    with session_scope(factory) as s:
        with pytest.raises(ServiceKeyError, match="only active keys rotate"):
            rotate_key(s, old.key_id, grace=timedelta(0), now=NOW + timedelta(days=2))
        with pytest.raises(ServiceKeyError, match="unknown"):
            rotate_key(s, "fak_0000000000000000", grace=timedelta(0), now=NOW)
        revoke_key(s, new.key_id)
        with pytest.raises(ServiceKeyError):
            rotate_key(s, new.key_id, grace=timedelta(hours=1), now=NOW)


def test_key_use_is_recorded_and_expired_keys_get_the_same_401(sqlite_url: str) -> None:
    clock = Clock(NOW)
    h = make_harness(sqlite_url, clock=clock)
    try:
        with session_scope(h.container.factory) as s:
            key = create_key(
                s, "t", ["review:read"], expires_at=NOW + timedelta(minutes=5), now=NOW
            )
        assert h.get("/v1/reviews", key.credential).status_code == 200
        with h.container.factory() as s:
            row = s.scalar(select(ServiceApiKey).where(ServiceApiKey.key_id == key.key_id))
            assert row is not None and row.last_used_at is not None
        clock.now = NOW + timedelta(minutes=10)
        expired = h.get("/v1/reviews", key.credential)
        unknown = h.get("/v1/reviews", f"fak_{'0' * 16}.{key.secret}")
        assert expired.status_code == unknown.status_code == 401
        assert expired.json()["error"]["message"] == unknown.json()["error"]["message"]
        assert "expired" not in expired.text
    finally:
        h.container.close()
        h.container.engine.dispose()


# ------------------------------------------------------------------ audit log
def test_audit_chain_detects_tampering_and_rows_are_immutable(
    factory: sessionmaker[Session], any_engine: Engine
) -> None:
    with session_scope(factory) as s:
        for i in range(3):
            audit.record(
                s,
                "service_key.created",
                actor="cli:test",
                target_type="service_key",
                target_id=f"fak_{i:016d}",
                details={"name": f"k{i}"},
                now=NOW + timedelta(seconds=i),
            )
    with factory() as s:
        report = audit.verify_chain(s)
        assert report.ok and report.events == 3
        assert [e.sequence for e in audit.list_events(s)] == [3, 2, 1]
    for statement in ("UPDATE audit_events SET actor = 'x'", "DELETE FROM audit_events"):
        with pytest.raises(DBAPIError), any_engine.begin() as conn:
            conn.execute(text(statement))
    with factory() as s:
        assert s.scalar(select(func.count()).select_from(AuditEvent)) == 3


def test_audit_chain_verification_reports_edits(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as s:
        first = audit.record(s, "retention.run", actor="cli:t", target_type="retention", now=NOW)
        audit.record(s, "retention.run", actor="cli:t", target_type="retention", now=NOW)
        # Simulate an edit that bypassed the triggers (e.g. by a superuser): detached copy.
        first.details = {"tampered": True}
        assert audit._digest(first) != first.event_sha256
        s.expunge_all()


def test_audit_details_never_hold_secrets(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as s:
        with pytest.raises(audit.AuditError, match="secrets"):
            audit.record(s, "x", actor="a", target_type="t", details={"api_secret": "v"})
        row = audit.record(
            s,
            "x",
            actor="a",
            target_type="t",
            details={"note": "credential fak_0123456789abcdef.SECRETSECRETSECRET from 10.1.2.3"},
        )
        assert "SECRETSECRET" not in json.dumps(row.details)
        assert "10.1.2.3" not in json.dumps(row.details)


def test_audit_chain_verify_finds_a_gap(any_engine: Engine, backend_url: str) -> None:
    factory = make_session_factory(any_engine)
    with session_scope(factory) as s:
        for _ in range(3):
            audit.record(s, "retention.run", actor="cli:t", target_type="retention", now=NOW)
    if backend_url.startswith("sqlite"):
        with any_engine.begin() as conn:
            conn.execute(text("DROP TRIGGER audit_events_no_delete"))
            conn.execute(text("DELETE FROM audit_events WHERE sequence = 2"))
    else:
        with any_engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable"))
            conn.execute(text("DELETE FROM audit_events WHERE sequence = 2"))
    with factory() as s:
        report = audit.verify_chain(s)
    assert not report.ok and report.first_bad_sequence == 3 and "gap" in (report.reason or "")


# ------------------------------------------------------------------ retention
def _retention_world(factory: sessionmaker[Session]) -> dict[str, Any]:
    [(aid, user_id, _)] = _seed_step_up(factory)
    old = NOW - timedelta(days=60)
    with session_scope(factory) as s:
        s.add(
            RequestReplayToken(
                signer="k",
                signature_sha256="a" * 64,
                signed_at=old,
                expires_at=old + timedelta(minutes=5),
            )
        )
        s.add(
            RequestReplayToken(
                signer="k",
                signature_sha256="b" * 64,
                signed_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        )
        s.add(
            RequestIdempotency(
                api_key_id="fak_1",
                route="r",
                idempotency_key="old-1",
                request_sha256="c" * 64,
                state="completed",
                created_at=old,
            )
        )
        s.add(
            RequestIdempotency(
                api_key_id="fak_1",
                route="r",
                idempotency_key="new-1",
                request_sha256="c" * 64,
                state="completed",
                created_at=NOW,
            )
        )
        s.add(
            RequestIdempotency(
                api_key_id="fak_1",
                route="r",
                idempotency_key="stuck-1",
                request_sha256="c" * 64,
                state="in_progress",
                created_at=NOW - timedelta(hours=2),
            )
        )
        free = AuthenticationChallenge(
            purpose=ChallengePurpose.AUTHENTICATION,
            challenge_sha256="d" * 64,
            user_id=uuid.UUID(user_id),
            created_at=old,
            expires_at=old + timedelta(minutes=2),
        )
        used = AuthenticationChallenge(
            purpose=ChallengePurpose.AUTHENTICATION,
            challenge_sha256="e" * 64,
            user_id=uuid.UUID(user_id),
            created_at=old,
            expires_at=old + timedelta(minutes=2),
        )
        s.add_all([free, used])
        s.flush()
        s.add(
            AuthenticationAttempt(
                assessment_id=uuid.UUID(aid),
                method=AuthenticationMethod.WEBAUTHN,
                attempt_number=1,
                result=AuthenticationResult.FAILED,
                challenge_id=used.challenge_id,
                created_at=old,
            )
        )
        identity = s.scalar(select(NetworkIdentity))
        assert identity is not None
        identity.ip_address = "10.1.2.3"
        identity.last_seen_at = old
    return {"assessment": aid}


def _counts(s: Session) -> dict[str, int]:
    return {
        t: int(s.scalar(text(f"SELECT count(*) FROM {t}")) or 0)  # noqa: S608 - fixed names
        for t in sorted(PROTECTED_TABLES)
    }


def test_retention_plan_and_run(factory: sessionmaker[Session]) -> None:
    _retention_world(factory)
    settings = Settings(retention_failed_attempt_days=30)
    with factory() as s:
        before = _counts(s)
        planned = {p.name: p for p in plan(s, settings, now=NOW)}
    assert planned["replay_tokens"].rows == 1
    assert planned["idempotency"].rows == 2  # the old completed one and the stuck one
    assert planned["webauthn_challenges"].rows == 1  # the referenced one is kept
    assert planned["raw_ip"].rows == 1 and planned["raw_ip"].action == "nullify"
    assert planned["failed_attempts"].rows == 1
    assert not planned["payment_requests"].enabled and not planned["log_files"].enabled
    with session_scope(factory) as s:
        dry = run(s, settings, execute=False, actor="cli:test", now=NOW)
        assert dry["dry_run"] and dry["applied"] == {}
    with session_scope(factory) as s, pytest.raises(RetentionError, match="RETENTION_ALLOW_DELETE"):
        run(s, settings, execute=True, actor="cli:test", now=NOW)
    with session_scope(factory) as s:
        done = run(s, settings, execute=True, confirmed=True, actor="cli:test", now=NOW)
    assert done["applied"] == {
        "replay_tokens": 1,
        "idempotency": 2,
        "webauthn_challenges": 1,
        "failed_attempts": 1,
        "raw_ip": 1,
    }
    with factory() as s:
        after = _counts(s)
        assert s.scalar(select(func.count()).select_from(RequestReplayToken)) == 1
        assert s.scalar(select(func.count()).select_from(AuthenticationChallenge)) == 1
        identity = s.scalar(select(NetworkIdentity))
        assert identity is not None and identity.ip_address is None and identity.ip_hash
        assert s.scalar(select(func.count()).select_from(RiskAssessment)) == 1
    # Protected history is untouched, apart from the two audit events the runs added.
    assert {k: v for k, v in after.items() if k != "audit_events"} == {
        k: v for k, v in before.items() if k != "audit_events"
    }
    assert after["audit_events"] == before["audit_events"] + 2
    assert all(
        c.table is None
        or c.table.__tablename__ not in PROTECTED_TABLES
        or (c.action == "nullify" and c.table.__tablename__ in NULLIFY_ONLY)
        for c in CATEGORIES
    )


def test_retention_cli(sqlite_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", sqlite_url)

    def invoke(*args: str, input: str | None = None) -> Any:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), input=input, catch_exceptions=False)

    assert "dry run" in invoke("retention", "plan").output
    assert "no retention runs recorded" in invoke("retention", "status").output
    assert "DRY RUN" in invoke("retention", "run").output
    refused = invoke("retention", "run", "--execute", input="n\n")
    assert refused.exit_code != 0 and "nothing was deleted" in refused.output
    assert "EXECUTED" in invoke("retention", "run", "--execute", "--yes").output
    status = invoke("retention", "status").output
    assert "executed" in status and "dry-run" in status
    assert "audit chain OK (2 events)" in invoke("audit", "verify").output
    assert "retention.run" in invoke("audit", "list").output


# ------------------------------------------------------------------ secrets provider
def test_file_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "pseudo"
    secret.write_text("file-provided-pseudonymisation-key-0123456789\n")
    secret.chmod(0o600)
    monkeypatch.delenv("PSEUDONYMISATION_KEY", raising=False)
    monkeypatch.setenv("PSEUDONYMISATION_KEY_FILE", str(secret))
    settings = Settings()
    assert settings.pseudonymisation_key is not None
    assert settings.pseudonymisation_key.get_secret_value() == (
        "file-provided-pseudonymisation-key-0123456789"
    )
    monkeypatch.setenv("PSEUDONYMISATION_KEY", "x" * 40)
    with pytest.raises(SecretError, match="exactly one"):
        resolve_file_secrets()
    monkeypatch.delenv("PSEUDONYMISATION_KEY")
    secret.chmod(0o644)
    provider = FileSecretsProvider()
    assert provider.get("PSEUDONYMISATION_KEY") is not None and provider.warnings
    for content, message in ((b"", "empty"), (b"x" * 20000, "larger")):
        secret.write_bytes(content)
        with pytest.raises(SecretError, match=message):
            FileSecretsProvider().get("PSEUDONYMISATION_KEY")
    monkeypatch.setenv("PSEUDONYMISATION_KEY_FILE", str(tmp_path / "missing"))
    with pytest.raises(SecretError, match="missing"):
        FileSecretsProvider().get("PSEUDONYMISATION_KEY")
    monkeypatch.setenv("PSEUDONYMISATION_KEY_FILE", str(tmp_path))
    with pytest.raises(SecretError, match="regular file"):
        FileSecretsProvider().get("PSEUDONYMISATION_KEY")
    assert FileSecretsProvider({}).get("PSEUDONYMISATION_KEY") is None


# ------------------------------------------------------------------ logging
def _capture(fmt: str) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter("%(message)s"))
    handler.addFilter(RedactingFilter())
    logger = get_logger(f"hardening.{uuid.uuid4().hex[:6]}")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, stream


@pytest.mark.parametrize(
    "leak",
    [
        "Authorization: Bearer fak_0123456789abcdef.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab",
        "credential fak_0123456789abcdef.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab",
        "X-Fraud-Signature: v1=" + "ab" * 32,
        # Assembled at runtime so no literal resembles a real provider credential.
        "stripe key " + "sk_" + "test_" + "FAKEfake0000FAKE" + " and " + "whsec_" + "FAKEfake0000",
        "client secret pi_3Nabc_secret_DEFghi",
        "payment token tok_1NabcDEFghiJKL and pm_1NabcDEFghiJKL",
        "db postgresql+psycopg://fraud_ai:hunter2hunter2@db/fraud",
        "peer 203.0.113.77 connected",
        "card 4111 1111 1111 1111 cvv=123",
        "password=hunter2hunter2",
    ],
)
def test_logs_are_redacted(leak: str) -> None:
    for fmt in ("text", "json"):
        logger, stream = _capture(fmt)
        logger.warning("event: %s", leak)
        logger.warning(leak)
        out = stream.getvalue()
        for secret in (
            "AbCdEfGhIjKl",
            "ab" * 32,
            "FAKEfake0000FAKE",
            "FAKEfake0000",
            "secret_DEF",
            "tok_1N",
            "pm_1N",
            "hunter2",
            "203.0.113.77",
            "4111 1111",
            "cvv=123",
        ):
            assert secret not in out, (fmt, out)


def test_json_logs_are_structured() -> None:
    logger, stream = _capture("json")
    logger.info('{"event": "realtime_decision", "decision": "ALLOW"}')
    logger.info("plain message")
    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("failed")
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert lines[0]["event"] == {"event": "realtime_decision", "decision": "ALLOW"}
    assert lines[1]["message"] == "plain message" and lines[1]["level"] == "INFO"
    assert lines[2]["exception"] == "ValueError"
    assert all({"ts", "level", "logger"} <= set(line) for line in lines)


def test_stored_metadata_is_not_rewritten_by_log_rules() -> None:
    from fraud_ai.security.redaction import redact_mapping

    data = {"token_reference": "tok_abcdefgh1234", "note": "seen at 10.0.0.1"}
    assert redact_mapping(data) == data  # storage redaction stays narrow (Stages 1-9)
    assert hashlib.sha256(b"x").hexdigest()
    assert os.sep
