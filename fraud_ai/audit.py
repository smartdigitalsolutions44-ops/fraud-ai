"""Immutable, hash-chained audit events for administrative actions (Stage 10).

Recorded actions:

| Action | When |
|---|---|
| ``service_key.created`` / ``.revoked`` / ``.rotated`` | CLI key management |
| ``policy.activated`` | a deployment is appended |
| ``policy.promoted`` | a lifecycle stage is recorded (shadow, evaluation, candidate, rejected) |
| ``review.resolved`` | an analyst outcome is appended (API or CLI) |
| ``retention.run`` | a retention job ran (dry-run or destructive) |
| ``service.configuration`` | the service started with a new configuration fingerprint |

**Chain.** Each event stores the previous event's hash. Its own hash is SHA-256 over a
canonical JSON of (sequence, time, actor, action, target, details, previous hash). Editing,
reordering or deleting an event breaks :func:`verify_chain`. Database triggers
additionally refuse UPDATE and DELETE. A DB superuser can still drop the triggers: the chain
detects tampering after the fact; it does not prevent it (see THREAT_MODEL.md).

**No secrets.** Details are checked: keys that look like secrets are refused, and string
values are passed through the log redaction filter.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import AuditEvent
from fraud_ai.security.redaction import redact_log_text as redact

_SECRET_KEY = re.compile(
    r"(^|_)(secret|password|passwd|credential|private_key|api_key|token|signature)$"
)
_ADVISORY_LOCK = 704_217_391  # PostgreSQL: serialise chain appends


class AuditError(FraudAIError):
    pass


def cli_actor() -> str:
    """``operator:<OPERATOR_ID>`` when an operator identity is configured (Stage 11),
    otherwise ``cli:<os user>``."""
    from fraud_ai.config.settings import get_settings

    try:
        operator = get_settings().operator_id
    except Exception:  # invalid settings must not hide who acted
        operator = None
    if operator:
        return f"operator:{operator}"
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - no user database in some containers
        user = "unknown"
    return f"cli:{user}"[:200]


def api_actor(key_id: str) -> str:
    return f"api_key:{key_id}"


def _clean(details: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in details.items():
        if _SECRET_KEY.search(key.lower()):
            raise AuditError(f"audit details must not contain secrets (field {key!r})")
        if isinstance(value, str):
            out[key] = redact(value)[:500]
        elif isinstance(value, dict):
            out[key] = _clean(value)
        elif isinstance(value, list | tuple):
            out[key] = [redact(v)[:200] if isinstance(v, str) else v for v in value][:100]
        else:
            out[key] = value
    return out


def _digest(row: AuditEvent) -> str:
    occurred = row.occurred_at
    if occurred.tzinfo is None:
        occurred = occurred.replace(tzinfo=UTC)
    payload = {
        "sequence": row.sequence,
        "occurred_at": occurred.astimezone(UTC).isoformat(timespec="microseconds"),
        "actor": row.actor,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "details": row.details,
        "previous_sha256": row.previous_sha256,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def record(
    session: Session,
    action: str,
    *,
    actor: str,
    target_type: str,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> AuditEvent:
    """Append an event in the caller's transaction (it commits with the action itself)."""
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK})
    last = session.scalar(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1))
    row = AuditEvent(
        sequence=(last.sequence + 1) if last else 1,
        occurred_at=now or datetime.now(UTC),
        actor=actor[:200],
        action=action,
        target_type=target_type,
        target_id=target_id[:120] if target_id else None,
        details=_clean(details or {}),
        previous_sha256=last.event_sha256 if last else None,
        event_sha256="0" * 64,
    )
    row.event_sha256 = _digest(row)
    session.add(row)
    session.flush()
    return row


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    events: int
    first_bad_sequence: int | None
    reason: str | None


def verify_chain(session: Session) -> ChainReport:
    previous: str | None = None
    expected_sequence = 1
    count = 0
    for row in session.scalars(select(AuditEvent).order_by(AuditEvent.sequence)):
        count += 1
        if row.sequence != expected_sequence:
            return ChainReport(False, count, row.sequence, "sequence gap (an event was removed)")
        if row.previous_sha256 != previous:
            return ChainReport(False, count, row.sequence, "previous-hash mismatch")
        if _digest(row) != row.event_sha256:
            return ChainReport(False, count, row.sequence, "event hash mismatch (edited)")
        previous = row.event_sha256
        expected_sequence += 1
    return ChainReport(True, count, None, None)


def list_events(
    session: Session, *, action: str | None = None, limit: int = 50
) -> list[AuditEvent]:
    stmt = select(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    return list(session.scalars(stmt.order_by(AuditEvent.sequence.desc()).limit(limit)))
