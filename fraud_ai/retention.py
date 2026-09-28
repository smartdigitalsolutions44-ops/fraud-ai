"""Configurable retention jobs (Stage 10).

Only short-lived operational records and optional raw personal data are ever cleaned:

Categories (``RETENTION_*_DAYS``; 0 disables one):

* ``replay_tokens``: request/callback replay tokens past their expiry (always; they are
  useless after expiry).
* ``idempotency``: completed Idempotency-Key records older than N days, and placeholders
  stuck ``in_progress`` for over an hour (default 7 days).
* ``webauthn_challenges``: expired challenges older than N days that no authentication
  attempt references (default 7 days).
* ``payment_requests``: terminal payment-auth requests older than N days that no attempt
  references (disabled by default).
* ``failed_attempts``: non-terminal failed/expired attempts without a follow-up, older
  than N days (disabled by default).
* ``raw_ip``: raw IP addresses (only stored with ``STORE_RAW_IP``) older than N days are
  set to NULL; the keyed hash stays (default 30 days).
* ``log_files``: not applicable; the application writes logs to stderr only.

**Never touched** (see :data:`PROTECTED_TABLES`): events, risk assessments, model and
policy history, deployments, fraud labels, review items and outcomes, investigations,
audit events and lifecycle events. Only an explicit future data-retention policy could
change that; this module has no code path that deletes them.

Runs are dry-run by default. A destructive run needs ``--execute`` **and** either
``RETENTION_ALLOW_DELETE=true`` or an interactive confirmation. Every run, dry or not, is
recorded as an audit event with the per-category counts.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, exists, func, or_, select, update
from sqlalchemy.orm import Session

from fraud_ai import audit
from fraud_ai.config.settings import Settings
from fraud_ai.core.enums import AuthenticationResult, PaymentAuthStatus
from fraud_ai.database.models import (
    AuthenticationAttempt,
    AuthenticationChallenge,
    NetworkIdentity,
    PaymentAuthRequest,
    RequestIdempotency,
    RequestReplayToken,
)

PROTECTED_TABLES = frozenset(
    {
        "events",
        "risk_assessments",
        "model_versions",
        "model_predictions",
        "model_calibrations",
        "risk_policies",
        "policy_deployments",
        "policy_lifecycle_events",
        "fraud_labels",
        "review_queue",
        "review_outcomes",
        "investigations",
        "audit_events",
        "feature_snapshots",
    }
)
STALE_IN_PROGRESS = timedelta(hours=1)


class RetentionError(Exception):
    pass


@dataclass(frozen=True)
class Category:
    name: str
    description: str
    action: str  # "delete" | "nullify" | "n/a"
    days: Callable[[Settings], float | None]  # None: always; 0: disabled
    condition: Callable[[datetime, float], Any] | None
    table: Any = None


def _days(value: float) -> timedelta:
    return timedelta(days=value)


def _replay(now: datetime, days: float) -> Any:
    return RequestReplayToken.expires_at < now


def _idempotency(now: datetime, days: float) -> Any:
    return or_(
        and_(
            RequestIdempotency.state == "completed",
            RequestIdempotency.created_at < now - _days(days),
        ),
        and_(
            RequestIdempotency.state == "in_progress",
            RequestIdempotency.created_at < now - STALE_IN_PROGRESS,
        ),
    )


def _challenges(now: datetime, days: float) -> Any:
    referenced = exists().where(
        AuthenticationAttempt.challenge_id == AuthenticationChallenge.challenge_id
    )
    return and_(AuthenticationChallenge.expires_at < now - _days(days), ~referenced)


_TERMINAL = [s for s in PaymentAuthStatus if s is not PaymentAuthStatus.PENDING]


def _payments(now: datetime, days: float) -> Any:
    referenced = exists().where(
        AuthenticationAttempt.payment_request_id == PaymentAuthRequest.request_id
    )
    return and_(
        PaymentAuthRequest.status.in_(_TERMINAL),
        PaymentAuthRequest.created_at < now - _days(days),
        ~referenced,
    )


def _attempts(now: datetime, days: float) -> Any:
    return and_(
        AuthenticationAttempt.followup_assessment_id.is_(None),
        AuthenticationAttempt.result != AuthenticationResult.SUCCESS,
        AuthenticationAttempt.created_at < now - _days(days),
    )


def _raw_ip(now: datetime, days: float) -> Any:
    return and_(
        NetworkIdentity.ip_address.is_not(None), NetworkIdentity.last_seen_at < now - _days(days)
    )


CATEGORIES: tuple[Category, ...] = (
    Category(
        "replay_tokens",
        "expired replay tokens",
        "delete",
        lambda s: None,
        _replay,
        RequestReplayToken,
    ),
    Category(
        "idempotency",
        "old Idempotency-Key records",
        "delete",
        lambda s: s.retention_idempotency_days,
        _idempotency,
        RequestIdempotency,
    ),
    Category(
        "webauthn_challenges",
        "expired, unreferenced WebAuthn challenges",
        "delete",
        lambda s: s.retention_challenge_days,
        _challenges,
        AuthenticationChallenge,
    ),
    Category(
        "payment_requests",
        "terminal, unreferenced payment-auth requests",
        "delete",
        lambda s: s.retention_payment_request_days,
        _payments,
        PaymentAuthRequest,
    ),
    Category(
        "failed_attempts",
        "non-terminal failed step-up attempts",
        "delete",
        lambda s: s.retention_failed_attempt_days,
        _attempts,
        AuthenticationAttempt,
    ),
    Category(
        "raw_ip",
        "raw IP addresses (the keyed hash is kept)",
        "nullify",
        lambda s: s.retention_raw_ip_days,
        _raw_ip,
        NetworkIdentity,
    ),
    Category(
        "log_files",
        "no locally persisted logs (stderr only)",
        "n/a",
        lambda s: 0.0,
        None,
        None,
    ),
)


@dataclass(frozen=True)
class CategoryPlan:
    name: str
    description: str
    action: str
    enabled: bool
    days: float | None
    rows: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "enabled": self.enabled,
            "days": self.days,
            "rows": self.rows,
        }


def plan(
    session: Session, settings: Settings, *, now: datetime | None = None
) -> list[CategoryPlan]:
    now = now or datetime.now(UTC)
    out = []
    for cat in CATEGORIES:
        days = cat.days(settings)
        enabled = cat.condition is not None and (days is None or days > 0)
        rows = 0
        if enabled and cat.condition is not None:
            assert cat.table.__tablename__ not in PROTECTED_TABLES
            rows = int(
                session.scalar(
                    select(func.count())
                    .select_from(cat.table)
                    .where(cat.condition(now, days or 0.0))
                )
                or 0
            )
        out.append(CategoryPlan(cat.name, cat.description, cat.action, enabled, days, rows))
    return out


def run(
    session: Session,
    settings: Settings,
    *,
    execute: bool,
    confirmed: bool = False,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply the plan (or only report it). Returns and audits the per-category counts."""
    now = now or datetime.now(UTC)
    if execute and not (confirmed or settings.retention_allow_delete):
        raise RetentionError(
            "destructive retention needs RETENTION_ALLOW_DELETE=true or an explicit "
            "confirmation (--yes)"
        )
    planned = plan(session, settings, now=now)
    applied: dict[str, int] = {}
    if execute:
        for cat, item in zip(CATEGORIES, planned, strict=True):
            if not item.enabled or item.rows == 0 or cat.condition is None:
                continue
            assert cat.table.__tablename__ not in PROTECTED_TABLES
            condition = cat.condition(now, item.days or 0.0)
            if cat.action == "delete":
                result = session.execute(
                    delete(cat.table).where(condition).execution_options(synchronize_session=False)
                )
            else:
                result = session.execute(
                    update(cat.table)
                    .where(condition)
                    .values(ip_address=None)
                    .execution_options(synchronize_session=False)
                )
            applied[cat.name] = int(getattr(result, "rowcount", 0) or 0)
    report = {
        "dry_run": not execute,
        "at": now.isoformat(),
        "categories": [p.to_dict() for p in planned],
        "applied": applied,
    }
    audit.record(
        session,
        "retention.run",
        actor=actor,
        target_type="retention",
        details={
            "dry_run": not execute,
            "planned": {p.name: p.rows for p in planned if p.enabled},
            "applied": applied,
        },
        now=now,
    )
    return report


def last_runs(session: Session, limit: int = 10) -> list[dict[str, Any]]:
    return [
        {
            "sequence": e.sequence,
            "at": e.occurred_at.isoformat(),
            "actor": e.actor,
            **e.details,
        }
        for e in audit.list_events(session, action="retention.run", limit=limit)
    ]
