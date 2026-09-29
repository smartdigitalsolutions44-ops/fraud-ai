"""Two-person policy activation (Stage 11).

Flow (with ``POLICY_APPROVALS_REQUIRED=2``, the default in production)::

    shadow → evaluation → candidate           (fraud-ai policy promote …)
    approval A  (operator a, note)            (fraud-ai policy approve …)
    approval B  (operator b ≠ a, note)
    activation                                 (fraud-ai deployment activate …)

Rules:

* **Distinct approvers.** The same operator cannot approve a policy twice. Both the code and
  a database unique constraint enforce it. Activation counts **distinct** operators with
  valid approvals.
* **Only candidates.** Only a promoted ``candidate`` can be approved.
* **Pinned to the definition.** An approval covers the policy definition's SHA-256; it is
  void if the stored definition no longer hashes to that value.
* **Expiry.** Approvals expire after ``POLICY_APPROVAL_TTL_HOURS`` (72 h by default;
  0 means never), so a weeks-old approval cannot be used.

**Operator identity** is not a login system. It is ``OPERATOR_ID``, set by the trusted
configuration of the operator's CLI environment (for example per-operator shell profiles,
or a jump host that sets it from the SSO user). An optional ``OPERATOR_ALLOWLIST`` limits
who may approve. Every approval is audited (``policy.approved``) with the operator, time,
policy version and note.

**Limitation (documented, not solved):** someone who controls ``OPERATOR_ID`` in two
environments, or has database write access, can impersonate a second approver. The rule
defends against a single operator acting alone through the tooling, not against a
compromised host or a DBA. See THREAT_MODEL.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fraud_ai import audit
from fraud_ai.database.models import PolicyApproval
from fraud_ai.privacy import freetext
from fraud_ai.risk.promotion import current_stage
from fraud_ai.risk.registry import PolicyError, get_policy_record, verified_definition


@dataclass(frozen=True)
class ApprovalStatus:
    policy_version: str
    required: int
    valid_operators: tuple[str, ...]
    expired: tuple[str, ...]
    stale: tuple[str, ...]  # approved a different definition hash

    @property
    def satisfied(self) -> bool:
        return len(self.valid_operators) >= self.required


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def approve(
    session: Session,
    version: str,
    *,
    operator: str | None,
    note: str,
    ttl_hours: float,
    allowed: set[str] | None = None,
    now: datetime | None = None,
) -> PolicyApproval:
    now = now or datetime.now(UTC)
    if not operator:
        raise PolicyError(
            "approvals need an operator identity: set OPERATOR_ID in the operator's "
            "trusted CLI configuration"
        )
    if allowed is not None and operator not in allowed:
        raise PolicyError(f"operator {operator!r} is not in OPERATOR_ALLOWLIST")
    if not note or not note.strip():
        raise PolicyError("an approval needs a note explaining the decision")
    try:
        note = freetext.check("policy.approval_note", note) or ""
    except freetext.FreeTextError as exc:
        raise PolicyError(str(exc)) from None
    stage = current_stage(session, version)
    if stage != "candidate":
        raise PolicyError(
            f"only a promoted candidate can be approved ({version} is at stage {stage or 'none'})"
        )
    row = get_policy_record(session, version)
    verified_definition(row)  # the stored definition still hashes to its recorded value
    existing = session.scalar(
        select(PolicyApproval).where(
            PolicyApproval.policy_version == version, PolicyApproval.operator == operator
        )
    )
    if existing is not None:
        raise PolicyError(
            f"operator {operator!r} has already approved {version}; a second approval must "
            "come from a different operator"
        )
    approval = PolicyApproval(
        policy_version=version,
        policy_sha256=row.definition_sha256,
        operator=operator,
        note=note.strip()[:500],
        approved_at=now,
        expires_at=now + timedelta(hours=ttl_hours) if ttl_hours > 0 else None,
    )
    savepoint = session.begin_nested()
    try:
        session.add(approval)
        session.flush()
        savepoint.commit()
    except IntegrityError:
        savepoint.rollback()
        raise PolicyError(f"operator {operator!r} has already approved {version}") from None
    audit.record(
        session,
        "policy.approved",
        actor=f"operator:{operator}",
        target_type="policy",
        target_id=version,
        details={
            "note": approval.note,
            "policy_sha256": approval.policy_sha256,
            "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
        },
        now=now,
    )
    return approval


def status(
    session: Session, version: str, *, required: int, now: datetime | None = None
) -> ApprovalStatus:
    now = now or datetime.now(UTC)
    row = get_policy_record(session, version)
    valid: list[str] = []
    expired: list[str] = []
    stale: list[str] = []
    for approval in session.scalars(
        select(PolicyApproval)
        .where(PolicyApproval.policy_version == version)
        .order_by(PolicyApproval.approved_at)
    ):
        expires = _aware(approval.expires_at)
        if approval.policy_sha256 != row.definition_sha256:
            stale.append(approval.operator)
        elif expires is not None and expires <= now:
            expired.append(approval.operator)
        else:
            valid.append(approval.operator)
    return ApprovalStatus(
        version, required, tuple(dict.fromkeys(valid)), tuple(expired), tuple(stale)
    )


def ensure_approved(
    session: Session, version: str, *, required: int, now: datetime | None = None
) -> ApprovalStatus:
    """The activation gate: ``required`` distinct, unexpired approvals of this definition."""
    result = status(session, version, required=required, now=now)
    if not result.satisfied:
        detail = []
        if result.expired:
            detail.append(f"expired: {', '.join(result.expired)}")
        if result.stale:
            detail.append(f"for another definition: {', '.join(result.stale)}")
        extra = f" ({'; '.join(detail)})" if detail else ""
        raise PolicyError(
            f"{version} needs {required} approvals from different operators; it has "
            f"{len(result.valid_operators)} valid{extra}"
        )
    return result
