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

**Operator identity (Stage 12).** With operator authentication (``OPERATOR_AUTH_REQUIRED``,
the default in staging and production) an approval needs a verified assertion from a
registered operator key with the ``policy_approver`` role (:mod:`fraud_ai.trust.operators`).
The identity recorded is the assertion's subject, never a configured string. The
assertion is bound to the policy version, its definition hash and the note's hash. It is
kept with the approval, and **activation re-verifies it**: an approval row written directly
into the database, or one whose operator has since lost the role or been disabled, does not
count.

Without operator authentication (development), Stage 11's ``OPERATOR_ID`` from trusted CLI
configuration is still accepted. It is configuration, not authentication. An optional
``OPERATOR_ALLOWLIST`` limits who may approve. Every approval is audited
(``policy.approved``) with the operator, time, policy version and note.

**Remaining limitation:** someone holding two operators' private keys can still act as
both. Keys are per person and should be kept on hardware (see THREAT_MODEL.md).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

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
    unverified: tuple[str, ...] = ()  # Stage 12: evidence missing or not verifiable

    @property
    def satisfied(self) -> bool:
        return len(self.valid_operators) >= self.required


@dataclass(frozen=True)
class EvidenceCheck:
    """Re-verification of stored approval assertions (operator authentication on)."""

    registry: Any  # fraud_ai.trust.operators.OperatorRegistry
    audience: str
    max_lifetime: int
    leeway: int

    @classmethod
    def from_settings(cls, settings: Any) -> EvidenceCheck | None:
        if not settings.operator_auth_is_required:
            return None
        from fraud_ai.trust.operators import registry_from_settings

        return cls(
            registry_from_settings(settings),
            settings.operator_audience,
            settings.operator_assertion_max_seconds,
            settings.operator_assertion_leeway_seconds,
        )

    def problem(self, approval: PolicyApproval) -> str | None:
        from fraud_ai.trust.operators import OperatorAuthError, verify_assertion

        if not approval.assertion:
            return "no operator assertion (unauthenticated approval)"
        try:
            verified = verify_assertion(
                approval.assertion,
                self.registry,
                audience=self.audience,
                action="policy.approve",
                target=approval.policy_version,
                binding=approval_binding(approval.policy_sha256, approval.note),
                max_lifetime=self.max_lifetime,
                leeway=self.leeway,
                at=_aware(approval.approved_at),
            )
        except OperatorAuthError as exc:
            return f"assertion does not verify ({exc.code})"
        if verified.operator_id != approval.operator or verified.jti != approval.assertion_jti:
            return "assertion belongs to another operator or approval"
        return None


def normalise_note(note: str) -> str:
    """The note exactly as it will be stored (and hashed into the operator's binding)."""
    if not note or not note.strip():
        raise PolicyError("an approval needs a note explaining the decision")
    try:
        checked = freetext.check("policy.approval_note", note) or ""
    except freetext.FreeTextError as exc:
        raise PolicyError(str(exc)) from None
    return checked.strip()[:500]


def approval_binding(definition_sha256: str, note: str) -> dict[str, str]:
    """What an approval assertion is bound to: this exact definition and this note."""
    return {
        "definition_sha256": definition_sha256,
        "note_sha256": hashlib.sha256(note.encode()).hexdigest(),
    }


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
    identity: Any = None,
    evidence: str | None = None,
) -> PolicyApproval:
    """Record one approval. ``identity`` (a verified operator assertion) and ``evidence``
    (its token) come from :func:`fraud_ai.trust.operators.authenticate`; the identity then
    replaces any configured operator string."""
    now = now or datetime.now(UTC)
    if identity is not None:
        operator = identity.operator_id
    if not operator:
        raise PolicyError(
            "approvals need an operator identity: an operator assertion, or (development "
            "only) OPERATOR_ID in the operator's trusted CLI configuration"
        )
    if allowed is not None and operator not in allowed:
        raise PolicyError(f"operator {operator!r} is not in OPERATOR_ALLOWLIST")
    note = normalise_note(note)
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
    if identity is not None and identity.binding != approval_binding(row.definition_sha256, note):
        raise PolicyError("the operator assertion was made for a different definition or note")
    approval = PolicyApproval(
        policy_version=version,
        policy_sha256=row.definition_sha256,
        operator=operator,
        note=note,
        approved_at=now,
        expires_at=now + timedelta(hours=ttl_hours) if ttl_hours > 0 else None,
        operator_key_id=identity.key_id if identity is not None else None,
        assertion_jti=identity.jti if identity is not None else None,
        assertion=evidence if identity is not None else None,
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
            "authenticated": identity is not None,
            "key_id": approval.operator_key_id,
            "jti": approval.assertion_jti,
        },
        now=now,
    )
    return approval


def status(
    session: Session,
    version: str,
    *,
    required: int,
    now: datetime | None = None,
    evidence: EvidenceCheck | None = None,
) -> ApprovalStatus:
    now = now or datetime.now(UTC)
    row = get_policy_record(session, version)
    valid: list[str] = []
    expired: list[str] = []
    stale: list[str] = []
    unverified: list[str] = []
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
        elif evidence is not None and (problem := evidence.problem(approval)) is not None:
            unverified.append(f"{approval.operator}: {problem}")
        else:
            valid.append(approval.operator)
    return ApprovalStatus(
        version,
        required,
        tuple(dict.fromkeys(valid)),
        tuple(expired),
        tuple(stale),
        tuple(unverified),
    )


def ensure_approved(
    session: Session,
    version: str,
    *,
    required: int,
    now: datetime | None = None,
    evidence: EvidenceCheck | None = None,
) -> ApprovalStatus:
    """The activation gate: ``required`` distinct, unexpired approvals of this definition
    (and, with operator authentication, each backed by an assertion that re-verifies)."""
    result = status(session, version, required=required, now=now, evidence=evidence)
    if not result.satisfied:
        detail = []
        if result.expired:
            detail.append(f"expired: {', '.join(result.expired)}")
        if result.stale:
            detail.append(f"for another definition: {', '.join(result.stale)}")
        if result.unverified:
            detail.append(f"not verifiable: {'; '.join(result.unverified)}")
        extra = f" ({'; '.join(detail)})" if detail else ""
        raise PolicyError(
            f"{version} needs {required} approvals from different operators; it has "
            f"{len(result.valid_operators)} valid{extra}"
        )
    return result
