"""Step-up attempts and immutable follow-up assessments.

Stage 8 decides *whether* step-up is required: a ``STEP_UP_AUTHENTICATION`` assessment.
Stage 9 *executes* it, by WebAuthn or an external payment-authentication provider, and
records the result:

* every attempt is an append-only ``authentication_attempts`` row (method, result,
  attempt number, failure reason and credential or provider reference);
* a **terminal** attempt creates a **new assessment version**, the follow-up. The
  original is never modified. Terminal means a success, a cancellation, or any failure
  once ``max_attempts`` is reached.

The follow-up **copies the original's model scores verbatim**: raw probability,
calibrated score, final risk score, model scores and rule results. An authentication
adapter can never change a model probability. The decision comes from the versioned
follow-up policy below.

| Result | Follow-up decision | Why |
|---|---|---|
| SUCCESS | ALLOW_WITH_MONITORING | control completed: evidence, **not** proof |
| FAILED / EXPIRED / UNAVAILABLE (no attempts left) | MANUAL_REVIEW | control not completed |
| CANCELLED | MANUAL_REVIEW | the user abandoned the control |

A non-terminal failure leaves the original STEP_UP decision in force, so the client may
request a new challenge. Nothing here ever returns ALLOW.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import (
    AuthenticationMethod,
    AuthenticationResult,
    Decision,
)
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import AuthenticationAttempt, ReviewItem, RiskAssessment

FOLLOWUP_POLICY_VERSION = "step-up-followup-1.0.0"
FOLLOWUP_DECISIONS: dict[AuthenticationResult, Decision] = {
    AuthenticationResult.SUCCESS: Decision.ALLOW_WITH_MONITORING,
    AuthenticationResult.FAILED: Decision.MANUAL_REVIEW,
    AuthenticationResult.EXPIRED: Decision.MANUAL_REVIEW,
    AuthenticationResult.CANCELLED: Decision.MANUAL_REVIEW,
    AuthenticationResult.UNAVAILABLE: Decision.MANUAL_REVIEW,
}
ALWAYS_TERMINAL = frozenset({AuthenticationResult.SUCCESS, AuthenticationResult.CANCELLED})


class StepUpError(FraudAIError):
    def __init__(self, code: str, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def latest_assessment(session: Session, event_id: uuid.UUID) -> RiskAssessment | None:
    return session.scalar(
        select(RiskAssessment)
        .where(RiskAssessment.event_id == event_id)
        .order_by(RiskAssessment.assessment_version.desc())
    )


def step_up_target(session: Session, assessment_id: uuid.UUID) -> RiskAssessment:
    """The assessment a step-up executes. It must be the event's latest assessment and
    request STEP_UP_AUTHENTICATION, with no completed step-up."""
    row = session.get(RiskAssessment, assessment_id)
    if row is None:
        raise StepUpError("NOT_FOUND", "unknown assessment", 404)
    if row.decision is not Decision.STEP_UP_AUTHENTICATION:
        raise StepUpError(
            "STEP_UP_NOT_REQUIRED", "the assessment did not request step-up authentication"
        )
    latest = latest_assessment(session, row.event_id)
    if latest is not None and latest.assessment_id != row.assessment_id:
        raise StepUpError(
            "STEP_UP_ALREADY_COMPLETED",
            "a later assessment supersedes this one (step-up completed or reassessed)",
        )
    return row


def attempts_used(session: Session, assessment_id: uuid.UUID) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(AuthenticationAttempt)
            .where(AuthenticationAttempt.assessment_id == assessment_id)
        )
        or 0
    )


def ensure_attempts_left(session: Session, assessment_id: uuid.UUID, max_attempts: int) -> int:
    used = attempts_used(session, assessment_id)
    if used >= max_attempts:
        raise StepUpError("ATTEMPTS_EXHAUSTED", "no step-up attempts left for this assessment")
    return used + 1


def record_attempt(
    session: Session,
    assessment: RiskAssessment,
    method: AuthenticationMethod,
    result: AuthenticationResult,
    *,
    max_attempts: int,
    failure_reason: str | None = None,
    credential_ref: str | None = None,
    challenge_id: uuid.UUID | None = None,
    payment_request_id: uuid.UUID | None = None,
) -> tuple[AuthenticationAttempt, RiskAssessment | None]:
    number = attempts_used(session, assessment.assessment_id) + 1
    attempt = AuthenticationAttempt(
        assessment_id=assessment.assessment_id,
        method=method,
        attempt_number=number,
        result=result,
        failure_reason=failure_reason,
        credential_ref=credential_ref,
        challenge_id=challenge_id,
        payment_request_id=payment_request_id,
    )
    session.add(attempt)
    session.flush()
    followup = None
    if result in ALWAYS_TERMINAL or number >= max_attempts:
        followup = create_followup(session, assessment, attempt)
        attempt.followup_assessment_id = followup.assessment_id
        session.flush()
    return attempt, followup


def create_followup(
    session: Session, original: RiskAssessment, attempt: AuthenticationAttempt
) -> RiskAssessment:
    latest = latest_assessment(session, original.event_id)
    version = (latest.assessment_version if latest else original.assessment_version) + 1
    decision = FOLLOWUP_DECISIONS[attempt.result]
    reason = f"STEP_UP_{attempt.result.value}"
    key = hashlib.sha256(
        f"{original.event_id}:{FOLLOWUP_POLICY_VERSION}:{version}".encode()
    ).hexdigest()
    action: dict[str, object] = {
        "type": "MONITOR" if decision is Decision.ALLOW_WITH_MONITORING else decision.value,
        "followup_policy": FOLLOWUP_POLICY_VERSION,
        "step_up_method": attempt.method.value,
        "step_up_result": attempt.result.value,
        "authentication_attempt_id": str(attempt.attempt_id),
        "note": "authentication is additional evidence, not proof of legitimacy",
    }
    row = RiskAssessment(
        event_id=original.event_id,
        assessment_version=version,
        supersedes_assessment_id=original.assessment_id,
        idempotency_key=key,
        mode="step_up_followup",
        user_id=original.user_id,
        transaction_id=original.transaction_id,
        prediction_id=original.prediction_id,
        deployment_id=original.deployment_id,
        event_time=original.event_time,
        arrival_time=original.arrival_time,
        lateness_seconds=original.lateness_seconds,
        policy_version=original.policy_version,
        rules_version=original.rules_version,
        primary_model=original.primary_model,
        # Scores are copied verbatim: step-up never changes a model probability.
        ml_probability=original.ml_probability,
        calibrated_score=original.calibrated_score,
        final_risk_score=original.final_risk_score,
        risk_level=original.risk_level,
        model_scores=dict(original.model_scores),
        triggered_rules=dict(original.triggered_rules),
        shadow={},
        decision=decision,
        reason_codes=[reason],
        action=action,
        latency_ms={},
        fallback_used=attempt.result is AuthenticationResult.UNAVAILABLE,
        failures=[],
        assessed_at=datetime.now(UTC),
    )
    session.add(row)
    session.flush()
    if decision is Decision.MANUAL_REVIEW:
        session.add(
            ReviewItem(
                assessment_id=row.assessment_id,
                event_id=row.event_id,
                priority=2,
                reason_codes=[reason],
            )
        )
        session.flush()
    return row


def authentication_status(session: Session, assessment_id: uuid.UUID) -> dict[str, object]:
    """A safe summary for the assessment API."""
    rows = list(
        session.scalars(
            select(AuthenticationAttempt)
            .where(AuthenticationAttempt.assessment_id == assessment_id)
            .order_by(AuthenticationAttempt.attempt_number)
        )
    )
    if not rows:
        return {"attempts": 0, "latest_result": None, "method": None, "completed": False}
    last = rows[-1]
    return {
        "attempts": len(rows),
        "latest_result": last.result.value,
        "method": last.method.value,
        "completed": last.followup_assessment_id is not None,
        "followup_assessment_id": str(last.followup_assessment_id)
        if last.followup_assessment_id
        else None,
    }
