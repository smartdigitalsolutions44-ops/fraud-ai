"""Request and response schemas of the versioned API (``fraud-api-1.0.0``).

Requests are strict: unknown fields are refused (``extra="forbid"``), strings are bounded
and ids are typed.

Responses are *safe representations*. They carry decisions, reason codes, versions and
statuses. They never carry:

* model probabilities, calibrated scores, feature values, rule internals or shadow
  results;
* artefact paths;
* personal data or secrets.

The score request body is the Stage 8 real-time event contract (``realtime-event-1``).
It is validated by :func:`fraud_ai.realtime.contract.parse_incoming`, which forbids
unexpected fields, unknown event types and schema versions, malformed ids and future
timestamps.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from fraud_ai.core.enums import ReviewResolution

API_VERSION = "fraud-api-1.0.0"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True)


# ------------------------------------------------------------------ score
class ScoreResponse(_Out):
    api_version: str = API_VERSION
    status: Literal["decided", "duplicate", "ingested"]
    event_id: uuid.UUID
    assessment_id: uuid.UUID | None
    assessment_version: int | None
    risk_level: str | None
    decision: str | None
    reason_codes: list[str]
    action_type: str | None
    policy_version: str | None
    model_version: str | None
    step_up_required: bool
    review_required: bool
    fallback_used: bool


# ------------------------------------------------------------------ assessments
class ReviewStatusView(_Out):
    review_id: uuid.UUID
    status: str
    priority: int
    outcome: str | None


class AuthenticationStatusView(_Out):
    attempts: int
    latest_result: str | None
    method: str | None
    completed: bool
    followup_assessment_id: uuid.UUID | None = None


class AssessmentView(_Out):
    api_version: str = API_VERSION
    assessment_id: uuid.UUID
    event_id: uuid.UUID
    assessment_version: int
    supersedes_assessment_id: uuid.UUID | None
    latest_assessment_id: uuid.UUID
    mode: str
    decision: str
    risk_level: str
    reason_codes: list[str]
    action_type: str | None
    policy_version: str
    model_version: str | None
    fallback_used: bool
    assessed_at: datetime
    step_up_required: bool
    review_required: bool
    review: ReviewStatusView | None
    authentication: AuthenticationStatusView


# ------------------------------------------------------------------ reviews
class ReviewItemView(_Out):
    review_id: uuid.UUID
    assessment_id: uuid.UUID
    event_id: uuid.UUID
    priority: int
    status: str
    reason_codes: list[str]
    created_at: datetime
    reviewed_at: datetime | None
    outcome: str | None


class ReviewList(_Out):
    api_version: str = API_VERSION
    items: list[ReviewItemView]


class ReviewOutcomeView(_Out):
    outcome_id: uuid.UUID
    resolution: str
    note: str | None
    created_at: datetime


class ReviewDetailView(_Out):
    api_version: str = API_VERSION
    review: ReviewItemView
    assessment: AssessmentView
    outcomes: list[ReviewOutcomeView]


class ResolveRequest(_Strict):
    resolution: ReviewResolution
    note: StrictStr | None = Field(default=None, max_length=500)


# ------------------------------------------------------------------ policy
class PolicyView(_Out):
    api_version: str = API_VERSION
    policy_version: str
    rules_version: str
    primary_model: str
    decision_event_kinds: list[str]
    activated_at: datetime
    followup_policy_version: str


# ------------------------------------------------------------------ step-up
class AssessmentSummary(_Out):
    assessment_id: uuid.UUID
    assessment_version: int
    supersedes_assessment_id: uuid.UUID | None
    decision: str
    reason_codes: list[str]
    policy_version: str
    followup_policy_version: str | None
    review_required: bool


class WebAuthnChallengeRequest(_Strict):
    session_id: StrictStr = Field(min_length=1, max_length=128)


class ChallengeResponse(_Out):
    api_version: str = API_VERSION
    challenge_id: uuid.UUID
    expires_at: datetime
    public_key: dict[str, Any]


class WebAuthnVerifyRequest(_Strict):
    challenge_id: uuid.UUID
    session_id: StrictStr = Field(min_length=1, max_length=128)
    credential: dict[str, Any]


class WebAuthnCancelRequest(_Strict):
    challenge_id: uuid.UUID


class StepUpResult(_Out):
    api_version: str = API_VERSION
    assessment_id: uuid.UUID
    method: str
    result: str
    attempt_number: int | None
    failure_reason: str | None
    attempts_remaining: int
    followup: AssessmentSummary | None
    note: str = "authentication is additional evidence, never proof of legitimacy"


class PaymentAuthRequestBody(_Strict):
    token_reference: StrictStr = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    amount_minor: StrictInt | None = Field(default=None, ge=0, le=10**12)
    currency: StrictStr | None = Field(default=None, pattern=r"^[A-Z]{3}$")


class PaymentAuthView(_Out):
    api_version: str = API_VERSION
    assessment_id: uuid.UUID
    request_id: uuid.UUID | None
    provider: str
    status: str
    next_action: dict[str, Any]
    result: str | None
    followup: AssessmentSummary | None


class PaymentStatusView(_Out):
    api_version: str = API_VERSION
    request_id: uuid.UUID
    status: str


class CallbackAck(_Out):
    api_version: str = API_VERSION
    accepted: bool
    status: str
    result: str | None


# ------------------------------------------------------------------ passkey registration
class RegistrationChallengeRequest(_Strict):
    user_id: uuid.UUID


class RegistrationRequest(_Strict):
    challenge_id: uuid.UUID
    credential: dict[str, Any]


class CredentialView(_Out):
    api_version: str = API_VERSION
    credential_ref: str
    status: str
    created_at: datetime


# ------------------------------------------------------------------ investigation
class InvestigationView(_Out):
    api_version: str = API_VERSION
    assessment_id: uuid.UUID
    investigation_id: uuid.UUID
    explanation_version: int
    runtime: str
    model: str
    explanation: str
    note: str = "decision support only; nothing was rescored or decided"


# ------------------------------------------------------------------ operations
class HealthView(_Out):
    status: Literal["ok"]
    api_version: str = API_VERSION


class ReadyView(_Out):
    status: Literal["ready", "not_ready"]
    api_version: str = API_VERSION
    checks: dict[str, str]
