"""Versioned HTTP routes (``/v1``). Thin adapters over the existing application code.

* Scoring: :class:`fraud_ai.realtime.service.FraudScoringService`.
* Reviews: :mod:`fraud_ai.realtime.review`.
* Step-up: :mod:`fraud_ai.stepup`.
* Investigation: :mod:`fraud_ai.llm.service`, imported lazily and only by its own
  endpoint.

No business logic lives here. Handlers validate the transport, check authorisation,
translate domain errors into API errors and build the safe response views.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, TypeVar

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from fraud_ai import audit
from fraud_ai.core.enums import AuthenticationMethod, Decision, ReviewStatus
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.engine import session_scope, write_scope
from fraud_ai.database.models import (
    AuthenticationChallenge,
    EventRecord,
    ReviewItem,
    ReviewOutcome,
    RiskAssessment,
)
from fraud_ai.realtime import review as review_ops
from fraud_ai.realtime.service import ScoringOutcome
from fraud_ai.risk.registry import active_deployment
from fraud_ai.service import idempotency
from fraud_ai.service.dependencies import Caller, ServiceContainer, container_of, require
from fraud_ai.service.errors import ApiError, log
from fraud_ai.service.health import is_ready, readiness
from fraud_ai.service.metrics import CONTENT_TYPE
from fraud_ai.service.network import claimed_intel
from fraud_ai.service.schemas import (
    API_VERSION,
    AssessmentSummary,
    AssessmentView,
    AuthenticationStatusView,
    CallbackAck,
    ChallengeResponse,
    CredentialView,
    HealthView,
    InvestigationView,
    PaymentAuthRequestBody,
    PaymentAuthView,
    PaymentStatusView,
    PolicyView,
    ReadyView,
    RegistrationChallengeRequest,
    RegistrationRequest,
    ResolveRequest,
    ReviewDetailView,
    ReviewItemView,
    ReviewList,
    ReviewOutcomeView,
    ReviewStatusView,
    ScoreResponse,
    StepUpResult,
    WebAuthnCancelRequest,
    WebAuthnChallengeRequest,
    WebAuthnVerifyRequest,
)
from fraud_ai.service.signatures import SignatureError
from fraud_ai.state.base import StateUnavailableError
from fraud_ai.stepup import payment as payment_ops
from fraud_ai.stepup import webauthn as webauthn_ops
from fraud_ai.stepup.outcomes import (
    FOLLOWUP_POLICY_VERSION,
    StepUpError,
    attempts_used,
    authentication_status,
    latest_assessment,
)
from fraud_ai.utils.time import ensure_utc

T = TypeVar("T")
router = APIRouter(prefix="/v1")
SCORE_ROUTE = "POST /v1/score"
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"description": "missing or invalid credentials / signature"},
    403: {"description": "the API key lacks the required scope"},
    422: {"description": "invalid request"},
    429: {"description": "rate limited"},
}


# ------------------------------------------------------------------ helpers
def _safe(message: str | None) -> str:
    return _UUID.sub("<id>", message or "")[:300]


def _stepup_error(exc: StepUpError) -> ApiError:
    return ApiError(exc.status, exc.code, _safe(str(exc)))


def _json_object(request: Request, body: bytes) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "INVALID_JSON", "the request body is not valid JSON") from None
    if not isinstance(data, dict):
        raise ApiError(422, "INVALID_EVENT", "the request body must be a JSON object")
    return data


async def _run_with_timeout(
    pool: concurrent.futures.ThreadPoolExecutor, fn: Callable[[], T], timeout: float
) -> T:
    return await asyncio.wait_for(asyncio.wrap_future(pool.submit(fn)), timeout)


def _review_row(session: Session, assessment_id: uuid.UUID) -> ReviewItem | None:
    return session.scalar(select(ReviewItem).where(ReviewItem.assessment_id == assessment_id))


def assessment_view(session: Session, row: RiskAssessment) -> AssessmentView:
    latest = latest_assessment(session, row.event_id) or row
    review = _review_row(session, row.assessment_id)
    auth = authentication_status(session, row.assessment_id)
    return AssessmentView(
        assessment_id=row.assessment_id,
        event_id=row.event_id,
        assessment_version=row.assessment_version,
        supersedes_assessment_id=row.supersedes_assessment_id,
        latest_assessment_id=latest.assessment_id,
        mode=row.mode,
        decision=row.decision.value,
        risk_level=row.risk_level,
        reason_codes=list(row.reason_codes),
        action_type=(row.action or {}).get("type"),
        policy_version=row.policy_version,
        model_version=row.primary_model,
        fallback_used=row.fallback_used,
        assessed_at=ensure_utc(row.assessed_at),
        step_up_required=row.decision is Decision.STEP_UP_AUTHENTICATION
        and latest.assessment_id == row.assessment_id,
        review_required=review is not None,
        review=ReviewStatusView(
            review_id=review.review_id,
            status=review.status.value,
            priority=review.priority,
            outcome=review.outcome.value if review.outcome else None,
        )
        if review
        else None,
        authentication=AuthenticationStatusView.model_validate(auth),
    )


def _summary(session: Session, row: RiskAssessment | None) -> AssessmentSummary | None:
    if row is None:
        return None
    return AssessmentSummary(
        assessment_id=row.assessment_id,
        assessment_version=row.assessment_version,
        supersedes_assessment_id=row.supersedes_assessment_id,
        decision=row.decision.value,
        reason_codes=list(row.reason_codes),
        policy_version=row.policy_version,
        followup_policy_version=(row.action or {}).get("followup_policy"),
        review_required=_review_row(session, row.assessment_id) is not None,
    )


def _review_view(item: ReviewItem) -> ReviewItemView:
    return ReviewItemView(
        review_id=item.review_id,
        assessment_id=item.assessment_id,
        event_id=item.event_id,
        priority=item.priority,
        status=item.status.value,
        reason_codes=list(item.reason_codes),
        created_at=ensure_utc(item.created_at),
        reviewed_at=ensure_utc(item.reviewed_at) if item.reviewed_at else None,
        outcome=item.outcome.value if item.outcome else None,
    )


def _outcome_view(o: ReviewOutcome) -> ReviewOutcomeView:
    return ReviewOutcomeView(
        outcome_id=o.outcome_id,
        resolution=o.resolution.value,
        note=o.note,
        created_at=ensure_utc(o.created_at),
    )


def score_payload(outcome: ScoringOutcome) -> tuple[int, dict[str, Any]]:
    """Map a Stage 8 outcome onto the API: a status code and a safe body."""
    if outcome.status == "rejected":
        message = _safe(outcome.error)
        if "conflicting duplicate" in message:
            raise ApiError(409, "EVENT_CONFLICT", message)
        raise ApiError(422, "INVALID_EVENT", message)
    if outcome.status == "not_persisted" or outcome.event_id is None:
        raise ApiError(
            503,
            "SCORING_UNAVAILABLE",
            "the decision could not be stored; treat the event as requiring manual review",
            extra={"fallback_decision": Decision.MANUAL_REVIEW.value},
        )
    decision = outcome.decision
    body = ScoreResponse(
        status=outcome.status,
        event_id=outcome.event_id,
        assessment_id=outcome.assessment_id,
        assessment_version=outcome.assessment_version,
        risk_level=outcome.risk_level,
        decision=decision.value if decision else None,
        reason_codes=list(outcome.reason_codes),
        action_type=outcome.action.get("type") if outcome.action else None,
        policy_version=outcome.policy_version,
        model_version=outcome.primary_model,
        step_up_required=decision is Decision.STEP_UP_AUTHENTICATION,
        review_required=outcome.review_id is not None,
        fallback_used=outcome.fallback_used,
    )
    return (202 if outcome.status == "ingested" else 200), body.model_dump(mode="json")


# ------------------------------------------------------------------ scoring
@router.post(
    "/score",
    response_model=ScoreResponse,
    responses={
        **_ERRORS,
        202: {"description": "ingested; not a decision point"},
        409: {"description": "idempotency conflict or conflicting event id"},
        503: {"description": "scoring unavailable (fallback: MANUAL_REVIEW)"},
    },
    summary="Score one event (realtime-event-1 contract)",
)
async def score(
    request: Request,
    caller: Annotated[Caller, Depends(require("score:write"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> Response:
    c = container_of(request)
    data = _json_object(request, caller.body)
    arrival: datetime | None = None
    if "arrival_time" in data:
        if not caller.has("score:replay"):
            raise ApiError(
                403,
                "INSUFFICIENT_SCOPE",
                "arrival_time is set by the service; supplying it requires score:replay",
            )
        raw = data.pop("arrival_time")
        try:
            arrival = ensure_utc(datetime.fromisoformat(str(raw)))
        except ValueError:
            raise ApiError(422, "INVALID_EVENT", "arrival_time is not an ISO-8601 time") from None
    intel = claimed_intel(data)
    if intel and not caller.has("signals:trusted"):
        raise ApiError(
            422,
            "UNTRUSTED_SIGNAL",
            "network-intelligence fields are accepted only from trusted infrastructure "
            f"(signals:trusted): {', '.join(intel)}",
        )
    record_id = None
    if idempotency_key is not None:
        key = idempotency.validate_key(idempotency_key)
        record_id, stored = await run_in_threadpool(
            idempotency.begin,
            c.factory,
            caller.key_id,
            SCORE_ROUTE,
            key,
            idempotency.body_digest(caller.body),
        )
        if stored is not None:
            c.metrics.idempotent_replays.inc()
            return JSONResponse(
                stored.body, stored.status_code, headers={"Idempotent-Replayed": "true"}
            )
    try:
        try:
            outcome = await _run_with_timeout(
                c.scoring_pool,
                lambda: c.scoring.score_event(data, arrival_time=arrival),
                c.settings.service_request_timeout,
            )
        except TimeoutError:
            raise ApiError(
                503,
                "SCORING_TIMEOUT",
                "scoring did not finish in time; treat the event as requiring manual review "
                "and retry with the same event_id",
                extra={"fallback_decision": Decision.MANUAL_REVIEW.value},
            ) from None
        status, body = score_payload(outcome)
    except BaseException:
        if record_id is not None:
            await run_in_threadpool(idempotency.abandon, c.factory, record_id)
        raise
    if record_id is not None:
        await run_in_threadpool(
            idempotency.complete, c.factory, record_id, status, body, outcome.policy_version
        )
    if outcome.decision is not None:
        c.metrics.decisions.labels(outcome.decision.value).inc()
        if outcome.status == "decided":
            c.metrics.policy_decisions.labels(
                outcome.policy_version or "none", outcome.decision.value
            ).inc()
    if outcome.fallback_used and outcome.status == "decided":
        first = outcome.failures[0]["category"] if outcome.failures else "fallback"
        c.metrics.fallbacks.labels(first).inc()
    return JSONResponse(body, status)


# ------------------------------------------------------------------ assessments
@router.get("/assessments/{assessment_id}", response_model=AssessmentView, responses=_ERRORS)
def get_assessment(
    assessment_id: uuid.UUID,
    request: Request,
    caller: Annotated[Caller, Depends(require("assessment:read"))],
) -> AssessmentView:
    c = container_of(request)
    with c.factory() as session:
        row = session.get(RiskAssessment, assessment_id)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "unknown assessment")
        return assessment_view(session, row)


@router.post(
    "/assessments/{assessment_id}/investigate",
    response_model=InvestigationView,
    responses={**_ERRORS, 503: {"description": "no LLM runtime"}, 504: {"description": "timeout"}},
    summary="Analyst-triggered LLM explanation (never part of scoring)",
)
async def investigate(
    assessment_id: uuid.UUID,
    request: Request,
    caller: Annotated[Caller, Depends(require("investigation:write"))],
) -> InvestigationView:
    c = container_of(request)
    try:
        client = c.llm_client()
    except FraudAIError:
        client = None
    if client is None:
        c.metrics.investigations.labels("unavailable").inc()
        raise ApiError(
            503,
            "LLM_UNAVAILABLE",
            "no local LLM runtime is available; scoring and decisions are unaffected",
        )

    def work() -> InvestigationView:
        from fraud_ai.llm.evidence import EvidenceError
        from fraud_ai.llm.service import GenerationSettings
        from fraud_ai.llm.service import investigate as run_investigation

        s = c.settings
        generation = GenerationSettings(
            temperature=s.local_llm_temperature,
            top_p=s.local_llm_top_p,
            seed=s.local_llm_seed,
            max_tokens=s.local_llm_max_tokens,
            context_window=s.local_llm_context_window,
        )
        with session_scope(c.factory) as session:  # no write lock: LLM calls are slow
            row = session.get(RiskAssessment, assessment_id)
            if row is None:
                raise ApiError(404, "NOT_FOUND", "unknown assessment")
            try:
                result = run_investigation(session, row.event_id, client, settings=generation)
            except EvidenceError as exc:
                raise ApiError(409, "INVESTIGATION_NOT_POSSIBLE", _safe(str(exc))) from None
            except FraudAIError as exc:
                raise ApiError(503, "LLM_UNAVAILABLE", _safe(str(exc))) from None
            if not result.ok or result.investigation is None:
                session.rollback()
                kind = result.failure.value if result.failure else "unknown"
                raise ApiError(
                    502,
                    "INVESTIGATION_FAILED",
                    "the explanation failed validation and was not stored",
                    extra={"failure": kind},
                )
            inv = result.investigation
            return InvestigationView(
                assessment_id=assessment_id,
                investigation_id=inv.investigation_id,
                explanation_version=inv.explanation_version,
                runtime=inv.llm_runtime,
                model=inv.llm_model,
                explanation=inv.explanation_text,
            )

    try:
        view = await _run_with_timeout(c.llm_pool, work, c.settings.local_llm_timeout + 10.0)
    except TimeoutError:
        c.metrics.investigations.labels("timeout").inc()
        raise ApiError(504, "LLM_TIMEOUT", "the investigation did not finish in time") from None
    except ApiError as exc:
        c.metrics.investigations.labels(exc.code.lower()).inc()
        raise
    c.metrics.investigations.labels("stored").inc()
    return view


# ------------------------------------------------------------------ reviews
@router.get("/reviews", response_model=ReviewList, responses=_ERRORS)
def list_reviews(
    request: Request,
    caller: Annotated[Caller, Depends(require("review:read"))],
    status: Annotated[str, Query(pattern=r"^(open|resolved|needs_more_information|all)$")] = "open",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ReviewList:
    c = container_of(request)
    wanted = None if status == "all" else ReviewStatus(status)
    with c.factory() as session:
        items = review_ops.list_reviews(session, status=wanted, limit=limit)
        return ReviewList(items=[_review_view(i) for i in items])


def _review_detail(session: Session, review_id: uuid.UUID) -> ReviewDetailView:
    try:
        detail = review_ops.get_review(session, review_id)
    except review_ops.ReviewError:
        raise ApiError(404, "NOT_FOUND", "unknown review item") from None
    return ReviewDetailView(
        review=_review_view(detail.item),
        assessment=assessment_view(session, detail.assessment),
        outcomes=[_outcome_view(o) for o in detail.outcomes],
    )


@router.get("/reviews/{review_id}", response_model=ReviewDetailView, responses=_ERRORS)
def get_review(
    review_id: uuid.UUID,
    request: Request,
    caller: Annotated[Caller, Depends(require("review:read"))],
) -> ReviewDetailView:
    c = container_of(request)
    with c.factory() as session:
        return _review_detail(session, review_id)


@router.post(
    "/reviews/{review_id}/resolve",
    response_model=ReviewDetailView,
    responses={**_ERRORS, 409: {"description": "already resolved"}},
)
def resolve_review(
    review_id: uuid.UUID,
    body: ResolveRequest,
    request: Request,
    caller: Annotated[Caller, Depends(require("review:write"))],
    operator_assertion: Annotated[
        str | None, Header(alias="X-Fraud-Operator-Assertion", max_length=4096)
    ] = None,
) -> ReviewDetailView:
    c = container_of(request)
    with write_scope(c.factory) as session:
        reviewer = _reviewer(c, session, review_id, body, caller, operator_assertion)
        try:
            review_ops.resolve(
                session,
                review_id,
                body.resolution,
                note=body.note,
                now=c.clock(),
                reviewer=reviewer,
            )
            audit.record(
                session,
                "review.resolved",
                actor=reviewer,
                target_type="review",
                target_id=str(review_id),
                details={
                    "resolution": body.resolution.value,
                    "via": "api",
                    "calling_key_id": caller.key_id,
                    "authenticated": reviewer.startswith("operator:"),
                },
            )
        except review_ops.ReviewError as exc:
            message = str(exc)
            if message.startswith("no review item"):
                raise ApiError(404, "NOT_FOUND", "unknown review item") from None
            if "already resolved" in message:
                raise ApiError(409, "ALREADY_RESOLVED", "the review is already resolved") from None
            raise ApiError(422, "INVALID_NOTE", _safe(message)) from None
        return _review_detail(session, review_id)


def _reviewer(
    c: ServiceContainer,
    session: Session,
    review_id: uuid.UUID,
    body: ResolveRequest,
    caller: Caller,
    token: str | None,
) -> str:
    """Stage 12: the authenticated reviewer (role ``reviewer``) from the operator's own
    signed assertion, bound to this review and resolution. Required when operator
    authentication is on; the API key alone then only identifies the calling tool."""
    from fraud_ai.trust.operators import OperatorAuthError, authenticate, record_failure

    required = c.settings.operator_auth_is_required
    if token is None:
        if required:
            raise ApiError(
                401,
                "OPERATOR_AUTH_REQUIRED",
                "resolving a review needs the reviewer's X-Fraud-Operator-Assertion",
            )
        return audit.api_actor(caller.key_id)
    if c.operator_registry is None:
        raise ApiError(401, "OPERATOR_AUTH_UNAVAILABLE", "operator authentication is not set up")
    try:
        verified = authenticate(
            session,
            c.settings,
            token,
            action="review.resolve",
            target=str(review_id),
            binding={"resolution": body.resolution.value},
            registry=c.operator_registry,
            now=c.clock(),
        )
    except OperatorAuthError as exc:
        session.rollback()
        record_failure(
            c.factory, action="review.resolve", target=str(review_id), error=exc, via="api"
        )
        status = 403 if exc.code == "FORBIDDEN" else 401
        raise ApiError(
            status, "OPERATOR_AUTH_FAILED", f"operator authentication failed ({exc.code})"
        ) from None
    return verified.actor


# ------------------------------------------------------------------ policy
@router.get("/policy", response_model=PolicyView, responses=_ERRORS)
def get_policy(
    request: Request, caller: Annotated[Caller, Depends(require("policy:read"))]
) -> PolicyView:
    c = container_of(request)
    with c.factory() as session:
        try:
            deployment = active_deployment(session)
        except FraudAIError:
            deployment = None
        if deployment is None:
            raise ApiError(503, "POLICY_UNAVAILABLE", "no verified active policy deployment")
        p = deployment.policy
        return PolicyView(
            policy_version=p.policy_version,
            rules_version=p.rules_version,
            primary_model=p.primary.ref,
            decision_event_kinds=list(p.decision_event_kinds),
            activated_at=ensure_utc(deployment.deployment.activated_at),
            followup_policy_version=FOLLOWUP_POLICY_VERSION,
        )


# ------------------------------------------------------------------ step-up: WebAuthn
def _own_challenge(
    session: Session, challenge_id: uuid.UUID, caller: Caller
) -> AuthenticationChallenge:
    row = session.get(AuthenticationChallenge, challenge_id)
    if row is None or row.api_key_id != caller.key_id:
        raise ApiError(409, "CHALLENGE_INVALID", "unknown, used or replayed challenge")
    return row


def _step_result(
    c: ServiceContainer,
    session: Session,
    assessment_id: uuid.UUID,
    completion: webauthn_ops.StepUpCompletion,
) -> StepUpResult:
    c.metrics.stepup.labels("webauthn", completion.result.value).inc()
    used = attempts_used(session, assessment_id)
    remaining = 0 if completion.followup else max(0, c.webauthn.max_attempts - used)
    return StepUpResult(
        assessment_id=assessment_id,
        method=AuthenticationMethod.WEBAUTHN.value,
        result=completion.result.value,
        attempt_number=completion.attempt.attempt_number,
        failure_reason=completion.failure_reason,
        attempts_remaining=remaining,
        followup=_summary(session, completion.followup),
    )


@router.post(
    "/step-up/{assessment_id}/webauthn/challenge",
    response_model=ChallengeResponse,
    responses={**_ERRORS, 409: {"description": "step-up not possible"}},
)
def webauthn_challenge(
    assessment_id: uuid.UUID,
    body: WebAuthnChallengeRequest,
    request: Request,
    caller: Annotated[Caller, Depends(require("stepup:write"))],
) -> ChallengeResponse:
    c = container_of(request)
    with write_scope(c.factory) as session:
        row = session.get(RiskAssessment, assessment_id)
        record = session.get(EventRecord, row.event_id) if row is not None else None
        if record is not None and record.session_id and record.session_id != body.session_id:
            raise ApiError(409, "SESSION_MISMATCH", "session_id does not match the assessed event")
        try:
            challenge, options = webauthn_ops.start_authentication(
                session,
                c.webauthn,
                assessment_id,
                session_id=body.session_id,
                now=c.clock(),
                api_key_id=caller.key_id,
            )
        except StepUpError as exc:
            raise _stepup_error(exc) from None
        return ChallengeResponse(
            challenge_id=challenge.challenge_id,
            expires_at=ensure_utc(challenge.expires_at),
            public_key=options,
        )


@router.post("/step-up/webauthn/verify", response_model=StepUpResult, responses=_ERRORS)
def webauthn_verify(
    body: WebAuthnVerifyRequest,
    request: Request,
    caller: Annotated[Caller, Depends(require("stepup:write"))],
) -> StepUpResult:
    c = container_of(request)
    with write_scope(c.factory) as session:
        challenge = _own_challenge(session, body.challenge_id, caller)
        assessment_id = challenge.assessment_id
        if assessment_id is None:
            raise ApiError(409, "CHALLENGE_INVALID", "not a step-up challenge")
        try:
            completion = webauthn_ops.finish_authentication(
                session,
                c.webauthn,
                body.challenge_id,
                body.credential,
                session_id=body.session_id,
                now=c.clock(),
            )
        except StepUpError as exc:
            session.commit()  # a consumed challenge stays consumed, even on failure
            raise _stepup_error(exc) from None
        return _step_result(c, session, assessment_id, completion)


@router.post("/step-up/webauthn/cancel", response_model=StepUpResult, responses=_ERRORS)
def webauthn_cancel(
    body: WebAuthnCancelRequest,
    request: Request,
    caller: Annotated[Caller, Depends(require("stepup:write"))],
) -> StepUpResult:
    c = container_of(request)
    with write_scope(c.factory) as session:
        challenge = _own_challenge(session, body.challenge_id, caller)
        assessment_id = challenge.assessment_id
        if assessment_id is None:
            raise ApiError(409, "CHALLENGE_INVALID", "not a step-up challenge")
        try:
            completion = webauthn_ops.cancel_authentication(
                session, c.webauthn, body.challenge_id, now=c.clock()
            )
        except StepUpError as exc:
            session.commit()  # a consumed challenge stays consumed, even on failure
            raise _stepup_error(exc) from None
        return _step_result(c, session, assessment_id, completion)


# ------------------------------------------------------------------ step-up: payment auth
def _payment_provider(c: ServiceContainer) -> payment_ops.PaymentAuthenticationProvider:
    if c.payment is None:
        raise ApiError(
            503,
            "PAYMENT_AUTH_NOT_CONFIGURED",
            "no payment-authentication provider is configured; use another step-up method",
        )
    return c.payment


@router.post(
    "/step-up/{assessment_id}/payment",
    response_model=PaymentAuthView,
    responses={**_ERRORS, 503: {"description": "no provider configured"}},
)
def payment_step_up(
    assessment_id: uuid.UUID,
    body: PaymentAuthRequestBody,
    request: Request,
    caller: Annotated[Caller, Depends(require("stepup:write"))],
) -> PaymentAuthView:
    c = container_of(request)
    provider = _payment_provider(c)
    with write_scope(c.factory) as session:
        try:
            outcome = payment_ops.request_payment_authentication(
                session,
                provider,
                c.pseudonymiser,
                assessment_id,
                body.token_reference,
                timeout=c.settings.payment_auth_timeout,
                max_attempts=c.settings.step_up_max_attempts,
                amount_minor=body.amount_minor,
                currency=body.currency,
            )
        except StepUpError as exc:
            raise _stepup_error(exc) from None
        if outcome.result is not None:
            c.metrics.stepup.labels("payment_authentication", outcome.result.value).inc()
        return PaymentAuthView(
            assessment_id=assessment_id,
            request_id=outcome.request.request_id if outcome.request else None,
            provider=provider.name,
            status=outcome.status.value,
            next_action=outcome.next_action,
            result=outcome.result.value if outcome.result else None,
            followup=_summary(session, outcome.followup),
        )


@router.get("/step-up/payment/{request_id}", response_model=PaymentStatusView, responses=_ERRORS)
def payment_step_up_status(
    request_id: uuid.UUID,
    request: Request,
    caller: Annotated[Caller, Depends(require("stepup:write"))],
) -> PaymentStatusView:
    c = container_of(request)
    provider = _payment_provider(c)
    with c.factory() as session:
        try:
            status = payment_ops.payment_status(
                session, provider, request_id, timeout=c.settings.payment_auth_timeout
            )
        except StepUpError as exc:
            raise _stepup_error(exc) from None
        return PaymentStatusView(request_id=request_id, status=status.value)


@router.post(
    "/callbacks/payment/{provider_name}",
    response_model=CallbackAck,
    responses={401: {"description": "bad signature"}, 409: {"description": "duplicate"}},
    summary="Signed provider callback (authenticated by the provider signature, not a key)",
)
async def payment_callback(provider_name: str, request: Request) -> CallbackAck:
    c = container_of(request)
    if c.payment is None or provider_name != c.payment.name:
        raise ApiError(404, "NOT_FOUND", "no such provider")
    try:
        decision = c.limiter.hit(f"callback|{provider_name}")
    except StateUnavailableError:
        raise ApiError(
            503, "STATE_UNAVAILABLE", "rate limiter unavailable", headers={"Retry-After": "1"}
        ) from None
    if not decision.allowed:
        raise ApiError(
            429, "RATE_LIMITED", "rate limited", headers={"Retry-After": str(decision.retry_after)}
        )
    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    provider = c.payment

    def work() -> CallbackAck:
        with write_scope(c.factory) as session:
            try:
                outcome = payment_ops.handle_callback(
                    session,
                    provider,
                    headers,
                    body,
                    now=c.clock(),
                    max_age=c.settings.signature_max_age,
                    max_attempts=c.settings.step_up_max_attempts,
                )
            except SignatureError as exc:
                c.metrics.auth_failures.labels(f"callback_{exc.code.lower()}").inc()
                raise ApiError(401, exc.code, str(exc)) from None
            except StepUpError as exc:
                raise _stepup_error(exc) from None
            except payment_ops.CallbackIgnoredError:
                return CallbackAck(accepted=False, status="ignored", result=None)
            if outcome.result is not None:
                c.metrics.stepup.labels("payment_authentication", outcome.result.value).inc()
            return CallbackAck(
                accepted=True,
                status=outcome.status.value,
                result=outcome.result.value if outcome.result else None,
            )

    return await run_in_threadpool(work)


# ------------------------------------------------------------------ passkey registration
@router.post(
    "/webauthn/registrations/challenge", response_model=ChallengeResponse, responses=_ERRORS
)
def registration_challenge(
    body: RegistrationChallengeRequest,
    request: Request,
    caller: Annotated[Caller, Depends(require("webauthn:write"))],
) -> ChallengeResponse:
    c = container_of(request)
    with write_scope(c.factory) as session:
        try:
            challenge, options = webauthn_ops.start_registration(
                session, c.webauthn, body.user_id, now=c.clock(), api_key_id=caller.key_id
            )
        except StepUpError as exc:
            raise _stepup_error(exc) from None
        return ChallengeResponse(
            challenge_id=challenge.challenge_id,
            expires_at=ensure_utc(challenge.expires_at),
            public_key=options,
        )


@router.post(
    "/webauthn/registrations", response_model=CredentialView, status_code=201, responses=_ERRORS
)
def registration_finish(
    body: RegistrationRequest,
    request: Request,
    caller: Annotated[Caller, Depends(require("webauthn:write"))],
) -> CredentialView:
    c = container_of(request)
    with write_scope(c.factory) as session:
        _own_challenge(session, body.challenge_id, caller)
        try:
            row = webauthn_ops.finish_registration(
                session, c.webauthn, body.challenge_id, body.credential, now=c.clock()
            )
        except StepUpError as exc:
            session.commit()  # a consumed challenge stays consumed, even on failure
            raise _stepup_error(exc) from None
        return CredentialView(
            credential_ref=row.credential_id,
            status=row.status.value,
            created_at=ensure_utc(row.created_at),
        )


# ------------------------------------------------------------------ operations
@router.get("/health", response_model=HealthView, summary="Liveness (process only)")
def health() -> HealthView:
    return HealthView(status="ok")


@router.get(
    "/ready",
    response_model=ReadyView,
    responses={503: {"description": "not ready"}},
    summary="Readiness (database, migrations, policy, primary model; never the LLM)",
)
def ready(request: Request) -> JSONResponse:
    checks = readiness(container_of(request))
    ok = is_ready(checks)
    view = ReadyView(status="ready" if ok else "not_ready", checks=checks)
    return JSONResponse(view.model_dump(mode="json"), status_code=200 if ok else 503)


@router.get("/metrics", response_class=Response, responses=_ERRORS)
def metrics(
    request: Request, caller: Annotated[Caller, Depends(require("metrics:read"))]
) -> Response:
    c = container_of(request)
    stats = c.scoring.cache.stats
    c.metrics.model_loads.set(stats.loads)
    c.metrics.model_load_failures.set(stats.load_failures)
    pool = c.engine.pool
    checked_out = getattr(pool, "checkedout", None)
    if callable(checked_out):
        c.metrics.db_pool_checked_out.set(checked_out())
    try:
        with c.factory() as session:
            for status, count in review_ops.queue_size(session).items():
                c.metrics.review_queue.labels(status).set(count)
    except Exception as exc:  # metrics must render even when the database is down
        log.warning("metrics: review queue unavailable (%s)", type(exc).__name__)
    return Response(c.metrics.render(), media_type=CONTENT_TYPE)


__all__ = ["API_VERSION", "router", "score_payload"]
