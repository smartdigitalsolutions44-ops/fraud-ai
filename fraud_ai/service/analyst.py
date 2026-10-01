"""Read-only analyst views (``/v1/analyst``, Stage 13): what the Sentinel console shows.

These endpoints **read** existing records. They never score, decide, resolve, activate or
change anything. They exist because an analyst console needs a few joined, safe views that
the transaction-oriented API does not offer:

* ``GET /v1/analyst/feed``: recent live assessments (the "live risk feed");
* ``GET /v1/analyst/reviews``: the review queue joined with each case's decision and
  step-up status;
* ``GET /v1/analyst/cases/{assessment_id}``: one case's evidence. It covers the stored
  model scores (primary and shadow), rule results with their own evidence, curated
  point-in-time indicators, the event timeline, step-up attempts, case activity and the
  latest stored investigation;
* ``GET /v1/analyst/summary``: decision distribution, backlog, step-ups, fallbacks,
  latency percentiles and shadow agreement, computed from stored assessments;
* ``GET /v1/analyst/system``: models, signatures, policy, migrations, the audit chain,
  anchors, the LLM runtime and security settings;
* ``GET /v1/analyst/search``: resolve a case, assessment or event id, or an id prefix.

All require the ``analyst:read`` scope. Model scores and rule evidence are **internal model
data**: exposing them to analysts is a deliberate product decision (ANALYST_WORKFLOW.md).
Nothing here returns names, contact details, card data, raw IPs, keyed hashes, API keys,
signing material or merchant customer references. Identifiers are internal UUIDs.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from fraud_ai import audit
from fraud_ai.core.enums import ReviewStatus
from fraud_ai.database import migrations as mig
from fraud_ai.database.models import (
    AuditEvent,
    AuthenticationAttempt,
    EventRecord,
    FeatureSnapshot,
    Investigation,
    LoginEvent,
    ModelArtifactSignature,
    NetworkEvent,
    PaymentAuthRequest,
    PolicyDeployment,
    ReviewItem,
    ReviewOutcome,
    RiskAssessment,
    SecurityEvent,
    Transaction,
    UserDevice,
)
from fraud_ai.risk.registry import active_deployment
from fraud_ai.service.dependencies import Caller, container_of, require
from fraud_ai.service.errors import ApiError
from fraud_ai.service.schemas import API_VERSION
from fraud_ai.stepup.outcomes import authentication_status
from fraud_ai.utils.time import ensure_utc

router = APIRouter(prefix="/v1/analyst", tags=["analyst"])
SCOPE = "analyst:read"
LIVE_MODES = ("live", "step_up_followup")
TIMELINE_BEFORE = 40
TIMELINE_AFTER = 10
TIMELINE_AFTER_WINDOW = timedelta(hours=24)
CHAIN_VERIFY_LIMIT = 50_000
SUMMARY_LATENCY_ROWS = 5_000

# Indicators shown in the case workspace: a curated allow-list of point-in-time features.
# (feature name, group, label). Only these leave the service; a new feature is not exposed
# until someone adds it here.
INDICATORS: tuple[tuple[str, str, str], ...] = (
    ("new_device", "device", "Device not seen on this account before"),
    ("device_seen_before", "device", "Device seen on this account before"),
    ("device_trusted", "device", "Device marked trusted"),
    ("device_age_days", "device", "Device age on this account (days)"),
    ("devices_per_account", "device", "Devices on this account"),
    ("distinct_devices_last_1h", "device", "Distinct devices, last hour"),
    ("device_changed_recently", "device", "Device changed recently"),
    ("shared_device_flag", "device", "Device shared with other accounts"),
    ("network_seen_before", "network", "Network seen on this account before"),
    ("network_type", "network", "Network type"),
    ("network_type_changed", "network", "Network type changed"),
    ("asn_changed", "network", "Network provider (ASN) changed"),
    ("country_changed", "network", "Country changed"),
    ("country_changed_recently", "network", "Country changed recently"),
    ("distinct_networks_last_1h", "network", "Distinct networks, last hour"),
    ("networks_per_account", "network", "Networks on this account"),
    ("vpn_detected", "network", "VPN signal"),
    ("proxy_detected", "network", "Proxy signal"),
    ("tor_detected", "network", "Tor signal"),
    ("datacenter_detected", "network", "Datacenter network signal"),
    ("shared_network_flag", "network", "Network shared with other accounts"),
    ("account_age_days", "behaviour", "Account age (days)"),
    ("address_age_days", "behaviour", "Address age (days)"),
    ("new_address", "behaviour", "New address"),
    ("address_changed_recently", "behaviour", "Address changed recently"),
    ("new_payment_method", "behaviour", "New payment method"),
    ("payment_method_age_days", "behaviour", "Payment method age (days)"),
    ("transactions_last_1h", "behaviour", "Transactions, last hour"),
    ("transactions_last_24h", "behaviour", "Transactions, last 24 hours"),
    ("transaction_value_last_24h", "behaviour", "Transaction value, last 24 hours (minor units)"),
    ("transaction_vs_median_ratio", "behaviour", "Amount vs the customer's median"),
    ("transaction_vs_average_ratio", "behaviour", "Amount vs the customer's average"),
    ("unusually_high_transaction", "behaviour", "Unusually high amount for this customer"),
    ("time_since_previous_transaction_minutes", "behaviour", "Minutes since previous purchase"),
    ("failed_logins_last_15m", "behaviour", "Failed logins, last 15 minutes"),
    ("failed_logins_last_1h", "behaviour", "Failed logins, last hour"),
    ("failed_logins_total", "behaviour", "Failed logins, total"),
    ("recent_password_reset", "behaviour", "Recent password reset"),
    ("recent_mfa_removed", "behaviour", "MFA recently removed"),
    ("rapid_multi_change_count", "behaviour", "Account changes, last 24 hours"),
    ("historical_chargebacks", "behaviour", "Historical chargebacks"),
)

# Engine-level reason codes (rule reason codes are described by the rule set itself).
ENGINE_REASONS: dict[str, str] = {
    "SCORE_BAND_VERY_LOW": "The calibrated primary-model score fell in the policy's very low band.",
    "SCORE_BAND_LOW": "The calibrated primary-model score fell in the policy's low band.",
    "SCORE_BAND_MODERATE": "The calibrated primary-model score fell in the policy's moderate band.",
    "SCORE_BAND_ELEVATED": "The calibrated primary-model score fell in the policy's elevated band.",
    "SCORE_BAND_HIGH": "The calibrated primary-model score fell in the policy's high band.",
    "SCORE_BAND_EXTREME": "The calibrated primary-model score fell in the policy's extreme band.",
    "SECONDARY_MODEL_ELEVATED": "The secondary model flagged the event, raising the decision.",
    "SEQUENCE_MODEL_ELEVATED": "The sequence model flagged the event, raising the decision.",
    "ANOMALY_SIGNAL": "The anomaly model flagged unusual behaviour, raising the decision.",
    "LATE_EVENT": "The event arrived late; the policy's late-event minimum applied.",
    "BLOCK_NOT_CORROBORATED": (
        "A block was not corroborated by a rule or a second model, so the policy sent the "
        "case to review instead."
    ),
    "STEP_UP_SUCCESS": "Step-up authentication succeeded (evidence, not proof of legitimacy).",
    "STEP_UP_FAILED": "Step-up authentication failed.",
    "STEP_UP_EXPIRED": "The step-up challenge expired before it was answered.",
    "STEP_UP_CANCELLED": "The step-up was cancelled.",
    "STEP_UP_UNAVAILABLE": "The authentication provider was unavailable (never an allow).",
    "ATTEMPTS_EXHAUSTED": "All step-up attempts were used; the case went to manual review.",
}
FALLBACK_PREFIX = "FALLBACK_"


class _View(BaseModel):
    model_config = ConfigDict(frozen=True)


class FeedItem(_View):
    assessment_id: uuid.UUID
    event_id: uuid.UUID
    event_type: str | None
    assessment_version: int
    mode: str
    assessed_at: datetime
    event_time: datetime | None
    decision: str
    risk_level: str
    reason_codes: list[str]
    policy_version: str
    model_version: str | None
    fallback_used: bool
    latency_ms: float | None
    review: dict[str, Any] | None
    authentication: dict[str, Any]


class FeedView(_View):
    api_version: str = API_VERSION
    generated_at: datetime
    items: list[FeedItem]


class QueueItem(_View):
    review_id: uuid.UUID
    assessment_id: uuid.UUID
    event_id: uuid.UUID
    priority: int
    status: str
    outcome: str | None
    reason_codes: list[str]
    created_at: datetime
    reviewed_at: datetime | None
    event_type: str | None
    decision: str
    risk_level: str
    policy_version: str
    model_version: str | None
    fallback_used: bool
    authentication: dict[str, Any]


class QueueView(_View):
    api_version: str = API_VERSION
    generated_at: datetime
    items: list[QueueItem]


class CaseView(_View):
    api_version: str = API_VERSION
    generated_at: datetime
    assessment: dict[str, Any]
    versions: list[dict[str, Any]]
    review: dict[str, Any] | None
    reasons: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    models: dict[str, Any]
    indicators: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    step_up: dict[str, Any]
    activity: list[dict[str, Any]]
    investigation: dict[str, Any] | None
    latency_ms: dict[str, Any]


class SummaryView(_View):
    api_version: str = API_VERSION
    generated_at: datetime
    window_hours: int | None
    assessments: dict[str, Any]
    reviews: dict[str, Any]
    step_up: dict[str, Any]
    latency_ms: dict[str, Any]
    shadow: dict[str, Any]
    series: list[dict[str, Any]]


class SystemView(_View):
    api_version: str = API_VERSION
    generated_at: datetime
    environment: str
    checks_ms: float
    policy: dict[str, Any] | None
    models: list[dict[str, Any]]
    migrations: dict[str, Any]
    security: dict[str, Any]
    audit: dict[str, Any]
    llm: dict[str, Any]
    reason_catalogue: dict[str, str]


class SearchView(_View):
    api_version: str = API_VERSION
    query: str
    matches: list[dict[str, Any]]


# ------------------------------------------------------------------ helpers
def _iso(value: datetime | None) -> str | None:
    return ensure_utc(value).isoformat() if value else None


def _enum(value: Any) -> Any:
    return getattr(value, "value", value)


def _review_status(item: ReviewItem | None) -> dict[str, Any] | None:
    if item is None:
        return None
    return {
        "review_id": str(item.review_id),
        "status": item.status.value,
        "priority": item.priority,
        "outcome": item.outcome.value if item.outcome else None,
    }


def _reviews_by_assessment(session: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, ReviewItem]:
    if not ids:
        return {}
    rows = session.scalars(select(ReviewItem).where(ReviewItem.assessment_id.in_(ids)))
    return {r.assessment_id: r for r in rows}


def _event_types(session: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    rows = session.execute(
        select(EventRecord.event_id, EventRecord.event_type).where(EventRecord.event_id.in_(ids))
    )
    return {eid: _enum(kind) for eid, kind in rows}


def _total_latency(row: RiskAssessment) -> float | None:
    total = (row.latency_ms or {}).get("total")
    return float(total) if isinstance(total, int | float) else None


def reason_catalogue() -> dict[str, str]:
    from fraud_ai.rules.ruleset import get_rule_set

    catalogue = dict(ENGINE_REASONS)
    for rule in get_rule_set().rules:
        catalogue[rule.reason_code] = rule.description
    return catalogue


def describe_reason(code: str, catalogue: dict[str, str]) -> str | None:
    if code in catalogue:
        return catalogue[code]
    if code.startswith(FALLBACK_PREFIX):
        failure = code[len(FALLBACK_PREFIX) :].lower().replace("_", " ")
        return f"A component failed ({failure}); the policy's conservative fallback applied."
    return None


# ------------------------------------------------------------------ feed and queue
@router.get("/feed", response_model=FeedView)
def feed(
    request: Request,
    caller: Annotated[Caller, Depends(require(SCOPE))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    since: Annotated[datetime | None, Query()] = None,
    decision: Annotated[str | None, Query(pattern=r"^[A-Z_]{3,40}$")] = None,
) -> FeedView:
    c = container_of(request)
    with c.factory() as session:
        stmt = select(RiskAssessment).where(RiskAssessment.mode.in_(LIVE_MODES))
        if since is not None:
            stmt = stmt.where(RiskAssessment.assessed_at > since)
        if decision is not None:
            stmt = stmt.where(RiskAssessment.decision == decision)
        rows = list(
            session.scalars(
                stmt.order_by(
                    RiskAssessment.assessed_at.desc(), RiskAssessment.assessment_id
                ).limit(limit)
            )
        )
        reviews = _reviews_by_assessment(session, [r.assessment_id for r in rows])
        kinds = _event_types(session, [r.event_id for r in rows])
        items = [
            FeedItem(
                assessment_id=r.assessment_id,
                event_id=r.event_id,
                event_type=kinds.get(r.event_id),
                assessment_version=r.assessment_version,
                mode=r.mode,
                assessed_at=ensure_utc(r.assessed_at),
                event_time=ensure_utc(r.event_time) if r.event_time else None,
                decision=r.decision.value,
                risk_level=r.risk_level,
                reason_codes=[str(x) for x in r.reason_codes],
                policy_version=r.policy_version,
                model_version=r.primary_model,
                fallback_used=r.fallback_used,
                latency_ms=_total_latency(r),
                review=_review_status(reviews.get(r.assessment_id)),
                authentication=authentication_status(session, r.assessment_id),
            )
            for r in rows
        ]
    return FeedView(generated_at=c.clock(), items=items)


@router.get("/reviews", response_model=QueueView)
def queue(
    request: Request,
    caller: Annotated[Caller, Depends(require(SCOPE))],
    status: Annotated[str, Query(pattern=r"^(open|resolved|needs_more_information|all)$")] = "open",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> QueueView:
    c = container_of(request)
    with c.factory() as session:
        stmt = select(ReviewItem, RiskAssessment).join(
            RiskAssessment, RiskAssessment.assessment_id == ReviewItem.assessment_id
        )
        if status != "all":
            stmt = stmt.where(ReviewItem.status == ReviewStatus(status))
        rows = list(
            session.execute(
                stmt.order_by(
                    ReviewItem.priority, ReviewItem.created_at, ReviewItem.review_id
                ).limit(limit)
            )
        )
        kinds = _event_types(session, [item.event_id for item, _ in rows])
        items = [
            QueueItem(
                review_id=item.review_id,
                assessment_id=item.assessment_id,
                event_id=item.event_id,
                priority=item.priority,
                status=item.status.value,
                outcome=item.outcome.value if item.outcome else None,
                reason_codes=[str(x) for x in item.reason_codes],
                created_at=ensure_utc(item.created_at),
                reviewed_at=ensure_utc(item.reviewed_at) if item.reviewed_at else None,
                event_type=kinds.get(item.event_id),
                decision=row.decision.value,
                risk_level=row.risk_level,
                policy_version=row.policy_version,
                model_version=row.primary_model,
                fallback_used=row.fallback_used,
                authentication=authentication_status(session, row.assessment_id),
            )
            for item, row in rows
        ]
    return QueueView(generated_at=c.clock(), items=items)


# ------------------------------------------------------------------ case
def _models(row: RiskAssessment, original: RiskAssessment) -> dict[str, Any]:
    """Stored scores only. Flagged means the raw score reached that model's own threshold;
    no consensus score is computed."""
    entries: list[dict[str, Any]] = []
    for role, data in (row.model_scores or {}).items():
        if not isinstance(data, dict):
            continue
        raw, threshold = data.get("raw"), data.get("threshold")
        flagged = (
            bool(raw >= threshold)
            if isinstance(raw, int | float) and isinstance(threshold, int | float)
            else None
        )
        entries.append(
            {
                "role": str(role),
                "status": "primary" if role == "primary" else "active",
                "model": data.get("model"),
                "raw_score": raw,
                "calibrated_score": data.get("calibrated"),
                "threshold": threshold,
                "flagged": flagged,
            }
        )
    # Shadow models are recorded on the original assessment (follow-ups copy no shadow).
    for data in (original.shadow or {}).get("models", []) or []:
        if not isinstance(data, dict):
            continue
        entries.append(
            {
                "role": "shadow",
                "status": "shadow",
                "model": data.get("model"),
                "raw_score": data.get("raw"),
                "calibrated_score": None,
                "threshold": data.get("threshold"),
                "flagged": data.get("flagged"),
                "agrees_with_active": data.get("agrees"),
            }
        )
    rated = [e for e in entries if e["flagged"] is not None]
    policies = [
        {
            "policy_version": p.get("policy_version"),
            "decision": p.get("decision"),
            "risk_level": p.get("risk_level"),
            "agrees": p.get("agrees"),
        }
        for p in (original.shadow or {}).get("policies", []) or []
        if isinstance(p, dict)
    ]
    return {
        "entries": entries,
        "flagged": sum(1 for e in rated if e["flagged"]),
        "rated": len(rated),
        "disagreement": len({bool(e["flagged"]) for e in rated}) > 1,
        "shadow_policies": policies,
        "note": "Model scores are model outputs, not certainty of fraud. Shadow models and "
        "policies are recorded but never decide.",
    }


def _indicators(session: Session, event_id: uuid.UUID) -> list[dict[str, Any]]:
    snapshot = session.scalar(
        select(FeatureSnapshot)
        .where(FeatureSnapshot.event_id == event_id)
        .order_by(FeatureSnapshot.generated_at.desc())
        .limit(1)
    )
    if snapshot is None:
        return []
    values = (snapshot.features or {}).get("values", {}) or {}
    missing = (snapshot.features or {}).get("missing", {}) or {}
    out = []
    for name, group, label in INDICATORS:
        if name not in values and name not in missing:
            continue
        value = values.get(name)
        if isinstance(value, float):
            value = round(value, 4)
        out.append(
            {
                "name": name,
                "group": group,
                "label": label,
                "value": value,
                "missing": missing.get(name),
                "as_of": _iso(snapshot.as_of_timestamp),
                "feature_version": snapshot.feature_version,
            }
        )
    return out


def _timeline(session: Session, event: EventRecord, assessed_at: datetime) -> list[dict[str, Any]]:
    """The customer's recent events around the case (point-in-time: events after the
    decision are marked ``after_decision``). Safe attributes only."""
    if event.user_id is None:
        rows = [event]
    else:
        before = list(
            session.scalars(
                select(EventRecord)
                .where(
                    EventRecord.user_id == event.user_id,
                    EventRecord.occurred_at <= event.occurred_at,
                )
                .order_by(EventRecord.occurred_at.desc(), EventRecord.event_id)
                .limit(TIMELINE_BEFORE)
            )
        )
        after = list(
            session.scalars(
                select(EventRecord)
                .where(
                    EventRecord.user_id == event.user_id,
                    EventRecord.occurred_at > event.occurred_at,
                    EventRecord.occurred_at <= event.occurred_at + TIMELINE_AFTER_WINDOW,
                )
                .order_by(EventRecord.occurred_at, EventRecord.event_id)
                .limit(TIMELINE_AFTER)
            )
        )
        rows = list(reversed(before)) + after
    ids = [r.event_id for r in rows]
    logins = {
        x.event_id: x
        for x in session.scalars(select(LoginEvent).where(LoginEvent.event_id.in_(ids)))
    }
    txns = {
        x.event_id: x
        for x in session.scalars(select(Transaction).where(Transaction.event_id.in_(ids)))
    }
    nets = {
        x.event_id: x
        for x in session.scalars(select(NetworkEvent).where(NetworkEvent.event_id.in_(ids)))
    }
    secs = {
        x.event_id: x
        for x in session.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(ids)))
    }
    first_seen: dict[uuid.UUID, datetime] = {}
    if event.user_id is not None:
        for d in session.scalars(select(UserDevice).where(UserDevice.user_id == event.user_id)):
            first_seen[d.device_id] = ensure_utc(d.first_seen_at)
    out: list[dict[str, Any]] = []
    for r in rows:
        item: dict[str, Any] = {
            "event_id": str(r.event_id),
            "event_type": _enum(r.event_type),
            "occurred_at": _iso(r.occurred_at),
            "is_case_event": r.event_id == event.event_id,
            "after_decision": ensure_utc(r.occurred_at) > ensure_utc(event.occurred_at),
            "source": _enum(r.source),
        }
        if r.device_id is not None and r.device_id in first_seen:
            item["new_device"] = (
                abs((first_seen[r.device_id] - ensure_utc(r.occurred_at)).total_seconds()) < 1.0
            )
        if (login := logins.get(r.event_id)) is not None:
            item["login"] = {
                "outcome": _enum(login.outcome),
                "auth_method": _enum(login.auth_method),
                "mfa_used": login.mfa_used,
            }
        if (txn := txns.get(r.event_id)) is not None:
            item["transaction"] = {
                "amount_minor": txn.amount_minor,
                "currency": txn.currency,
                "channel": _enum(txn.channel),
                "merchant_category": txn.merchant_category,
                "status": _enum(txn.status),
            }
        if (net := nets.get(r.event_id)) is not None:
            item["network"] = {
                "country": net.country,
                "network_type": _enum(net.network_type),
                "vpn": net.is_known_vpn,
                "proxy": net.is_known_proxy,
                "tor": net.is_tor,
                "datacenter": net.is_datacenter,
                "mobile": net.is_mobile_network,
            }
        if (sec := secs.get(r.event_id)) is not None:
            item["security_event"] = _enum(sec.security_event_type)
        out.append(item)
    return out


def _step_up(session: Session, assessment_ids: list[uuid.UUID]) -> dict[str, Any]:
    attempts = list(
        session.scalars(
            select(AuthenticationAttempt)
            .where(AuthenticationAttempt.assessment_id.in_(assessment_ids))
            .order_by(AuthenticationAttempt.created_at, AuthenticationAttempt.attempt_number)
        )
    )
    payments = list(
        session.scalars(
            select(PaymentAuthRequest)
            .where(PaymentAuthRequest.assessment_id.in_(assessment_ids))
            .order_by(PaymentAuthRequest.created_at)
        )
    )
    return {
        "attempts": [
            {
                "attempt_number": a.attempt_number,
                "method": a.method.value,
                "result": a.result.value,
                "failure_reason": a.failure_reason,
                "created_at": _iso(a.created_at),
                "followup_assessment_id": str(a.followup_assessment_id)
                if a.followup_assessment_id
                else None,
            }
            for a in attempts
        ],
        # Provider-safe status only: no provider reference, token or client secret.
        "payment_requests": [
            {
                "provider": p.provider,
                "status": p.status.value,
                "attempt_number": p.attempt_number,
                "created_at": _iso(p.created_at),
                "completed_at": _iso(p.completed_at),
            }
            for p in payments
        ],
    }


def _activity(
    session: Session,
    versions: list[RiskAssessment],
    review: ReviewItem | None,
    outcomes: list[ReviewOutcome],
    step_up: dict[str, Any],
    investigations: list[Investigation],
) -> list[dict[str, Any]]:
    """Case activity: stored records, plus hash-chained audit events that name the case.
    Each entry says where it comes from; audit details are not returned."""
    items: list[dict[str, Any]] = []
    for v in versions:
        items.append(
            {
                "at": _iso(v.assessed_at),
                "kind": "assessment.created",
                "source": "risk_assessments",
                "summary": f"Assessment v{v.assessment_version}: {v.decision.value}"
                + (" (step-up follow-up)" if v.mode == "step_up_followup" else ""),
            }
        )
    if review is not None:
        items.append(
            {
                "at": _iso(review.created_at),
                "kind": "review.created",
                "source": "review_queue",
                "summary": f"Review created (priority {review.priority})",
            }
        )
    for o in outcomes:
        items.append(
            {
                "at": _iso(o.created_at),
                "kind": "review.outcome",
                "source": "review_outcomes",
                "summary": f"Resolution: {o.resolution.value}"
                + (f" by {o.reviewer}" if o.reviewer else ""),
            }
        )
    for p in step_up["payment_requests"]:
        items.append(
            {
                "at": p["created_at"],
                "kind": "step_up.requested",
                "source": "payment_auth_requests",
                "summary": f"Payment authentication requested ({p['provider']})",
            }
        )
    for a in step_up["attempts"]:
        items.append(
            {
                "at": a["created_at"],
                "kind": "step_up.result",
                "source": "authentication_attempts",
                "summary": f"Authentication attempt {a['attempt_number']}: {a['result']}",
            }
        )
    for inv in investigations:
        items.append(
            {
                "at": _iso(inv.created_at),
                "kind": "investigation.generated",
                "source": "investigations",
                "summary": f"Analyst explanation v{inv.explanation_version} ({inv.llm_runtime})",
            }
        )
    targets = {str(v.assessment_id) for v in versions}
    if review is not None:
        targets.add(str(review.review_id))
    for row in session.scalars(
        select(AuditEvent)
        .where(AuditEvent.target_id.in_(targets))
        .order_by(AuditEvent.sequence)
        .limit(100)
    ):
        items.append(
            {
                "at": _iso(row.occurred_at),
                "kind": row.action,
                "source": "audit_log",
                "summary": f"{row.action} by {row.actor}",
                "sequence": row.sequence,
            }
        )
    return sorted(items, key=lambda x: x["at"] or "")


def _investigation(inv: Investigation | None) -> dict[str, Any] | None:
    if inv is None:
        return None
    explanation = inv.explanation_json or {}
    cited: set[str] = set()
    for value in explanation.values():
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if isinstance(entry, dict):
                cited.update(str(x) for x in entry.get("evidence_ids", []) or [])
    packet = inv.evidence_packet or {}
    evidence = [e for e in packet.get("evidence", []) or [] if str(e.get("id")) in cited]
    limitations = list(packet.get("limitations", []) or [])
    return {
        "investigation_id": str(inv.investigation_id),
        "explanation_version": inv.explanation_version,
        "created_at": _iso(inv.created_at),
        "runtime": inv.llm_runtime,
        "model": inv.llm_model,
        "explanation": explanation,
        "evidence": evidence,
        "limitations": limitations,
        "note": "Analyst assistance only: it never scores, decides or changes anything.",
    }


@router.get("/cases/{assessment_id}", response_model=CaseView)
def case(
    assessment_id: uuid.UUID,
    request: Request,
    caller: Annotated[Caller, Depends(require(SCOPE))],
) -> CaseView:
    from fraud_ai.service.routes import assessment_view

    c = container_of(request)
    catalogue = reason_catalogue()
    with c.factory() as session:
        row = session.get(RiskAssessment, assessment_id)
        if row is None:
            raise ApiError(404, "NOT_FOUND", "unknown assessment")
        event = session.get(EventRecord, row.event_id)
        if event is None:
            raise ApiError(404, "NOT_FOUND", "unknown event")
        versions = list(
            session.scalars(
                select(RiskAssessment)
                .where(RiskAssessment.event_id == row.event_id)
                .order_by(RiskAssessment.assessment_version)
            )
        )
        original = versions[0] if versions else row
        ids = [v.assessment_id for v in versions]
        review = session.scalar(
            select(ReviewItem)
            .where(ReviewItem.assessment_id.in_(ids))
            .order_by(ReviewItem.created_at.desc())
            .limit(1)
        )
        outcomes = (
            list(
                session.scalars(
                    select(ReviewOutcome)
                    .where(ReviewOutcome.review_id == review.review_id)
                    .order_by(ReviewOutcome.created_at)
                )
            )
            if review
            else []
        )
        investigations = list(
            session.scalars(
                select(Investigation)
                .where(Investigation.event_id == row.event_id)
                .order_by(Investigation.explanation_version)
            )
        )
        step_up = _step_up(session, ids)
        rules = [
            {
                "rule_id": r.get("rule_id"),
                "reason_code": r.get("reason_code"),
                "description": catalogue.get(str(r.get("reason_code"))),
                "severity": r.get("severity"),
                "matched": r.get("matched"),
                "evaluated": r.get("evaluated"),
                "evidence": r.get("evidence") or {},
                "missing": r.get("missing") or [],
            }
            for r in (original.triggered_rules or {}).get("results", []) or []
            if isinstance(r, dict)
        ]
        reasons = [
            {"code": str(code), "description": describe_reason(str(code), catalogue)}
            for code in row.reason_codes
        ]
        view = CaseView(
            generated_at=c.clock(),
            assessment=assessment_view(session, row).model_dump(mode="json"),
            versions=[
                {
                    "assessment_id": str(v.assessment_id),
                    "assessment_version": v.assessment_version,
                    "mode": v.mode,
                    "decision": v.decision.value,
                    "reason_codes": [str(x) for x in v.reason_codes],
                    "assessed_at": _iso(v.assessed_at),
                }
                for v in versions
            ],
            review=(
                {
                    **(_review_status(review) or {}),
                    "assessment_id": str(review.assessment_id),
                    "reason_codes": [str(x) for x in review.reason_codes],
                    "created_at": _iso(review.created_at),
                    "reviewed_at": _iso(review.reviewed_at),
                    "outcomes": [
                        {
                            "resolution": o.resolution.value,
                            "note": o.note,
                            "reviewer": o.reviewer,
                            "created_at": _iso(o.created_at),
                        }
                        for o in outcomes
                    ],
                }
                if review
                else None
            ),
            reasons=reasons,
            rules=rules,
            models=_models(row, original),
            indicators=_indicators(session, row.event_id),
            timeline=_timeline(session, event, row.assessed_at),
            step_up=step_up,
            activity=_activity(session, versions, review, outcomes, step_up, investigations),
            investigation=_investigation(investigations[-1] if investigations else None),
            latency_ms={k: v for k, v in (original.latency_ms or {}).items()},
        )
    return view


# ------------------------------------------------------------------ summary
def _percentiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None, "samples": 0}
    ordered = sorted(values)

    def pick(q: float) -> float:
        index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
        return round(ordered[index], 2)

    return {"p50": pick(0.50), "p95": pick(0.95), "p99": pick(0.99), "samples": len(ordered)}


@router.get("/summary", response_model=SummaryView)
def summary(
    request: Request,
    caller: Annotated[Caller, Depends(require(SCOPE))],
    hours: Annotated[int | None, Query(ge=1, le=8760)] = None,
) -> SummaryView:
    c = container_of(request)
    now = c.clock()
    start = now - timedelta(hours=hours) if hours else None
    with c.factory() as session:
        live = select(RiskAssessment.decision, func.count()).where(RiskAssessment.mode == "live")
        if start is not None:
            live = live.where(RiskAssessment.assessed_at >= start)
        decisions = {d.value: n for d, n in session.execute(live.group_by(RiskAssessment.decision))}
        fallback_stmt = select(func.count()).where(
            RiskAssessment.mode == "live", RiskAssessment.fallback_used.is_(True)
        )
        followups = select(func.count()).where(RiskAssessment.mode == "step_up_followup")
        if start is not None:
            fallback_stmt = fallback_stmt.where(RiskAssessment.assessed_at >= start)
            followups = followups.where(RiskAssessment.assessed_at >= start)
        latency_stmt = select(RiskAssessment).where(RiskAssessment.mode == "live")
        if start is not None:
            latency_stmt = latency_stmt.where(RiskAssessment.assessed_at >= start)
        latency_rows = session.scalars(
            latency_stmt.order_by(RiskAssessment.assessed_at.desc()).limit(SUMMARY_LATENCY_ROWS)
        ).all()
        latencies = [t for r in latency_rows if (t := _total_latency(r)) is not None]
        agree = disagree = 0
        for r in latency_rows:
            for m in (r.shadow or {}).get("models", []) or []:
                if isinstance(m, dict) and m.get("agrees") is not None:
                    agree += bool(m["agrees"])
                    disagree += not m["agrees"]
        buckets: dict[str, dict[str, int]] = {}
        for r in latency_rows:
            key = ensure_utc(r.assessed_at).replace(minute=0, second=0, microsecond=0).isoformat()
            per = buckets.setdefault(key, {})
            per[r.decision.value] = per.get(r.decision.value, 0) + 1
        reviews = {
            s.value: n
            for s, n in session.execute(
                select(ReviewItem.status, func.count()).group_by(ReviewItem.status)
            )
        }
        by_priority = {
            int(p): n
            for p, n in session.execute(
                select(ReviewItem.priority, func.count())
                .where(ReviewItem.status == ReviewStatus.OPEN)
                .group_by(ReviewItem.priority)
            )
        }
        oldest = session.scalar(
            select(func.min(ReviewItem.created_at)).where(ReviewItem.status == ReviewStatus.OPEN)
        )
        attempts_stmt = select(AuthenticationAttempt.result, func.count()).group_by(
            AuthenticationAttempt.result
        )
        requested = select(func.count()).where(
            RiskAssessment.mode == "live",
            RiskAssessment.decision == "STEP_UP_AUTHENTICATION",
        )
        if start is not None:
            attempts_stmt = attempts_stmt.where(AuthenticationAttempt.created_at >= start)
            requested = requested.where(RiskAssessment.assessed_at >= start)
        attempts = {r.value: n for r, n in session.execute(attempts_stmt)}
        view = SummaryView(
            generated_at=now,
            window_hours=hours,
            assessments={
                "total": sum(decisions.values()),
                "by_decision": decisions,
                "fallbacks": session.scalar(fallback_stmt) or 0,
                "step_up_followups": session.scalar(followups) or 0,
            },
            reviews={
                "by_status": reviews,
                "open_by_priority": by_priority,
                "oldest_open_at": _iso(oldest),
            },
            step_up={"requested": session.scalar(requested) or 0, "attempts_by_result": attempts},
            latency_ms={
                **_percentiles(latencies),
                "scope": f"latest {SUMMARY_LATENCY_ROWS} live assessments in the window",
            },
            shadow={"agree": agree, "disagree": disagree},
            series=[
                {"hour": hour, "by_decision": counts} for hour, counts in sorted(buckets.items())
            ],
        )
    return view


# ------------------------------------------------------------------ system
@router.get("/system", response_model=SystemView)
def system(
    request: Request,
    caller: Annotated[Caller, Depends(require(SCOPE))],
) -> SystemView:
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.trust.anchors import latest_status

    c = container_of(request)
    s = c.settings
    started = time.perf_counter()
    with c.factory() as session:
        deployment = active_deployment(session)
        policy = None
        refs: list[tuple[str, str]] = []
        if deployment is not None:
            record = session.get(PolicyDeployment, deployment.deployment_id)
            definition = deployment.policy
            policy = {
                "policy_version": definition.policy_version,
                "rules_version": definition.rules_version,
                "primary_model": definition.primary.ref,
                "deployment_sequence": record.sequence if record else None,
                "activated_at": _iso(record.activated_at) if record else None,
                "activated_by": record.activated_by if record else None,
                "shadow_models": list(deployment.shadow_models),
                "shadow_policies": [p.policy_version for p in deployment.shadow_policies],
                "bands": [
                    {"lower": b.lower, "risk_level": b.risk_level, "decision": b.decision.value}
                    for b in definition.bands
                ],
                "approvals_required": s.effective_policy_approvals,
                "promotion_required": s.requires_promotion,
            }
            refs = [("primary", definition.primary.ref)]
            for role in ("secondary", "sequence", "anomaly"):
                ref = getattr(definition, role, None)
                if ref is not None:
                    refs.append((role, ref.ref))
            refs += [("shadow", m) for m in deployment.shadow_models]
        models = []
        cached = c.scoring.cache.keys()  # a method (sorted cache keys), not a dict
        for role, ref in refs:
            try:
                mv = resolve_model(session, ref)
            except Exception:
                models.append({"ref": ref, "role": role, "registered": False})
                continue
            signatures = list(
                session.scalars(
                    select(ModelArtifactSignature)
                    .where(ModelArtifactSignature.model_version_id == mv.model_version_id)
                    .order_by(ModelArtifactSignature.signed_at.desc())
                )
            )
            latest_sig = signatures[0] if signatures else None
            models.append(
                {
                    "ref": ref,
                    "role": role,
                    "registered": True,
                    "model_name": mv.model_name,
                    "model_version": mv.model_version,
                    "algorithm": mv.algorithm,
                    "feature_version": mv.feature_version,
                    "trained_at": _iso(mv.training_timestamp),
                    "artifact_sha256": mv.artifact_sha256,
                    "signature": {
                        "present": latest_sig is not None,
                        "key_id": latest_sig.key_id if latest_sig else None,
                        "signed_at": _iso(latest_sig.signed_at) if latest_sig else None,
                        "matches_artifact": latest_sig is not None
                        and latest_sig.artifact_sha256 == mv.artifact_sha256,
                    },
                    # In this worker's model cache (each worker process has its own).
                    "loaded": any(
                        k[0] == mv.model_name and k[1] == mv.model_version for k in cached
                    ),
                    "verified_at_readiness": role == "primary" and "primary_artifact" in c.extras,
                }
            )
        try:
            status = mig.schema_status(c.engine, s.resolved_database_url)
            migrations = {
                "current": status.current,
                "head": status.head,
                "up_to_date": status.up_to_date,
            }
        except Exception:
            migrations = {"current": None, "head": None, "up_to_date": False}
        events = session.scalar(select(func.count()).select_from(AuditEvent)) or 0
        if events <= CHAIN_VERIFY_LIMIT:
            report = audit.verify_chain(session)
            chain = {"verified": report.ok, "events": report.events, "reason": report.reason}
        else:
            chain = {"verified": None, "events": events, "reason": "not checked (too large)"}
        anchor = latest_status(session)
        anchors = (
            {
                "anchor_number": anchor.anchor_number,
                "sequence": anchor.sequence,
                "anchored_at": _iso(anchor.anchored_at),
                "age_minutes": round(anchor.age_minutes(), 1),
                "events_since": anchor.events_since,
                "key_id": anchor.key_id,
                "store": s.effective_anchor_store,
            }
            if anchor
            else None
        )
    runtime = s.local_llm_runtime
    try:
        client = c.llm_client()
        llm_available = client is not None
    except Exception:
        llm_available = False
    return SystemView(
        generated_at=c.clock(),
        environment=s.environment.value,
        checks_ms=round((time.perf_counter() - started) * 1000, 1),
        policy=policy,
        models=models,
        migrations=migrations,
        security={
            "request_signatures_required": s.service_require_signatures,
            "signature_min_version": s.effective_signature_min_version,
            "model_signatures_required": s.requires_model_signatures,
            "operator_auth_required": s.operator_auth_is_required,
            "state_backend": s.state_backend,
            "key_provider": s.key_provider,
        },
        audit={
            "chain": chain,
            "anchor": anchors,
            "anchor_max_age_minutes": s.anchor_max_age_minutes,
        },
        llm={
            "runtime": runtime,
            "model": s.local_llm_model,
            "available": llm_available,
            "reference_template": runtime == "reference",
            "note": "Analyst assistance only; scoring never uses it.",
        },
        reason_catalogue=reason_catalogue(),
    )


# ------------------------------------------------------------------ search
@router.get("/search", response_model=SearchView)
def search(
    request: Request,
    caller: Annotated[Caller, Depends(require(SCOPE))],
    q: Annotated[str, Query(min_length=8, max_length=36, pattern=r"^[0-9a-fA-F-]+$")],
) -> SearchView:
    """Identifier search only (case, assessment or event id, or a prefix of at least 8
    hexadecimal characters). There is deliberately no free-text or personal-data search."""
    c = container_of(request)
    text = q.lower()
    matches: list[dict[str, Any]] = []
    with c.factory() as session:
        exact: uuid.UUID | None = None
        try:
            exact = uuid.UUID(text)
        except ValueError:
            exact = None
        prefix = text.replace("-", "")[:32] + "%"

        def like(column: Any) -> Any:
            return func.replace(func.lower(cast(column, String)), "-", "").like(prefix)

        reviews = session.scalars(
            select(ReviewItem)
            .where(ReviewItem.review_id == exact if exact else like(ReviewItem.review_id))
            .limit(10)
        ).all()
        for r in reviews:
            matches.append(
                {"kind": "review", "id": str(r.review_id), "assessment_id": str(r.assessment_id)}
            )
        assessments = session.scalars(
            select(RiskAssessment)
            .where(
                or_(RiskAssessment.assessment_id == exact, RiskAssessment.event_id == exact)
                if exact
                else or_(like(RiskAssessment.assessment_id), like(RiskAssessment.event_id))
            )
            .order_by(RiskAssessment.assessment_version)
            .limit(20)
        ).all()
        for a in assessments:
            is_event = (exact is not None and a.event_id == exact) or (
                exact is None and str(a.event_id).replace("-", "").startswith(prefix[:-1])
            )
            matches.append(
                {
                    "kind": "event" if is_event else "assessment",
                    "id": str(a.event_id if is_event else a.assessment_id),
                    "assessment_id": str(a.assessment_id),
                    "decision": a.decision.value,
                    "assessed_at": _iso(a.assessed_at),
                }
            )
    return SearchView(query=q, matches=matches[:20])


__all__ = ["INDICATORS", "SCOPE", "reason_catalogue", "router"]
