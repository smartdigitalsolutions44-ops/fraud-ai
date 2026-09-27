"""The deterministic policy engine: model scores + rules + policy = decision.

Models provide calibrated probabilities (evidence). Rules provide explicit matches
(evidence). Only :func:`decide`, driven by a versioned :class:`RiskPolicyDefinition`,
chooses the decision. It is a pure function: the same inputs always give the same output,
and the live service and the offline simulator call the same code.

Order of application (each step can only make the decision *more* restrictive):

1. **Base.** The band of the calibrated primary score. If a blocking failure left no
   trustworthy score, the strictest applicable fallback is used instead (risk level
   ``unknown``).
2. **Rules.** Each matched rule applies the policy's minimum decision for its severity.
3. **Secondary and sequence models.** A model flagging an event that the primary score
   placed below the escalation level raises it to ``secondary_escalation``.
4. **Anomaly signal.** An anomaly score above its threshold raises the decision to
   ``anomaly_escalation``.
5. **Non-blocking failures** (secondary, sequence or anomaly model, sequence
   extraction). These raise the decision to their fallback.
6. **Late events.** An event arriving later than ``late_event_seconds`` raises the
   decision to ``late_event_minimum``.
7. **Corroboration.** A ``TEMPORARY_BLOCK`` needs corroboration: a matched rule of at
   least medium severity, or a flagging secondary/sequence model. Otherwise it becomes
   ``MANUAL_REVIEW``, so a single model score can never block on its own.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from fraud_ai.core.enums import Decision, RuleSeverity
from fraud_ai.risk.policy import (
    BLOCKING_FAILURES,
    SYSTEM_FALLBACK,
    UNKNOWN_RISK,
    FailureCategory,
    RiskPolicyDefinition,
)
from fraud_ai.rules.engine import RuleResult


@dataclass(frozen=True)
class PolicyInputs:
    primary_score: float | None  # calibrated
    rule_results: Sequence[RuleResult] = ()
    secondary_flags: dict[str, bool] = field(default_factory=dict)  # role -> flagged
    anomaly_flag: bool | None = None
    failures: Sequence[FailureCategory] = ()
    lateness_seconds: float | None = None


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    risk_level: str
    final_risk_score: float | None
    reason_codes: tuple[str, ...]
    action: dict[str, Any]
    fallback_used: bool


def _raise(current: Decision, minimum: Decision) -> Decision:
    return minimum if minimum.severity > current.severity else current


def decide(policy: RiskPolicyDefinition | None, inputs: PolicyInputs) -> PolicyDecision:
    reasons: list[str] = []
    blocking = [f for f in inputs.failures if f in BLOCKING_FAILURES]
    if policy is None:
        system = tuple(
            dict.fromkeys(
                [f"FALLBACK_{f.value.upper()}" for f in inputs.failures]
                or ["FALLBACK_POLICY_UNAVAILABLE"]
            )
        )
        return PolicyDecision(
            SYSTEM_FALLBACK,
            UNKNOWN_RISK,
            None,
            system,
            _action(SYSTEM_FALLBACK, system, None, fallback=True),
            True,
        )

    fallback_used = bool(inputs.failures)
    if blocking or inputs.primary_score is None:
        decision = Decision.ALLOW
        for failure in blocking or [FailureCategory.PRIMARY_MODEL_UNAVAILABLE]:
            decision = _raise(decision, policy.fallbacks[failure])
            reasons.append(f"FALLBACK_{failure.value.upper()}")
        risk_level, score = UNKNOWN_RISK, None
        fallback_used = True
    else:
        band = policy.band_for(inputs.primary_score)
        decision, risk_level, score = band.decision, band.risk_level, inputs.primary_score
        reasons.append(f"SCORE_BAND_{band.risk_level.upper()}")

    corroborated = False
    for result in inputs.rule_results:
        if not result.matched:
            continue
        decision = _raise(decision, policy.severity_minimum[result.severity])
        reasons.append(result.reason_code)
        if result.severity is not RuleSeverity.LOW:
            corroborated = True

    for role, flagged in sorted(inputs.secondary_flags.items()):
        if flagged:
            corroborated = True
            if decision.severity < policy.secondary_escalation.severity:
                decision = policy.secondary_escalation
            reasons.append(f"{role.upper()}_MODEL_ELEVATED")

    if inputs.anomaly_flag:
        decision = _raise(decision, policy.anomaly_escalation)
        reasons.append("ANOMALY_SIGNAL")

    for failure in inputs.failures:
        if failure not in BLOCKING_FAILURES:
            decision = _raise(decision, policy.fallbacks[failure])
            reasons.append(f"FALLBACK_{failure.value.upper()}")

    if inputs.lateness_seconds is not None and inputs.lateness_seconds > policy.late_event_seconds:
        decision = _raise(decision, policy.late_event_minimum)
        reasons.append("LATE_EVENT")

    if (
        decision is Decision.TEMPORARY_BLOCK
        and policy.block_requires_corroboration
        and not corroborated
        and not blocking
    ):
        decision = Decision.MANUAL_REVIEW
        reasons.append("BLOCK_NOT_CORROBORATED")

    codes = tuple(dict.fromkeys(reasons))
    return PolicyDecision(
        decision,
        risk_level,
        score,
        codes,
        _action(decision, codes, policy, fallback=fallback_used),
        fallback_used,
    )


_ATO_CODES = {"ATO_RESET_NEW_DEVICE_HIGH_VALUE", "MFA_REMOVED_NEW_DEVICE", "FAILED_LOGIN_BURST"}


def _action(
    decision: Decision,
    reasons: Sequence[str],
    policy: RiskPolicyDefinition | None,
    *,
    fallback: bool,
) -> dict[str, Any]:
    """An internal action *request* (nothing is executed; no external system is called)."""
    if decision is Decision.ALLOW:
        return {"type": "NONE"}
    if decision is Decision.ALLOW_WITH_MONITORING:
        hours = policy.monitoring_hours if policy else 72
        return {"type": "MONITOR", "window_hours": hours, "reason_codes": list(reasons)}
    if decision is Decision.STEP_UP_AUTHENTICATION:
        strong = fallback or bool(_ATO_CODES & set(reasons))
        return {
            "type": "STEP_UP_AUTHENTICATION",
            "required_strength": "strong" if strong else "standard",
            "reason_codes": list(reasons),
            "note": "placeholder request only; no authentication is performed",
        }
    if decision is Decision.MANUAL_REVIEW:
        return {"type": "MANUAL_REVIEW", "reason_codes": list(reasons)}
    hours = policy.temporary_block_hours if policy else 24
    return {
        "type": "TEMPORARY_BLOCK",
        "expires_after_hours": hours,
        "requires_review": True,
        "reason_codes": list(reasons),
        "note": "internal policy output; never permanent, always reviewed",
    }


def review_priority(decision: PolicyDecision) -> int | None:
    """1 is most urgent. Only MANUAL_REVIEW and TEMPORARY_BLOCK enter the queue."""
    if decision.decision is Decision.TEMPORARY_BLOCK:
        return 1
    if decision.decision is not Decision.MANUAL_REVIEW:
        return None
    if decision.fallback_used:
        return 2
    if decision.risk_level in ("high", "extreme"):
        return 2
    return 3
