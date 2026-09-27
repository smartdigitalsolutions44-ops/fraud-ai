"""Stage 8 rules, policy definitions and the deterministic policy engine (no database)."""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest
from pydantic import ValidationError

from fraud_ai.core.enums import Decision, RuleSeverity
from fraud_ai.evaluation.costs import CostConfig
from fraud_ai.risk.engine import PolicyInputs, decide, review_priority
from fraud_ai.risk.offline import OfflinePolicyError, PolicyCostConfig, derive_bands
from fraud_ai.risk.policy import (
    BLOCKING_FAILURES,
    DEFAULT_FALLBACKS,
    Band,
    CalibrationSpec,
    FailureCategory,
    ModelSlot,
    RiskPolicyDefinition,
)
from fraud_ai.rules.engine import Rule, RuleResult, RuleSet
from fraud_ai.rules.ruleset import RULES, RULES_VERSION, get_rule_set

SHA = "a" * 64
RULESET = get_rule_set()


def _slot(ref: str = "gradient-boosting-1.0.0", calibrated: bool = True) -> ModelSlot:
    spec = CalibrationSpec(
        calibration_id="00000000-0000-0000-0000-000000000001",
        method="sigmoid",
        parameters={"a": 1.0, "b": 0.0},
    )
    return ModelSlot(
        ref=ref, artifact_sha256=SHA, threshold=0.5, calibration=spec if calibrated else None
    )


BANDS = (
    Band(lower=0.0, risk_level="very_low", decision=Decision.ALLOW),
    Band(lower=0.2, risk_level="moderate", decision=Decision.ALLOW_WITH_MONITORING),
    Band(lower=0.4, risk_level="elevated", decision=Decision.STEP_UP_AUTHENTICATION),
    Band(lower=0.6, risk_level="high", decision=Decision.MANUAL_REVIEW),
    Band(lower=0.9, risk_level="extreme", decision=Decision.TEMPORARY_BLOCK),
)


def policy(**overrides: Any) -> RiskPolicyDefinition:
    base: dict[str, Any] = {
        "policy_version": "risk-policy-1.0.0",
        "primary": _slot(),
        "bands": BANDS,
        "rules_version": RULES_VERSION,
        "rules_fingerprint": RULESET.fingerprint(),
    }
    base.update(overrides)
    return RiskPolicyDefinition(**base)


def matched(rule_id: str) -> RuleResult:
    rule = next(r for r in RULES if r.rule_id == rule_id)
    return RuleResult(rule_id, rule.version, True, True, rule.severity, rule.reason_code, {})


# ------------------------------------------------------------------ rules
BASE_FEATURES: dict[str, Any] = {
    "recent_password_reset": False,
    "new_device": False,
    "unusually_high_transaction": False,
    "transaction_vs_median_ratio": 1.0,
    "failed_logins_last_15m": 0,
    "failed_logins_from_network_last_1h": 0,
    "rapid_multi_change_count": 0,
    "recent_mfa_removed": False,
    "tor_detected": False,
    "datacenter_detected": False,
    "vpn_detected": False,
    "new_payment_method": False,
    "new_address": False,
}


def _eval(kind: str = "transaction", **changes: Any) -> dict[str, RuleResult]:
    return {r.rule_id: r for r in RULESET.evaluate({**BASE_FEATURES, **changes}, kind, "snap/1")}


def test_quiet_event_matches_nothing() -> None:
    results = _eval()
    assert results and not any(r.matched for r in results.values())
    assert all(r.evaluated and r.snapshot_ref == "snap/1" for r in results.values())


@pytest.mark.parametrize(
    ("rule_id", "changes"),
    [
        (
            "R001",
            {"recent_password_reset": True, "new_device": True, "unusually_high_transaction": True},
        ),
        (
            "R001",
            {"recent_password_reset": True, "new_device": True, "transaction_vs_median_ratio": 3.5},
        ),
        ("R002", {"failed_logins_last_15m": 5}),
        ("R002", {"failed_logins_from_network_last_1h": 10}),
        ("R003", {"rapid_multi_change_count": 3}),
        ("R004", {"recent_mfa_removed": True, "new_device": True}),
        ("R005", {"tor_detected": True, "new_device": True}),
        ("R005", {"datacenter_detected": True, "new_device": True}),
        (
            "R006",
            {"new_payment_method": True, "new_address": True, "unusually_high_transaction": True},
        ),
    ],
)
def test_each_rule_matches_its_pattern(rule_id: str, changes: dict[str, Any]) -> None:
    results = _eval(**changes)
    assert results[rule_id].matched
    assert set(results[rule_id].evidence) >= set(changes)
    assert results[rule_id].to_dict()["reason_code"] == results[rule_id].reason_code


@pytest.mark.parametrize(
    "changes",
    [
        {"recent_password_reset": True, "new_device": True},  # not high value
        {"failed_logins_last_15m": 4},
        {"rapid_multi_change_count": 2},
        {"vpn_detected": True, "new_device": True},  # VPN alone is not proof
        {"tor_detected": True},  # known device
    ],
)
def test_near_misses_do_not_match(changes: dict[str, Any]) -> None:
    assert not any(r.matched for r in _eval(**changes).values())


def test_missing_evidence_never_matches_and_is_reported() -> None:
    features = {**BASE_FEATURES, "new_device": None, "recent_password_reset": True}
    r001 = next(r for r in RULESET.evaluate(features, "transaction") if r.rule_id == "R001")
    assert not r001.matched and not r001.evaluated and r001.missing == ("new_device",)


def test_rules_apply_only_to_their_event_kinds() -> None:
    login_ids = {r.rule_id for r in RULESET.evaluate(BASE_FEATURES, "login")}
    assert "R001" not in login_ids and "R006" not in login_ids and "R002" in login_ids


def test_rule_set_fingerprint_and_registry() -> None:
    assert RULESET.fingerprint() == get_rule_set(RULES_VERSION).fingerprint()
    assert len(RULESET.fingerprint()) == 64
    changed = RuleSet(RULES_VERSION, [RULES[0], *RULES[1:5]])
    assert changed.fingerprint() != RULESET.fingerprint()
    with pytest.raises(KeyError):
        get_rule_set("fraud-rules-9.9.9")
    with pytest.raises(ValueError, match="duplicate"):
        RuleSet("x", [RULES[0], RULES[0]])
    assert {r.severity for r in RULES} <= set(RuleSeverity)
    spec = RULES[0].spec()
    assert spec["rule_id"] == "R001" and spec["parameters"] == {"median_ratio": 3.0}


def test_rules_are_deterministic() -> None:
    features = {**BASE_FEATURES, "failed_logins_last_15m": 9, "rapid_multi_change_count": 4}
    first = [r.to_dict() for r in RULESET.evaluate(features, "login")]
    assert first == [r.to_dict() for r in RULESET.evaluate(features, "login")]


def test_custom_rule_contract() -> None:
    rule = Rule(
        "X1",
        "x",
        "1.0.0",
        "d",
        RuleSeverity.LOW,
        "X",
        "c",
        lambda f, p: f.get("a") == p["v"],
        ("a",),
        parameters={"v": 1},
    )
    assert RuleSet("t", [rule]).evaluate({"a": 1}, "login")[0].matched


# ------------------------------------------------------------------ policy definition
def test_policy_hash_is_stable_and_changes_with_content() -> None:
    assert policy().sha256() == policy().sha256()
    assert policy().sha256() != policy(late_event_seconds=60).sha256()
    assert RiskPolicyDefinition.model_validate(policy().model_dump(mode="json")) == policy()


@pytest.mark.parametrize(
    "overrides",
    [
        {"policy_version": "my-policy"},
        {"primary": _slot(calibrated=False)},
        {"bands": BANDS[1:]},
        {"bands": (BANDS[0], BANDS[2], BANDS[1])},
        {
            "bands": (
                BANDS[0],
                Band(lower=0.5, risk_level="moderate", decision=Decision.MANUAL_REVIEW),
                Band(lower=0.6, risk_level="elevated", decision=Decision.ALLOW),
            )
        },
        {
            "fallbacks": {
                **DEFAULT_FALLBACKS,
                FailureCategory.FEATURE_EXTRACTION_FAILED: Decision.ALLOW,
            }
        },
        {
            "fallbacks": {
                **DEFAULT_FALLBACKS,
                FailureCategory.SEQUENCE_MODEL_FAILED: Decision.ALLOW_WITH_MONITORING,
            }
        },
        {
            "fallbacks": {
                k: v for k, v in DEFAULT_FALLBACKS.items() if k is not FailureCategory.RULES_FAILED
            }
        },
        {"decision_event_kinds": ("address",)},
        {"severity_minimum": {RuleSeverity.LOW: Decision.ALLOW}},
        {"schema_version": "risk-policy-schema-9"},
    ],
)
def test_invalid_policies_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        policy(**overrides)


def test_band_lookup() -> None:
    p = policy()
    assert [p.band_for(s).decision for s in (0.0, 0.19, 0.2, 0.5, 0.61, 0.95, 1.0)] == [
        Decision.ALLOW,
        Decision.ALLOW,
        Decision.ALLOW_WITH_MONITORING,
        Decision.STEP_UP_AUTHENTICATION,
        Decision.MANUAL_REVIEW,
        Decision.TEMPORARY_BLOCK,
        Decision.TEMPORARY_BLOCK,
    ]
    assert set(policy(secondary=_slot("neural-network-1.0.0", False)).slots()) == {
        "primary",
        "secondary",
    }


def test_decision_ordering_has_no_permanent_ban() -> None:
    assert [d.value for d in sorted(Decision, key=lambda d: d.severity)] == [
        "ALLOW",
        "ALLOW_WITH_MONITORING",
        "STEP_UP_AUTHENTICATION",
        "MANUAL_REVIEW",
        "TEMPORARY_BLOCK",
    ]
    assert "BLOCK" not in Decision.__members__


# ------------------------------------------------------------------ decide()
def test_score_bands_drive_the_base_decision() -> None:
    p = policy()
    d = decide(p, PolicyInputs(primary_score=0.1))
    assert (
        d.decision is Decision.ALLOW and d.risk_level == "very_low" and d.action == {"type": "NONE"}
    )
    assert d.reason_codes == ("SCORE_BAND_VERY_LOW",) and not d.fallback_used
    assert decide(p, PolicyInputs(primary_score=0.45)).decision is Decision.STEP_UP_AUTHENTICATION


def test_rules_raise_but_never_lower() -> None:
    p = policy()
    high = decide(p, PolicyInputs(primary_score=0.05, rule_results=[matched("R001")]))
    assert high.decision is Decision.MANUAL_REVIEW
    assert high.reason_codes == ("SCORE_BAND_VERY_LOW", "ATO_RESET_NEW_DEVICE_HIGH_VALUE")
    low = decide(p, PolicyInputs(primary_score=0.65, rule_results=[matched("R005")]))
    assert low.decision is Decision.MANUAL_REVIEW  # a low-severity rule cannot lower it
    medium = decide(p, PolicyInputs(primary_score=0.05, rule_results=[matched("R002")]))
    assert medium.decision is Decision.STEP_UP_AUTHENTICATION
    assert medium.action["required_strength"] == "strong"  # takeover-type reason
    unmatched = RuleResult("R001", "1.0.0", False, True, RuleSeverity.HIGH, "X", {})
    assert decide(p, PolicyInputs(primary_score=0.05, rule_results=[unmatched])).decision is (
        Decision.ALLOW
    )


def test_secondary_and_anomaly_escalate_to_monitoring_only() -> None:
    p = policy()
    d = decide(
        p, PolicyInputs(primary_score=0.05, secondary_flags={"sequence": True, "secondary": False})
    )
    assert (
        d.decision is Decision.ALLOW_WITH_MONITORING and "SEQUENCE_MODEL_ELEVATED" in d.reason_codes
    )
    assert d.action["type"] == "MONITOR" and d.action["window_hours"] == 72
    a = decide(p, PolicyInputs(primary_score=0.05, anomaly_flag=True))
    assert a.decision is Decision.ALLOW_WITH_MONITORING and "ANOMALY_SIGNAL" in a.reason_codes
    # A flag on an already-restrictive decision changes nothing.
    assert decide(
        p, PolicyInputs(primary_score=0.7, secondary_flags={"secondary": True})
    ).decision is (Decision.MANUAL_REVIEW)


def test_temporary_block_needs_corroboration() -> None:
    p = policy()
    alone = decide(p, PolicyInputs(primary_score=0.95))
    assert (
        alone.decision is Decision.MANUAL_REVIEW and "BLOCK_NOT_CORROBORATED" in alone.reason_codes
    )
    with_rule = decide(p, PolicyInputs(primary_score=0.95, rule_results=[matched("R003")]))
    assert with_rule.decision is Decision.TEMPORARY_BLOCK
    assert with_rule.action["expires_after_hours"] == 24 and with_rule.action["requires_review"]
    low_rule = decide(p, PolicyInputs(primary_score=0.95, rule_results=[matched("R005")]))
    assert low_rule.decision is Decision.MANUAL_REVIEW
    with_model = decide(p, PolicyInputs(primary_score=0.95, secondary_flags={"secondary": True}))
    assert with_model.decision is Decision.TEMPORARY_BLOCK
    unguarded = policy(block_requires_corroboration=False)
    assert decide(unguarded, PolicyInputs(primary_score=0.95)).decision is Decision.TEMPORARY_BLOCK


@pytest.mark.parametrize(
    "failure", sorted(BLOCKING_FAILURES - {FailureCategory.POLICY_UNAVAILABLE})
)
def test_blocking_failures_never_allow(failure: FailureCategory) -> None:
    d = decide(policy(), PolicyInputs(primary_score=0.01, failures=[failure]))
    assert d.decision.severity >= Decision.STEP_UP_AUTHENTICATION.severity
    assert d.risk_level == "unknown" and d.final_risk_score is None and d.fallback_used
    assert f"FALLBACK_{failure.value.upper()}" in d.reason_codes


@pytest.mark.parametrize(
    "failure",
    [
        FailureCategory.SEQUENCE_EXTRACTION_FAILED,
        FailureCategory.SECONDARY_MODEL_FAILED,
        FailureCategory.SEQUENCE_MODEL_FAILED,
        FailureCategory.ANOMALY_MODEL_FAILED,
        FailureCategory.RULES_FAILED,
    ],
)
def test_optional_failures_raise_a_low_score(failure: FailureCategory) -> None:
    d = decide(policy(), PolicyInputs(primary_score=0.01, failures=[failure]))
    assert d.decision.severity >= Decision.STEP_UP_AUTHENTICATION.severity and d.fallback_used


def test_missing_score_without_failure_is_treated_as_unavailable() -> None:
    d = decide(policy(), PolicyInputs(primary_score=None))
    assert d.decision is Decision.MANUAL_REVIEW
    assert d.reason_codes[0] == "FALLBACK_PRIMARY_MODEL_UNAVAILABLE"


def test_no_policy_means_system_fallback() -> None:
    d = decide(None, PolicyInputs(primary_score=0.01))
    assert d.decision is Decision.MANUAL_REVIEW and d.reason_codes == (
        "FALLBACK_POLICY_UNAVAILABLE",
    )
    d2 = decide(
        None, PolicyInputs(primary_score=None, failures=[FailureCategory.POLICY_UNAVAILABLE])
    )
    assert d2.fallback_used and d2.action["type"] == "MANUAL_REVIEW"


def test_late_events_are_monitored() -> None:
    p = policy()
    assert (
        decide(p, PolicyInputs(primary_score=0.05, lateness_seconds=60)).decision is Decision.ALLOW
    )
    late = decide(p, PolicyInputs(primary_score=0.05, lateness_seconds=3600))
    assert late.decision is Decision.ALLOW_WITH_MONITORING and "LATE_EVENT" in late.reason_codes


def test_decide_is_deterministic() -> None:
    inputs = PolicyInputs(
        primary_score=0.42,
        rule_results=[matched("R003"), matched("R005")],
        secondary_flags={"sequence": True},
        lateness_seconds=10.0,
    )
    assert decide(policy(), inputs) == decide(policy(), inputs)


def test_review_priority() -> None:
    p = policy()
    assert review_priority(decide(p, PolicyInputs(primary_score=0.1))) is None
    assert (
        review_priority(decide(p, PolicyInputs(primary_score=0.95, rule_results=[matched("R003")])))
        == 1
    )
    assert review_priority(decide(p, PolicyInputs(primary_score=0.7))) == 2
    assert review_priority(decide(p, PolicyInputs(primary_score=None))) == 2
    moderate = decide(p, PolicyInputs(primary_score=0.25, rule_results=[matched("R001")]))
    assert moderate.decision is Decision.MANUAL_REVIEW and review_priority(moderate) == 3


# ------------------------------------------------------------------ band derivation + costs
def _synthetic_scores(seed: int = 0, n: int = 3000) -> tuple[Any, Any]:
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.05).astype(int)
    p = np.where(y == 1, rng.beta(6, 2, n), rng.beta(1, 25, n))
    return y, p


def test_derived_bands_are_ordered_and_documented() -> None:
    y, p = _synthetic_scores()
    bands, derivation = derive_bands(y, p, CostConfig())
    assert bands[0].lower == 0.0 and bands[0].decision is Decision.ALLOW
    assert [b.lower for b in bands] == sorted({b.lower for b in bands})
    assert "SYNTHETIC" in derivation["note"] and derivation["targets"]["min_validation_fraud"] == 10
    assert sum(r["validation_events"] for r in derivation["validation_bands"]) == len(y)
    assert derive_bands(y, p, CostConfig()) == (bands, derivation)  # deterministic


def test_coinciding_thresholds_keep_the_stricter_band() -> None:
    y, p = _synthetic_scores(1)
    bands, derivation = derive_bands(y, p, CostConfig(), monitor_recall=0.1)
    t = derivation["thresholds"]
    decisions = [b.decision for b in bands]
    if t["step_up"] == t["manual_review"]:
        assert Decision.MANUAL_REVIEW in decisions
    assert decisions == sorted(decisions, key=lambda d: d.severity)


def test_no_block_band_without_precision() -> None:
    y, p = _synthetic_scores(2)
    bands, derivation = derive_bands(
        y,
        p,
        CostConfig(),
        block_precision=1.0,
    )
    if derivation["thresholds"]["temporary_block"] is None:
        assert Decision.TEMPORARY_BLOCK not in [b.decision for b in bands]


def test_too_little_fraud_is_refused() -> None:
    y = np.zeros(500, dtype=int)
    y[:3] = 1
    with pytest.raises(OfflinePolicyError, match="at least 10 fraud"):
        derive_bands(y, np.linspace(0, 1, 500), CostConfig())


def test_policy_cost_model() -> None:
    c = PolicyCostConfig()
    assert c.event_cost(Decision.ALLOW, True) == 500 and c.event_cost(Decision.ALLOW, False) == 0
    assert c.event_cost(Decision.ALLOW_WITH_MONITORING, False) == pytest.approx(0.1)
    assert c.event_cost(Decision.STEP_UP_AUTHENTICATION, True) == pytest.approx(251.0)
    assert c.event_cost(Decision.STEP_UP_AUTHENTICATION, False) == pytest.approx(11.0)
    assert c.event_cost(Decision.MANUAL_REVIEW, True) == pytest.approx(5.0)
    assert c.event_cost(Decision.TEMPORARY_BLOCK, False) == pytest.approx(35.0)
    with pytest.raises(ValueError):
        PolicyCostConfig(step_up_fraud_stop_rate=1.5)
    with pytest.raises(ValueError):
        PolicyCostConfig(fraud_loss=-1)
