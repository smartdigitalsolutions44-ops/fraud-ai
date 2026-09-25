import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fraud_ai.core.enums import Decision
from fraud_ai.risk.engine import RiskEngine
from fraud_ai.risk.policy import RiskPolicy
from fraud_ai.rules.engine import Rule, RuleEngine

POLICY = RiskPolicy(
    policy_version="p1",
    ml_weight=0.8,
    step_up_threshold=0.4,
    review_threshold=0.7,
    block_threshold=0.9,
)

RULES = RuleEngine(
    [
        Rule(
            "new_device_high_value",
            "New device and transaction >5x average",
            lambda f: bool(f["new_device"]) and float(f["transaction_vs_average_ratio"] or 0) > 5,
            weight=0.15,
            required_features=("new_device", "transaction_vs_average_ratio"),
        ),
        Rule(
            "recent_password_reset",
            "Password reset in the last hour",
            lambda f: float(f["time_since_password_reset"] or 1e9) < 60,
            weight=0.1,
            minimum_decision=Decision.STEP_UP_AUTHENTICATION,
            required_features=("time_since_password_reset",),
        ),
    ]
)


def test_policy_validation_and_bands() -> None:
    with pytest.raises(ValidationError):
        RiskPolicy(
            policy_version="bad", step_up_threshold=0.8, review_threshold=0.5, block_threshold=0.9
        )
    assert [POLICY.decision_for(s) for s in (0.1, 0.4, 0.75, 0.95)] == [
        Decision.ALLOW,
        Decision.STEP_UP_AUTHENTICATION,
        Decision.MANUAL_REVIEW,
        Decision.BLOCK,
    ]


def test_policy_from_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY.model_dump(mode="json")))
    assert RiskPolicy.from_file(path) == POLICY


def test_ml_and_rules_combine_into_decision() -> None:
    features = {
        "new_device": True,
        "transaction_vs_average_ratio": 7.4,
        "time_since_password_reset": 12,
    }
    outcome = RiskEngine(POLICY).assess(0.78, RULES.evaluate(features))
    assert outcome.triggered_rules == ("new_device_high_value", "recent_password_reset")
    assert outcome.rule_score == pytest.approx(0.25)
    assert outcome.final_risk_score == pytest.approx(0.8 * 0.78 + 0.25)
    assert outcome.decision is Decision.MANUAL_REVIEW
    assert outcome.policy_version == "p1"


def test_rules_impose_minimum_decision_even_at_low_probability() -> None:
    outcome = RiskEngine(POLICY).assess(
        0.01,
        RULES.evaluate(
            {
                "new_device": False,
                "transaction_vs_average_ratio": 1.0,
                "time_since_password_reset": 5,
            }
        ),
    )
    assert outcome.final_risk_score < POLICY.step_up_threshold
    assert outcome.decision is Decision.STEP_UP_AUTHENTICATION


def test_missing_features_never_trigger_and_missing_model_is_conservative() -> None:
    results = RULES.evaluate({"new_device": True})
    assert not any(r.triggered for r in results)
    assert "missing" in results[0].reason
    outcome = RiskEngine(POLICY).assess(None, results)
    assert outcome.decision is Decision.MANUAL_REVIEW


def test_input_validation() -> None:
    with pytest.raises(ValueError):
        RiskEngine(POLICY).assess(1.5, [])
    with pytest.raises(ValueError):
        Rule("r", "d", lambda f: True, weight=2)
    with pytest.raises(ValueError):
        RuleEngine([Rule("r", "d", lambda f: True), Rule("r", "d", lambda f: True)])
    assert Decision.BLOCK.severity > Decision.ALLOW.severity
