"""The boundary between ML probability, rules and the final decision."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from fraud_ai.core.enums import Decision
from fraud_ai.risk.policy import RiskPolicy
from fraud_ai.rules.engine import RuleResult


@dataclass(frozen=True)
class RiskOutcome:
    ml_probability: float | None
    rule_score: float
    final_risk_score: float
    decision: Decision
    policy_version: str
    triggered_rules: tuple[str, ...]

    def triggered_rules_json(self) -> dict[str, list[str]]:
        return {"triggered": list(self.triggered_rules)}


class RiskEngine:
    def __init__(self, policy: RiskPolicy) -> None:
        self.policy = policy

    def assess(
        self, ml_probability: float | None, rule_results: Sequence[RuleResult]
    ) -> RiskOutcome:
        if ml_probability is not None and not 0.0 <= ml_probability <= 1.0:
            raise ValueError("ml_probability must be within [0, 1]")
        triggered = [r for r in rule_results if r.triggered]
        rule_score = min(1.0, sum(r.weight for r in triggered))
        model_part = self.policy.ml_weight * ml_probability if ml_probability is not None else 0.0
        final = min(1.0, model_part + rule_score)

        decision = self.policy.decision_for(final)
        if ml_probability is None:
            decision = _max(decision, self.policy.no_model_decision)
        for r in triggered:
            if r.minimum_decision is not None:
                decision = _max(decision, r.minimum_decision)
        return RiskOutcome(
            ml_probability=ml_probability,
            rule_score=rule_score,
            final_risk_score=final,
            decision=decision,
            policy_version=self.policy.policy_version,
            triggered_rules=tuple(r.rule_id for r in triggered),
        )


def _max(a: Decision, b: Decision) -> Decision:
    return a if a.severity >= b.severity else b
