"""Rules encode security policy (not statistical prediction).

A rule is a named predicate over a feature mapping. A triggered rule contributes a score
weight and may impose a *minimum* decision (e.g. "Tor + new device => at least step-up").
Rules never lower a decision. Concrete rule sets are configured once features exist
(Stage 2); this module provides the evaluation boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from fraud_ai.core.enums import Decision

FeatureValue = float | int | bool | None
Features = Mapping[str, FeatureValue]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    predicate: Callable[[Features], bool]
    weight: float = 0.0
    minimum_decision: Decision | None = None
    required_features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("rule weight must be within [0, 1]")


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    triggered: bool
    weight: float
    minimum_decision: Decision | None
    reason: str


class RuleEngine:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = list(rules)
        ids = [r.rule_id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id")

    def evaluate(self, features: Features) -> list[RuleResult]:
        results = []
        for rule in self.rules:
            missing = [f for f in rule.required_features if features.get(f) is None]
            if missing:
                # Missing evidence never triggers a rule; it is reported for auditability.
                results.append(
                    RuleResult(rule.rule_id, False, 0.0, None, f"missing: {', '.join(missing)}")
                )
                continue
            triggered = bool(rule.predicate(features))
            results.append(
                RuleResult(
                    rule.rule_id,
                    triggered,
                    rule.weight if triggered else 0.0,
                    rule.minimum_decision if triggered else None,
                    rule.description,
                )
            )
        return results
