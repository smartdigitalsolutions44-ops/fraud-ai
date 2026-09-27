"""Rules encode explicit security policy (not statistical prediction).

A rule is a small, named, versioned predicate over the event's point-in-time feature
vector. Each evaluation returns a :class:`RuleResult`:

* the rule id and version;
* whether it matched;
* its severity and reason code;
* the evidence: the feature values it read, citing the feature snapshot.

Rules **never execute an action**. A match contributes to the risk policy, which maps a
severity to a *minimum* decision. Rules never lower a decision, and missing evidence
never triggers a rule: the rule reports it as missing.

A rule's logic is fixed for its version. Changing a predicate or a parameter means a new
rule version *and* a new rule-set version, and the rule-set fingerprint covers both.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from fraud_ai.core.enums import RuleSeverity

FeatureValue = float | int | bool | str | None
Features = Mapping[str, FeatureValue]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    version: str
    description: str
    severity: RuleSeverity
    reason_code: str
    category: str
    predicate: Callable[[Features, Mapping[str, Any]], bool]
    required_features: tuple[str, ...]
    evidence_features: tuple[str, ...] = ()
    applies_to: frozenset[str] = frozenset({"transaction", "login"})
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def spec(self) -> dict[str, Any]:
        """Everything that defines the rule except its code (which its version pins)."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "severity": self.severity.value,
            "reason_code": self.reason_code,
            "category": self.category,
            "applies_to": sorted(self.applies_to),
            "required_features": list(self.required_features),
            "evidence_features": list(self.evidence_features),
            "parameters": dict(self.parameters),
        }


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    version: str
    matched: bool
    evaluated: bool
    severity: RuleSeverity
    reason_code: str
    evidence: dict[str, FeatureValue]
    missing: tuple[str, ...] = ()
    snapshot_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "matched": self.matched,
            "evaluated": self.evaluated,
            "severity": self.severity.value,
            "reason_code": self.reason_code,
            "evidence": self.evidence,
            "missing": list(self.missing),
            "snapshot_ref": self.snapshot_ref,
        }


class RuleSet:
    def __init__(self, version: str, rules: Iterable[Rule]) -> None:
        self.version = version
        self.rules = list(rules)
        ids = [r.rule_id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id")

    def fingerprint(self) -> str:
        payload = {"version": self.version, "rules": [r.spec() for r in self.rules]}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def evaluate(
        self, features: Features, event_kind: str, snapshot_ref: str | None = None
    ) -> list[RuleResult]:
        results = []
        for rule in self.rules:
            if event_kind not in rule.applies_to:
                continue
            evidence = {
                name: features.get(name)
                for name in (*rule.required_features, *rule.evidence_features)
            }
            missing = tuple(f for f in rule.required_features if features.get(f) is None)
            matched = not missing and bool(rule.predicate(features, rule.parameters))
            results.append(
                RuleResult(
                    rule.rule_id,
                    rule.version,
                    matched,
                    not missing,
                    rule.severity,
                    rule.reason_code,
                    evidence,
                    missing,
                    snapshot_ref,
                )
            )
        return results
