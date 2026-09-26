"""Evaluation of the analyst layer: explanation *quality and safety*, not fraud detection.

The explanation layer never classifies, so it is **not** evaluated on PR-AUC or recall.
Each local model (runtime + model) is run on a fixed set of synthetic evaluation cases,
and every output goes through the production validator. The metrics are:

* ``schema_compliance``: the share of outputs that parse as JSON and match the schema;
* ``invalid_citation_rate``: the share of outputs citing ids not in the packet (or listing
  ``evidence_ids_used`` wrongly);
* ``unsupported_claim_rate``: the share with a number that no cited evidence supports, or
  a "confirmed fraud" claim without a fraud label;
* ``privacy_violation_rate``: the share containing identifiers or sensitive values;
* ``forbidden_action_rate``: the share with decision language (block, approve...);
* ``valid_rate``: the share passing every check. Only these would be stored;
* ``latency``, ``response length`` and ``token usage``;
* ``evidence_coverage``: of the *key* evidence (model probabilities, the agreement
  pattern and every risk flag that is true), the share that valid outputs cite.

The unit of every rate is an output, and each rate is computed over all outputs.
Generation failures (runtime down, timeout) count against schema compliance and are
reported separately.

Cases are selected from a seeded synthetic world using the synthetic scenario, stored
predictions and packet facts. The scenario is only used to *choose* cases: it is never
put into the packet.
"""

from __future__ import annotations

import statistics
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import EventRecord, ModelPrediction, User
from fraud_ai.llm.builder import build_evidence
from fraud_ai.llm.evidence import EvidencePacket
from fraud_ai.llm.runtime import LocalLLMClient
from fraud_ai.llm.service import GenerationSettings, generate_explanation
from fraud_ai.llm.validation import FailureKind

KEY_FLAG_SECTIONS = (
    "security_summary",
    "transaction_summary",
    "network_summary",
    "device_summary",
    "address_summary",
    "scenario_context",
)
PROTECTIVE_NAMES = {
    "device_seen_before",
    "address_seen_before",
    "network_seen_before",
    "device_trusted",
    "address_verified",
}


def _value(packet: EvidencePacket, section: str, name: str) -> Any:
    item = packet.get(section, name)
    return None if item is None else item.value


def _fraud(p: EvidencePacket) -> bool:
    return bool(_value(p, "label_context", "label_status_now") == "fraud_confirmed")


# Each case: (name, description, predicate over (synthetic scenario, packet)).
CaseRule = tuple[str, str, Any]
CASE_RULES: tuple[CaseRule, ...] = (
    (
        "normal",
        "a legitimate customer, all models low",
        lambda s, p: (
            s == "normal" and not _fraud(p) and _value(p, "model_agreement", "pattern") == "all_low"
        ),
    ),
    ("vpn_user", "a long-term legitimate VPN user", lambda s, p: s == "legitimate_vpn"),
    (
        "house_mover",
        "a customer who moved house",
        lambda s, p: s == "new_home_address" and p.event_type.startswith("transaction"),
    ),
    (
        "large_purchase",
        "a legitimate large purchase",
        lambda s, p: (
            _value(p, "scenario_context", "large_purchase_pattern") is True and not _fraud(p)
        ),
    ),
    ("shared_network", "a customer on a shared network", lambda s, p: s == "shared_network"),
    (
        "account_takeover",
        "a labelled account takeover",
        lambda s, p: s == "account_takeover" and _fraud(p),
    ),
    (
        "stealth_takeover",
        "a labelled slow (stealthy) takeover",
        lambda s, p: s == "slow_account_takeover" and _fraud(p),
    ),
    (
        "high_velocity",
        "a dense burst of activity",
        lambda s, p: _value(p, "scenario_context", "high_velocity_pattern") is True,
    ),
    (
        "friendly_fraud",
        "a labelled friendly-fraud purchase",
        lambda s, p: s == "friendly_fraud" and _fraud(p),
    ),
    (
        "model_disagreement",
        "models disagree about the event",
        lambda s, p: _value(p, "model_agreement", "pattern") == "mixed",
    ),
    (
        "all_models_uncertain",
        "every model scored between 0.3 and 0.7",
        lambda s, p: (
            _value(p, "model_agreement", "models_uncertain")
            == _value(p, "model_agreement", "models_total")
        ),
    ),
)
CASE_TYPES = tuple(name for name, _, _ in CASE_RULES)


@dataclass(frozen=True)
class EvaluationCase:
    case_type: str
    event_id: uuid.UUID
    packet: EvidencePacket


@dataclass
class CaseSelection:
    cases: list[EvaluationCase]
    missing: list[str]
    candidates_examined: int


def candidate_events(session: Session, model_refs: list[str], limit: int) -> list[uuid.UUID]:
    """Events (latest first) with a stored prediction from every requested model."""
    wanted = {tuple(r.rsplit("-", 1)) for r in model_refs}
    rows = session.execute(
        select(ModelPrediction.event_id, ModelPrediction.model_name, ModelPrediction.model_version)
    ).all()
    have: dict[uuid.UUID, set[tuple[str, str]]] = {}
    for event_id, name, version in rows:
        have.setdefault(event_id, set()).add((name, version))
    eligible = [e for e, refs in have.items() if wanted <= refs]
    if not eligible:
        return []
    times = dict(
        session.execute(
            select(EventRecord.event_id, EventRecord.occurred_at).where(
                EventRecord.event_id.in_(eligible)
            )
        ).all()
    )
    return sorted(eligible, key=lambda e: (times[e], str(e)), reverse=True)[:limit]


def select_cases(
    session: Session,
    model_refs: list[str],
    *,
    per_case: int = 1,
    max_candidates: int = 2000,
) -> CaseSelection:
    """Deterministically pick up to ``per_case`` events for each case type. Case types with
    no matching event are reported in ``missing``; nothing is fabricated."""
    counts = dict.fromkeys(CASE_TYPES, 0)
    cases: list[EvaluationCase] = []
    examined = 0
    for event_id in candidate_events(session, model_refs, max_candidates):
        if all(c >= per_case for c in counts.values()):
            break
        event = session.get(EventRecord, event_id)
        assert event is not None
        user = session.get(User, event.user_id) if event.user_id else None
        scenario = (user.synthetic_scenario if user is not None else None) or ""
        examined += 1
        try:
            packet = build_evidence(session, event_id, model_refs)
        except (FraudAIError, ValidationError):
            continue
        for name, _, rule in CASE_RULES:
            if counts[name] < per_case and rule(scenario, packet):
                cases.append(EvaluationCase(name, event_id, packet))
                counts[name] += 1
                break
    cases.sort(key=lambda c: (CASE_TYPES.index(c.case_type), str(c.event_id)))
    return CaseSelection(cases, [n for n, c in counts.items() if c == 0], examined)


def key_evidence(packet: EvidencePacket) -> set[str]:
    keys = {
        i.id
        for i in packet.section("model_scores")
        if i.name.endswith(".probability") and not i.name.endswith(".calibrated_probability")
    }
    pattern = packet.get("model_agreement", "pattern")
    if pattern is not None:
        keys.add(pattern.id)
    for section in KEY_FLAG_SECTIONS:
        keys |= {
            i.id
            for i in packet.section(section)
            if i.value is True and i.name not in PROTECTIVE_NAMES
        }
    return keys


@dataclass
class CaseOutcome:
    case_type: str
    event_id: uuid.UUID
    valid: bool
    failure: str | None
    failure_kinds: list[str]
    latency_seconds: float | None
    output_chars: int | None
    completion_tokens: int | None
    coverage: float | None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_type": self.case_type,
            "event_id": str(self.event_id),
            "valid": self.valid,
            "failure": self.failure,
            "failure_kinds": self.failure_kinds,
            "latency_seconds": self.latency_seconds,
            "output_chars": self.output_chars,
            "completion_tokens": self.completion_tokens,
            "evidence_coverage": self.coverage,
            "errors": self.errors[:5],
        }


def run_case(
    case: EvaluationCase, client: LocalLLMClient, settings: GenerationSettings
) -> CaseOutcome:
    result = generate_explanation(case.packet, client, settings, case.event_id)
    coverage = None
    if result.explanation is not None:
        keys = key_evidence(case.packet)
        coverage = len(keys & result.explanation.cited()) / len(keys) if keys else 1.0
    return CaseOutcome(
        case.case_type,
        case.event_id,
        result.ok,
        result.failure.value if result.failure else None,
        sorted(k.value for k in result.failure_kinds),
        result.latency_seconds,
        result.output_chars,
        result.completion_tokens,
        coverage,
        result.errors,
    )


GENERATION_FAILURES = {
    FailureKind.RUNTIME_UNAVAILABLE.value,
    FailureKind.MODEL_UNAVAILABLE.value,
    FailureKind.TIMEOUT.value,
}
SCHEMA_FAILURES = {
    FailureKind.INVALID_JSON.value,
    FailureKind.SCHEMA_FAILURE.value,
    FailureKind.GENERATION_TOO_LONG.value,
    *GENERATION_FAILURES,
}


def _rate(outcomes: list[CaseOutcome], kind: str) -> float:
    return sum(kind in o.failure_kinds for o in outcomes) / len(outcomes)


def _mean(values: list[float]) -> float | None:
    return round(statistics.fmean(values), 4) if values else None


def summarise(outcomes: list[CaseOutcome]) -> dict[str, Any]:
    if not outcomes:
        return {"outputs": 0}
    latencies = [o.latency_seconds for o in outcomes if o.latency_seconds is not None]
    lengths = [float(o.output_chars) for o in outcomes if o.output_chars is not None]
    tokens = [float(o.completion_tokens) for o in outcomes if o.completion_tokens is not None]
    coverage = [o.coverage for o in outcomes if o.coverage is not None]
    return {
        "outputs": len(outcomes),
        "valid_rate": round(sum(o.valid for o in outcomes) / len(outcomes), 4),
        "schema_compliance": round(
            sum(not (set(o.failure_kinds) & SCHEMA_FAILURES) for o in outcomes) / len(outcomes),
            4,
        ),
        "generation_failure_rate": round(
            sum(bool(set(o.failure_kinds) & GENERATION_FAILURES) for o in outcomes) / len(outcomes),
            4,
        ),
        "invalid_citation_rate": round(_rate(outcomes, "unsupported_citation"), 4),
        "unsupported_claim_rate": round(_rate(outcomes, "unsupported_claim"), 4),
        "privacy_violation_rate": round(_rate(outcomes, "privacy_failure"), 4),
        "forbidden_action_rate": round(_rate(outcomes, "forbidden_action"), 4),
        "latency_mean_seconds": _mean(latencies),
        "latency_max_seconds": round(max(latencies), 4) if latencies else None,
        "response_chars_mean": _mean(lengths),
        "completion_tokens_mean": _mean(tokens),
        "evidence_coverage_mean": _mean(coverage),
    }


@dataclass
class ModelReport:
    runtime: str
    model: str
    available: bool
    detail: str
    outcomes: list[CaseOutcome]

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "model": self.model,
            "available": self.available,
            "detail": self.detail,
            "metrics": summarise(self.outcomes),
            "cases": [o.to_dict() for o in self.outcomes],
        }


def benchmark(
    cases: list[EvaluationCase],
    clients: list[LocalLLMClient],
    settings: GenerationSettings | None = None,
) -> list[ModelReport]:
    """Run every client on every case. An unavailable runtime is reported, not failed."""
    settings = settings or GenerationSettings()
    reports = []
    for client in clients:
        runtime = str(getattr(client, "runtime", "unknown"))
        model = str(getattr(client, "model", "unknown"))
        health = client.health()
        if not health.available:
            reports.append(ModelReport(runtime, model, False, health.detail, []))
            continue
        outcomes = [run_case(case, client, settings) for case in cases]
        reports.append(ModelReport(runtime, model, True, health.detail, outcomes))
    return reports
