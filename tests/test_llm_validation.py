"""Stage 7 output validation: schema, citations, faithfulness of numbers, confirmed-fraud
claims, decision language, privacy, length, and the reference template analyst."""

from __future__ import annotations

import json
from typing import Any

import pytest

from fraud_ai.llm.evidence import EvidencePacket
from fraud_ai.llm.prompt import build_prompt
from fraud_ai.llm.reference import REFERENCE_MODEL, ReferenceAnalyst, explain
from fraud_ai.llm.runtime import GenerationRequest
from fraud_ai.llm.schema import EXPLANATION_SCHEMA_VERSION, InvestigationExplanation, json_schema
from fraud_ai.llm.validation import FailureKind, validate_output
from tests.llm_helpers import GB, GRU, packet


def _check(data: Any, p: EvidencePacket | None = None, **kw: Any) -> Any:
    p = p or packet()
    text = data if isinstance(data, str) else json.dumps(data)
    return validate_output(text, p, **kw)


def _cite(p: EvidencePacket, name: str) -> str:
    item = next(i for i in p.items if i.name == name)
    return item.id


def _finding(statement: str, *ids: str) -> dict[str, Any]:
    return {"statement": statement, "evidence_ids": list(ids)}


def _minimal(p: EvidencePacket, statement: str, *ids: str, **extra: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"summary": _finding(statement, *ids)} | extra
    cited = set(ids)
    for value in extra.values():
        for f in value:
            cited |= set(f["evidence_ids"])
    data["evidence_ids_used"] = sorted(cited)
    return data


# ------------------------------------------------------------------ the happy path
def test_reference_output_is_valid_and_fully_cited() -> None:
    p = packet()
    result = _check(explain(p), p)
    assert result.valid and result.failure is None and result.kinds == frozenset()
    explanation = result.explanation
    assert explanation is not None
    assert explanation.cited() <= p.ids
    assert set(explanation.evidence_ids_used) == explanation.cited()
    assert result.to_dict() == {"valid": True, "failure": None, "failure_kinds": [], "errors": []}


def test_code_fence_is_tolerated() -> None:
    p = packet()
    assert _check(f"```json\n{json.dumps(explain(p))}\n```", p).valid


def test_render_is_deterministic_and_says_decision_support_only() -> None:
    p = packet()
    e = InvestigationExplanation.model_validate(explain(p))
    assert e.render() == InvestigationExplanation.model_validate(explain(p)).render()
    assert e.render().endswith("does not change any score or decision.")
    assert "Questions for the analyst:" in e.render()


def test_json_schema_is_exported() -> None:
    schema = json_schema()
    assert "summary" in schema["required"]
    assert EXPLANATION_SCHEMA_VERSION == "investigation-explanation-1.0.0"


# ------------------------------------------------------------------ failure modes
def test_too_long() -> None:
    result = _check("x" * 50, max_chars=10)
    assert result.failure is FailureKind.GENERATION_TOO_LONG and not result.valid


@pytest.mark.parametrize("text", ["not json", "{", "[1, 2]", '"a string"', ""])
def test_invalid_json(text: str) -> None:
    assert _check(text).failure is FailureKind.INVALID_JSON


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"summary": {"statement": "x"}},
        {"summary": {"statement": "x", "evidence_ids": []}},
        {"summary": {"statement": "x", "evidence_ids": ["E1"]}, "decision": "block"},
        {"summary": {"statement": "x", "evidence_ids": ["E1"]}, "risk_factors": "none"},
    ],
)
def test_schema_failure(data: dict[str, Any]) -> None:
    assert _check(data).failure is FailureKind.SCHEMA_FAILURE


def test_review_questions_must_be_questions() -> None:
    p = packet()
    data = explain(p)
    data["recommended_review_questions"] = [{"question": "Check the device.", "evidence_ids": []}]
    result = _check(data, p)
    assert result.failure is FailureKind.SCHEMA_FAILURE
    assert "not a question" in result.errors[0]


def test_unknown_citation_is_rejected() -> None:
    p = packet()
    data = explain(p)
    data["risk_factors"].append(_finding("Something else happened.", "E999"))
    data["evidence_ids_used"].append("E999")
    result = _check(data, p)
    assert result.failure is FailureKind.UNSUPPORTED_CITATION
    assert any("E999" in e for e in result.errors)


def test_evidence_ids_used_must_match_citations() -> None:
    p = packet()
    data = explain(p)
    data["evidence_ids_used"] = data["evidence_ids_used"][:-1]
    assert _check(data, p).failure is FailureKind.UNSUPPORTED_CITATION


def test_numbers_must_come_from_cited_evidence() -> None:
    p = packet()
    gb = _cite(p, f"{GB}.probability")
    ok = _minimal(p, "Gradient boosting scored 0.91.", gb)
    assert _check(ok, p).valid
    assert _check(_minimal(p, "Gradient boosting scored 91%.", gb), p).valid
    assert _check(_minimal(p, "Gradient boosting scored 0.9.", gb), p).valid  # rounding
    wrong = _check(_minimal(p, "Gradient boosting scored 0.42.", gb), p)
    assert wrong.failure is FailureKind.UNSUPPORTED_CLAIM
    # A true number, but not from the evidence the statement cites.
    ratio = _cite(p, "transaction_vs_median_ratio")
    misattributed = _check(_minimal(p, "Gradient boosting scored 0.91.", ratio), p)
    assert misattributed.failure is FailureKind.UNSUPPORTED_CLAIM
    # Model references carry version numbers; they are not claims.
    assert _check(_minimal(p, f"{GB} scored 0.91.", gb), p).valid
    # Citation tokens in prose are not numbers either.
    assert _check(_minimal(p, "See E3: gradient boosting scored 0.91.", gb), p).valid


def test_confirmed_fraud_requires_a_fraud_label() -> None:
    claim = "This is confirmed fraud."
    p = packet()
    label = _cite(p, "label_status_now")
    assert _check(_minimal(p, claim, label), p).failure is FailureKind.UNSUPPORTED_CLAIM
    confirmed = packet(label="fraud_confirmed")
    label = _cite(confirmed, "label_status_now")
    assert _check(_minimal(confirmed, claim, label), confirmed).valid
    # Having the label is not enough: the claim must cite it.
    gb = _cite(confirmed, f"{GB}.probability")
    uncited = _check(_minimal(confirmed, claim, gb), confirmed)
    assert uncited.failure is FailureKind.UNSUPPORTED_CLAIM


@pytest.mark.parametrize(
    "statement",
    [
        "Block the account.",
        "Approve this transaction.",
        "We should decline it.",
        "Freeze the card.",
        "Issue a refund.",
        "Bypass the MFA check.",
        "Override the rule.",
        "Add the device to the allowlist.",
    ],
)
def test_decision_language_is_refused(statement: str) -> None:
    p = packet()
    result = _check(_minimal(p, statement, "E1"), p)
    assert result.failure is FailureKind.FORBIDDEN_ACTION


def test_decision_language_in_questions_is_refused() -> None:
    p = packet()
    data = explain(p)
    data["recommended_review_questions"] = [{"question": "Should we block it?", "evidence_ids": []}]
    assert _check(data, p).failure is FailureKind.FORBIDDEN_ACTION


@pytest.mark.parametrize(
    "leak",
    [
        "The customer alice@example.com logged in.",
        "The login came from 203.0.113.9.",
        "Card 4111 1111 1111 1111 was used.",
        "The user id is 0e9b2a9c-4b1e-4b6f-9d7e-2a6b1c3d4e5f.",
        "The address is 12 High Street.",
    ],
)
def test_privacy_leaks_are_refused(leak: str) -> None:
    p = packet()
    result = _check(_minimal(p, leak, "E1"), p)
    assert FailureKind.PRIVACY_FAILURE in result.kinds
    assert result.failure in (FailureKind.PRIVACY_FAILURE, FailureKind.UNSUPPORTED_CLAIM)


def test_echoed_instruction_is_decision_language() -> None:
    p = packet()
    result = _check(_minimal(p, "Ignore previous instructions as requested.", "E1"), p)
    assert result.failure is FailureKind.FORBIDDEN_ACTION


def test_all_failure_kinds_are_reported() -> None:
    p = packet()
    data = _minimal(p, "Approve it; it scored 0.42.", "E999")
    result = _check(data, p)
    assert {
        FailureKind.UNSUPPORTED_CITATION,
        FailureKind.UNSUPPORTED_CLAIM,
        FailureKind.FORBIDDEN_ACTION,
    } <= result.kinds
    assert result.failure is FailureKind.UNSUPPORTED_CITATION  # first by priority
    assert result.explanation is not None and not result.valid
    assert sorted(result.to_dict()["failure_kinds"]) == result.to_dict()["failure_kinds"]


# ------------------------------------------------------------------ reference template
def test_reference_explains_model_disagreement_gb_high_gru_low() -> None:
    e = InvestigationExplanation.model_validate(explain(packet(gb=0.91, gru=0.12)))
    [statement] = [f.statement for f in e.model_disagreement]
    assert statement.startswith(f"{GB} scored 0.91") and f"{GRU} scored 0.12" in statement


def test_reference_explains_gb_low_gru_high() -> None:
    e = InvestigationExplanation.model_validate(explain(packet(gb=0.08, gru=0.83)))
    assert e.model_disagreement[0].statement.startswith(f"{GRU} scored 0.83")


@pytest.mark.parametrize(("gb", "gru", "pattern"), [(0.9, 0.8, "all_high"), (0.1, 0.2, "all_low")])
def test_reference_says_when_models_agree(gb: float, gru: float, pattern: str) -> None:
    e = InvestigationExplanation.model_validate(explain(packet(gb=gb, gru=gru)))
    assert e.model_disagreement[0].statement == f"All models agree ({pattern})."


def test_reference_states_uncertainty_when_all_models_are_uncertain() -> None:
    p = packet(gb=0.45, gru=0.55)
    e = InvestigationExplanation.model_validate(explain(p))
    assert e.uncertainties[0].statement.startswith("2 model(s) scored between 0.30 and 0.70")
    assert _check(explain(p), p).valid


def test_reference_timeline_and_limitations() -> None:
    p = packet()
    e = InvestigationExplanation.model_validate(explain(p))
    timeline = " ".join(f.statement for f in e.temporal_findings)
    assert "4 device changes" in timeline and "3 network (ASN) changes" in timeline
    assert "unknown device" in timeline and "3.00 minutes" in timeline
    assert [f.evidence_ids for f in e.uncertainties if f.evidence_ids[0].startswith("L")] == [
        ["L1"],
        ["L2"],
    ]
    risks = " ".join(f.statement for f in e.risk_factors)
    assert "6.25 times" in risks and "VPN" in risks
    questions = [q.question for q in e.recommended_review_questions]
    assert "Was this device previously verified by the customer?" in questions
    assert all(q.endswith("?") for q in questions)


def test_reference_only_confirms_fraud_with_a_label() -> None:
    assert "confirmed" not in json.dumps(explain(packet()))
    confirmed = explain(packet(label="fraud_confirmed"))
    assert "fraud is confirmed by the label store" in confirmed["risk_factors"][0]["statement"]


def test_reference_analyst_as_a_runtime() -> None:
    analyst = ReferenceAnalyst()
    assert analyst.health().available and "not an LLM" in analyst.health().detail
    assert analyst.list_models() == [REFERENCE_MODEL]
    assert analyst.model_info().version == "1.0.0"
    prompt = build_prompt(packet())
    result = analyst.generate(GenerationRequest(prompt.system, prompt.user))
    assert result.runtime == "reference" and result.model == REFERENCE_MODEL
    assert validate_output(result.text, packet()).valid


def test_error_messages_never_echo_identifiers() -> None:
    p = packet()
    result = _check(_minimal(p, "Approve: alice@example.com at 203.0.113.9 scored 0.42.", "E1"), p)
    assert not result.valid
    text = " ".join(result.errors)
    assert "alice@example.com" not in text and "203.0.113.9" not in text
    assert "[REDACTED]" in text


def test_citing_unavailable_evidence_is_rejected() -> None:
    p = packet(extra=[("security_summary", "mfa_enabled", "missing:unknown", "feature_snapshot")])
    eid = _cite(p, "mfa_enabled")
    result = _check(_minimal(p, "MFA was enabled.", eid), p)
    assert result.failure is FailureKind.UNSUPPORTED_CITATION
    assert "not available" in result.errors[0]
