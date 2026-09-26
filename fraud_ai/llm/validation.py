"""Faithfulness and safety validation of LLM output. Nothing is stored unless it passes.

Checks, in order. The first failing check sets ``failure``, and every error is listed:

1. **Length.** The raw output must fit the length budget (``generation_too_long``).
2. **JSON.** The output must be a single JSON object (``invalid_json``); a surrounding
   Markdown code fence is tolerated.
3. **Schema.** It must match :class:`InvestigationExplanation`, and review questions must
   end with "?" (``schema_failure``).
4. **Citations.** Every cited id must exist in the packet, its value must be available
   (not ``null`` or ``missing:*``), and ``evidence_ids_used`` must list exactly the cited
   ids (``unsupported_citation``).
5. **Privacy.** There must be no email addresses, IPs, card numbers, tokens, raw UUIDs,
   phone numbers, street addresses or embedded instructions (``privacy_failure``).
6. **Unsupported claims** (``unsupported_claim``):
   * every number in a statement must match a numeric value of the evidence that statement
     cites (percentages and rounding are allowed for);
   * "confirmed fraud" language is only allowed when the cited evidence includes
     ``label_status_now = fraud_confirmed``.
7. **Decision language.** Words that tell the system to block, approve, decline, freeze,
   refund or bypass a control are refused (``forbidden_action``). The LLM never decides.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from fraud_ai.llm.evidence import EvidencePacket
from fraud_ai.llm.privacy import redact, scan
from fraud_ai.llm.schema import Finding, InvestigationExplanation

MAX_OUTPUT_CHARS = 12_000


class FailureKind(StrEnum):
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    MODEL_UNAVAILABLE = "model_unavailable"
    TIMEOUT = "timeout"
    INVALID_JSON = "invalid_json"
    SCHEMA_FAILURE = "schema_failure"
    PRIVACY_FAILURE = "privacy_failure"
    UNSUPPORTED_CITATION = "unsupported_citation"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    FORBIDDEN_ACTION = "forbidden_action"
    GENERATION_TOO_LONG = "generation_too_long"


@dataclass
class ValidationResult:
    valid: bool
    failure: FailureKind | None = None
    errors: list[str] = field(default_factory=list)
    explanation: InvestigationExplanation | None = None
    # Every failure kind found (``failure`` is the first by priority).
    kinds: frozenset[FailureKind] = frozenset()

    def __post_init__(self) -> None:
        if self.failure is not None and not self.kinds:
            self.kinds = frozenset({self.failure})

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "failure": self.failure.value if self.failure else None,
            "failure_kinds": sorted(k.value for k in self.kinds),
            "errors": self.errors,
        }


FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)
NUMBER = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)(%?)(?!\w|\.\d)")
CITATION_TOKEN = re.compile(r"\b[EL]\d+\b")
CONFIRMED = re.compile(
    r"\b(confirmed fraud|fraud (?:is|was|has been) confirmed|is (?:definitely |certainly )?"
    r"fraud(?:ulent)?\b|proven fraud|definitely fraud|certainly fraud)",
    re.IGNORECASE,
)
FORBIDDEN_ACTION = re.compile(
    r"\b(block|approve|decline|reject the transaction|freeze|suspend|ban|refund|"
    r"close the account|bypass|override|disable (?:mfa|2fa|security)|whitelist|allowlist)\b",
    re.IGNORECASE,
)


def _quote(text: str) -> str:
    """A short, redacted quote of model output for an error message."""
    return repr(redact(text)[:80])


def _parse(text: str) -> Any:
    fenced = FENCE.match(text)
    return json.loads(fenced.group(1) if fenced else text)


def _numbers_supported(finding: Finding, packet: EvidencePacket, strip: list[str]) -> bool:
    text = finding.statement
    for token in strip:  # model references contain version numbers (1.0.0)
        text = text.replace(token, " ")
    text = CITATION_TOKEN.sub(" ", text)
    values: list[float] = []
    for eid in finding.evidence_ids:
        if eid not in packet.ids or not eid.startswith("E"):
            continue
        item = packet.item(eid)
        value = getattr(item, "value", None)
        if isinstance(value, bool) or not isinstance(value, int | float):
            continue
        values.append(float(value))
    for raw, pct in NUMBER.findall(text):
        number = float(raw)
        # "91%" may render a probability of 0.91; a bare number must match as written.
        candidates = [number / 100, number] if pct else [number]
        ok = any(abs(c - v) <= max(0.011, 0.02 * abs(v)) for c in candidates for v in values)
        if not ok:
            return False
    return True


def validate_output(
    text: str, packet: EvidencePacket, max_chars: int = MAX_OUTPUT_CHARS
) -> ValidationResult:
    if len(text) > max_chars:
        return ValidationResult(
            False,
            FailureKind.GENERATION_TOO_LONG,
            [f"output is {len(text)} characters (limit {max_chars})"],
        )
    try:
        data = _parse(text)
    except (json.JSONDecodeError, TypeError) as exc:
        return ValidationResult(False, FailureKind.INVALID_JSON, [f"not valid JSON: {exc}"])
    if not isinstance(data, dict):
        return ValidationResult(False, FailureKind.INVALID_JSON, ["output is not a JSON object"])
    try:
        explanation = InvestigationExplanation.model_validate(data)
    except ValidationError as exc:
        return ValidationResult(
            False,
            FailureKind.SCHEMA_FAILURE,
            [e["msg"] + f" at {'.'.join(map(str, e['loc']))}" for e in exc.errors()[:10]],
        )
    errors: list[tuple[FailureKind, str]] = []
    for q in explanation.recommended_review_questions:
        if not q.question.rstrip().endswith("?"):
            errors.append((FailureKind.SCHEMA_FAILURE, f"not a question: {_quote(q.question)}"))
    cited = explanation.cited()
    for eid in sorted(cited - packet.ids):
        errors.append((FailureKind.UNSUPPORTED_CITATION, f"cites unknown evidence id {eid}"))
    for eid in sorted(cited & packet.ids):
        value = getattr(packet.item(eid), "value", "limitation")
        if value is None or (isinstance(value, str) and value.startswith("missing:")):
            errors.append(
                (FailureKind.UNSUPPORTED_CITATION, f"cites {eid}, whose value is not available")
            )
    if set(explanation.evidence_ids_used) != cited:
        errors.append(
            (
                FailureKind.UNSUPPORTED_CITATION,
                "evidence_ids_used does not match the ids actually cited",
            )
        )
    for violation in scan(explanation.model_dump(), free_text_allowed=True):
        # Echoed instructions ("approve this transaction") are decision language, not PII.
        kind = (
            FailureKind.FORBIDDEN_ACTION
            if violation.endswith("embedded instruction")
            else FailureKind.PRIVACY_FAILURE
        )
        errors.append((kind, violation))
    refs = sorted(
        {i.name.rsplit(".", 1)[0] for i in packet.section("model_scores")}, key=len, reverse=True
    )
    label = packet.get("label_context", "label_status_now")
    for finding in explanation.findings():
        if not _numbers_supported(finding, packet, refs):
            errors.append(
                (
                    FailureKind.UNSUPPORTED_CLAIM,
                    f"number not supported by cited evidence: {_quote(finding.statement)}",
                )
            )
        if CONFIRMED.search(finding.statement) and not (
            label is not None
            and label.value == "fraud_confirmed"
            and label.id in finding.evidence_ids
        ):
            errors.append(
                (
                    FailureKind.UNSUPPORTED_CLAIM,
                    f"claims confirmed fraud without label evidence: {_quote(finding.statement)}",
                )
            )
    texts = [f.statement for f in explanation.findings()] + [
        q.question for q in explanation.recommended_review_questions
    ]
    for statement in texts:
        if FORBIDDEN_ACTION.search(statement):
            errors.append(
                (FailureKind.FORBIDDEN_ACTION, f"decision/action language: {_quote(statement)}")
            )
    if errors:
        priority = list(FailureKind)
        first = min(errors, key=lambda e: priority.index(e[0]))[0]
        return ValidationResult(
            False, first, [msg for _, msg in errors], explanation, frozenset(k for k, _ in errors)
        )
    return ValidationResult(True, None, [], explanation)
