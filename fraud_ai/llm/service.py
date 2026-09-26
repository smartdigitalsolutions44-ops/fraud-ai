"""The investigation pipeline: stored outputs -> evidence -> local LLM -> validation -> storage.

::

    event -> feature snapshot -> stored model predictions -> sequence findings
          -> evidence packet -> privacy gate -> prompt -> local LLM
          -> output validation -> stored explanation (a new version, never an overwrite)

* **No rescoring.** Evidence comes from stored predictions only (:mod:`fraud_ai.llm.builder`).
* **Privacy gate before generation.** A packet with any violation never reaches the model.
* **Nothing unvalidated is stored.** A failure (runtime down, timeout, invalid JSON, schema,
  privacy, citation, unsupported claim, decision language, over-length) is returned as a
  structured :class:`InvestigationResult` with ``ok = False``. There is no fallback to
  unvalidated prose.
* **Append-only.** Each successful run is a new ``explanation_version`` for the event.
* **Read-only elsewhere.** Nothing here writes to scores, labels, thresholds, rules or
  decisions.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import Investigation
from fraud_ai.llm.builder import build_evidence
from fraud_ai.llm.evidence import EVIDENCE_SCHEMA_VERSION, EvidencePacket, EvidencePrivacyError
from fraud_ai.llm.privacy import scan_packet
from fraud_ai.llm.prompt import PROMPT_VERSION, build_prompt
from fraud_ai.llm.runtime import GenerationRequest, LLMRuntimeError, LocalLLMClient
from fraud_ai.llm.schema import EXPLANATION_SCHEMA_VERSION, InvestigationExplanation
from fraud_ai.llm.validation import MAX_OUTPUT_CHARS, FailureKind, validate_output


class InvestigationNotFoundError(FraudAIError):
    """No stored investigation has that id."""


@dataclass(frozen=True)
class GenerationSettings:
    """Generation parameters, stored with every explanation. Deterministic by default."""

    temperature: float = 0.0
    top_p: float = 1.0
    seed: int = 0
    max_tokens: int = 1200
    context_window: int = 8192
    max_output_chars: int = MAX_OUTPUT_CHARS

    def request(self, system: str, user: str) -> GenerationRequest:
        return GenerationRequest(
            system=system,
            user=user,
            temperature=self.temperature,
            top_p=self.top_p,
            seed=self.seed,
            max_tokens=self.max_tokens,
            context_window=self.context_window,
        )


@dataclass
class InvestigationResult:
    ok: bool
    event_id: uuid.UUID
    runtime: str
    model: str
    failure: FailureKind | None = None
    errors: list[str] = field(default_factory=list)
    packet: EvidencePacket | None = None
    explanation: InvestigationExplanation | None = None
    investigation: Investigation | None = None
    latency_seconds: float | None = None
    output_chars: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    failure_kinds: frozenset[FailureKind] = frozenset()

    def __post_init__(self) -> None:
        if self.failure is not None and not self.failure_kinds:
            self.failure_kinds = frozenset({self.failure})

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "event_id": str(self.event_id),
            "runtime": self.runtime,
            "model": self.model,
            "failure": self.failure.value if self.failure else None,
            "failure_kinds": sorted(k.value for k in self.failure_kinds),
            "errors": self.errors,
            "investigation_id": (
                str(self.investigation.investigation_id) if self.investigation else None
            ),
            "explanation_version": (
                self.investigation.explanation_version if self.investigation else None
            ),
            "evidence_packet_sha256": self.packet.sha256() if self.packet else None,
            "latency_seconds": self.latency_seconds,
            "output_chars": self.output_chars,
        }


def privacy_gate(packet: EvidencePacket) -> None:
    """Raise :class:`EvidencePrivacyError` if the packet may not be sent to a model."""
    violations = scan_packet(packet)
    if violations:
        raise EvidencePrivacyError("; ".join(violations))


def _client_names(client: LocalLLMClient) -> tuple[str, str]:
    return str(getattr(client, "runtime", "unknown")), str(getattr(client, "model", "unknown"))


def generate_explanation(
    packet: EvidencePacket,
    client: LocalLLMClient,
    settings: GenerationSettings,
    event_id: uuid.UUID,
) -> InvestigationResult:
    """Gate, prompt, generate and validate. Stores nothing."""
    runtime, model = _client_names(client)

    def failed(kind: FailureKind, errors: list[str]) -> InvestigationResult:
        return InvestigationResult(False, event_id, runtime, model, kind, errors, packet=packet)

    try:
        privacy_gate(packet)
    except EvidencePrivacyError as exc:
        return failed(FailureKind.PRIVACY_FAILURE, [f"evidence packet refused: {exc}"])
    prompt = build_prompt(packet)
    try:
        generation = client.generate(settings.request(prompt.system, prompt.user))
    except LLMRuntimeError as exc:
        return failed(FailureKind(exc.kind), [str(exc)])
    validation = validate_output(generation.text, packet, settings.max_output_chars)
    return InvestigationResult(
        validation.valid,
        event_id,
        generation.runtime,
        generation.model,
        validation.failure,
        validation.errors,
        packet=packet,
        explanation=validation.explanation if validation.valid else None,
        latency_seconds=generation.latency_seconds,
        output_chars=len(generation.text),
        prompt_tokens=generation.prompt_tokens,
        completion_tokens=generation.completion_tokens,
        failure_kinds=validation.kinds,
    )


def next_version(session: Session, event_id: uuid.UUID) -> int:
    current = session.scalar(
        select(func.max(Investigation.explanation_version)).where(
            Investigation.event_id == event_id
        )
    )
    return int(current or 0) + 1


def investigate(
    session: Session,
    event_id: uuid.UUID,
    client: LocalLLMClient,
    *,
    settings: GenerationSettings | None = None,
    model_refs: list[str] | None = None,
) -> InvestigationResult:
    """Run the full pipeline for one event and store the explanation if (and only if) it is
    valid. Raises :class:`~fraud_ai.llm.evidence.EvidenceError` when the event is unknown or
    has no stored predictions (it is never rescored here)."""
    settings = settings or GenerationSettings()
    try:
        packet = build_evidence(session, event_id, model_refs)
    except ValidationError as exc:  # a value that is not a clean token never becomes evidence
        runtime, model = _client_names(client)
        return InvestigationResult(
            False,
            event_id,
            runtime,
            model,
            FailureKind.PRIVACY_FAILURE,
            [f"evidence refused: {e['msg']}" for e in exc.errors()[:10]],
        )
    result = generate_explanation(packet, client, settings, event_id)
    if not result.ok:
        return result
    assert result.explanation is not None
    try:
        info = client.model_info()
        model_version = info.version
    except LLMRuntimeError:
        model_version = None
    parameters = settings.request("", "").parameters() | {
        "max_output_chars": settings.max_output_chars
    }
    row = Investigation(
        event_id=event_id,
        explanation_version=next_version(session, event_id),
        explanation_text=result.explanation.render(),
        explanation_json=result.explanation.model_dump(mode="json"),
        explanation_schema_version=EXPLANATION_SCHEMA_VERSION,
        evidence_packet=packet.canonical(),
        evidence_packet_sha256=packet.sha256(),
        evidence_schema_version=EVIDENCE_SCHEMA_VERSION,
        prompt_version=PROMPT_VERSION,
        llm_runtime=result.runtime,
        llm_model=result.model,
        llm_model_version=model_version,
        generation_parameters=parameters,
        validation={"valid": True, "failure": None, "errors": []},
        latency_seconds=float(result.latency_seconds or 0.0),
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
    )
    session.add(row)
    session.flush()
    result.investigation = row
    return result


def load_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation:
    row = session.get(Investigation, investigation_id)
    if row is None:
        raise InvestigationNotFoundError(f"no investigation {investigation_id}")
    return row


def list_investigations(session: Session, event_id: uuid.UUID) -> list[Investigation]:
    return list(
        session.scalars(
            select(Investigation)
            .where(Investigation.event_id == event_id)
            .order_by(Investigation.explanation_version)
        )
    )


@dataclass
class RevalidationReport:
    """Re-checks a stored explanation. Read-only: the stored row is never modified."""

    investigation_id: uuid.UUID
    valid: bool
    packet_hash_matches: bool
    packet_privacy_clean: bool
    text_matches_json: bool
    output_validation: dict[str, Any]
    evidence_current: bool | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": str(self.investigation_id),
            "valid": self.valid,
            "packet_hash_matches": self.packet_hash_matches,
            "packet_privacy_clean": self.packet_privacy_clean,
            "text_matches_json": self.text_matches_json,
            "output_validation": self.output_validation,
            "evidence_current": self.evidence_current,
            "notes": self.notes,
        }


def revalidate(
    session: Session, investigation_id: uuid.UUID, *, compare_current: bool = True
) -> RevalidationReport:
    """Re-run every check on a stored explanation against its stored packet.

    With ``compare_current`` the packet is also rebuilt from today's stored outputs. A
    difference (for example a label that arrived later) is reported as ``evidence_current =
    False``; it does not invalidate the explanation, which was faithful to the evidence at
    the time. Run ``investigate`` again to add a new version.
    """
    row = load_investigation(session, investigation_id)
    notes: list[str] = []
    packet = EvidencePacket.from_canonical(row.evidence_packet)
    hash_ok = packet.sha256() == row.evidence_packet_sha256
    if not hash_ok:
        notes.append("stored evidence packet does not match its SHA-256 (tampered or corrupt)")
    violations = scan_packet(packet)
    notes += [f"packet: {v}" for v in violations]
    validation = validate_output(json.dumps(row.explanation_json, sort_keys=True), packet)
    notes += validation.errors
    text_ok = validation.explanation is not None and (
        validation.explanation.render() == row.explanation_text
    )
    if not text_ok:
        notes.append("stored text is not the rendering of the stored JSON")
    current: bool | None = None
    if compare_current:
        refs = sorted({i.name.rsplit(".", 1)[0] for i in packet.section("model_scores")})
        try:
            current = build_evidence(session, row.event_id, refs).sha256() == packet.sha256()
        except (FraudAIError, ValidationError) as exc:
            current = False
            notes.append(f"evidence can no longer be rebuilt: {exc}")
        if current is False and not any(n.startswith("evidence can") for n in notes):
            notes.append(
                "evidence has changed since generation (e.g. a new label); the stored "
                "explanation reflects the evidence at the time"
            )
    return RevalidationReport(
        investigation_id=row.investigation_id,
        valid=hash_ok and not violations and validation.valid and text_ok,
        packet_hash_matches=hash_ok,
        packet_privacy_clean=not violations,
        text_matches_json=text_ok,
        output_validation=validation.to_dict(),
        evidence_current=current,
        notes=notes,
    )
