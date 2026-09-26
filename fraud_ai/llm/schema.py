"""The only accepted LLM output: a validated :class:`InvestigationExplanation`.

Every factual statement is a :class:`Finding` that cites evidence ids (``E…``) and/or
limitation ids (``L…``). Review questions are questions: they never instruct the system to
block, approve or change anything.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

EXPLANATION_SCHEMA_VERSION = "investigation-explanation-1.0.0"
CITATION = r"^[EL][1-9][0-9]*$"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    statement: str = Field(min_length=1, max_length=400)
    evidence_ids: list[str] = Field(min_length=1, max_length=12)


class ReviewQuestion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    question: str = Field(min_length=1, max_length=240)
    evidence_ids: list[str] = Field(default_factory=list, max_length=12)


class InvestigationExplanation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: Finding
    risk_factors: list[Finding] = Field(default_factory=list, max_length=10)
    protective_factors: list[Finding] = Field(default_factory=list, max_length=10)
    model_disagreement: list[Finding] = Field(default_factory=list, max_length=6)
    temporal_findings: list[Finding] = Field(default_factory=list, max_length=6)
    uncertainties: list[Finding] = Field(default_factory=list, max_length=6)
    recommended_review_questions: list[ReviewQuestion] = Field(default_factory=list, max_length=8)
    evidence_ids_used: list[str] = Field(default_factory=list)

    def findings(self) -> list[Finding]:
        return [
            self.summary,
            *self.risk_factors,
            *self.protective_factors,
            *self.model_disagreement,
            *self.temporal_findings,
            *self.uncertainties,
        ]

    def cited(self) -> set[str]:
        ids = {i for f in self.findings() for i in f.evidence_ids}
        return ids | {i for q in self.recommended_review_questions for i in q.evidence_ids}

    def render(self) -> str:
        """Deterministic plain-text rendering for analysts (the JSON stays primary)."""

        def block(title: str, items: list[Finding]) -> list[str]:
            return (
                [f"{title}:"] + [f"  - {f.statement} [{', '.join(f.evidence_ids)}]" for f in items]
                if items
                else []
            )

        lines = [f"Summary: {self.summary.statement} [{', '.join(self.summary.evidence_ids)}]"]
        lines += block("Risk factors", self.risk_factors)
        lines += block("Protective factors", self.protective_factors)
        lines += block("Model disagreement", self.model_disagreement)
        lines += block("Timeline", self.temporal_findings)
        lines += block("Uncertainties", self.uncertainties)
        if self.recommended_review_questions:
            lines.append("Questions for the analyst:")
            lines += [f"  - {q.question}" for q in self.recommended_review_questions]
        lines.append(
            "This explanation is decision support only; it does not change any score or decision."
        )
        return "\n".join(lines)


def json_schema() -> dict[str, Any]:
    return InvestigationExplanation.model_json_schema()
