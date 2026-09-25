"""Protocol for a local explanation provider (e.g. an Ollama or llama.cpp runtime).

No implementation ships in Stage 1: there is no fake client. A Stage 7 implementation must
talk only to the endpoint configured in LOCAL_LLM_ENDPOINT (validated as local/private).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from fraud_ai.llm.evidence import EvidencePacket


@dataclass(frozen=True)
class Explanation:
    text: str
    model: str
    # The score the explanation refers to - copied, never produced, by the LLM.
    risk_score: float


@runtime_checkable
class ExplanationProvider(Protocol):
    def explain(self, evidence: EvidencePacket) -> Explanation: ...
