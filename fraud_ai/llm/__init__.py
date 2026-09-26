"""Local, offline analyst assistance (Stage 7).

The LLM **explains** stored system outputs to a human analyst. It is not the classifier,
the risk engine, the rules engine, the authentication system or the decision maker: it never
changes a score, label, threshold, rule or decision, and it never blocks or approves.

Pipeline (:mod:`fraud_ai.llm.service`): stored predictions and features -> privacy-checked
:class:`EvidencePacket` -> versioned prompt -> local runtime -> validated, cited
:class:`InvestigationExplanation` -> append-only ``investigations`` row.
"""

from fraud_ai.llm.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceError,
    EvidencePacket,
    EvidencePrivacyError,
)
from fraud_ai.llm.prompt import PROMPT_VERSION
from fraud_ai.llm.runtime import LocalLLMClient, make_client
from fraud_ai.llm.schema import EXPLANATION_SCHEMA_VERSION, InvestigationExplanation
from fraud_ai.llm.service import GenerationSettings, InvestigationResult, investigate, revalidate
from fraud_ai.llm.validation import FailureKind, ValidationResult, validate_output

__all__ = [
    "EVIDENCE_SCHEMA_VERSION",
    "EXPLANATION_SCHEMA_VERSION",
    "PROMPT_VERSION",
    "EvidenceError",
    "EvidencePacket",
    "EvidencePrivacyError",
    "FailureKind",
    "GenerationSettings",
    "InvestigationExplanation",
    "InvestigationResult",
    "LocalLLMClient",
    "ValidationResult",
    "investigate",
    "make_client",
    "revalidate",
    "validate_output",
]
