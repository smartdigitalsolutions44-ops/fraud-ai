"""Local offline LLM layer (Stage 7) - interfaces only.

The LLM explains decisions and assists analysts. It is never the fraud classifier and its
output never replaces the numerical risk score. It receives only structured, minimised
evidence (:class:`EvidencePacket`), never raw personal data.
"""

from fraud_ai.llm.evidence import EvidencePacket, EvidencePrivacyError
from fraud_ai.llm.provider import Explanation, ExplanationProvider

__all__ = ["EvidencePacket", "EvidencePrivacyError", "Explanation", "ExplanationProvider"]
