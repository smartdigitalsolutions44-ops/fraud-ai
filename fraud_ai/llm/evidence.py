"""Structured fraud evidence: the only input the local LLM is allowed to see."""

from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fraud_ai.core.enums import Decision
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.security.redaction import contains_card_number, is_sensitive_key

EvidenceValue = float | int | bool | str | None

# Identifiers that must never be sent to the LLM, even though they may exist in the DB.
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "ip",
        "ip_address",
        "email",
        "phone",
        "name",
        "full_address",
        "address",
        "device_identifier",
        "external_ref",
        "token_reference",
        "card_last4",
    }
)
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.IGNORECASE)


class EvidencePrivacyError(FraudAIError):
    """Raised (not wrapped by pydantic) when evidence would expose identifying data."""


class EvidencePacket(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    ml_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    decision: Decision
    policy_version: str
    model_name: str | None = None
    model_version: str | None = None
    signals: dict[str, EvidenceValue] = Field(default_factory=dict)
    historical: dict[str, EvidenceValue] = Field(default_factory=dict)
    triggered_rules: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _privacy(self) -> EvidencePacket:
        for section in (self.signals, self.historical):
            for key, value in section.items():
                if key.lower() in _FORBIDDEN_EVIDENCE_KEYS or is_sensitive_key(key):
                    raise EvidencePrivacyError(f"evidence key {key!r} is not allowed")
                if isinstance(value, str) and _looks_identifying(value):
                    raise EvidencePrivacyError(f"evidence value for {key!r} looks identifying")
        return self

    def render(self) -> str:
        """Deterministic plain-text rendering used as the LLM's evidence block."""
        lines = [f"Risk score: {self.risk_score:.2f}"]
        if self.ml_probability is not None:
            lines.append(f"Model probability: {self.ml_probability:.2f}")
        lines.append("Signals:")
        lines += [f"  {k} = {_fmt(v)}" for k, v in sorted(self.signals.items())]
        lines.append("Historical behaviour:")
        lines += [f"  {k} = {_fmt(v)}" for k, v in sorted(self.historical.items())]
        if self.triggered_rules:
            lines.append(f"Triggered rules: {', '.join(self.triggered_rules)}")
        lines.append(f"Decision: {self.decision.value}")
        return "\n".join(lines)


def _looks_identifying(value: str) -> bool:
    if contains_card_number(value) or _EMAIL.search(value):
        return True
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _fmt(value: EvidenceValue) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)
