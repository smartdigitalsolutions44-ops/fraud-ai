"""Configurable risk policy.

The final decision is *never* a bare ``if probability > x: block``. It is a policy
combining a weighted model probability with rule contributions, mapped onto ordered
decision bands, with rules able to impose minimum decisions.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fraud_ai.core.enums import Decision


class RiskPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_version: str = Field(min_length=1, max_length=32)
    ml_weight: float = Field(default=1.0, ge=0.0, le=1.0)
    # Lower bounds (inclusive) of the final score for each decision above ALLOW.
    step_up_threshold: float = Field(ge=0.0, le=1.0)
    review_threshold: float = Field(ge=0.0, le=1.0)
    block_threshold: float = Field(ge=0.0, le=1.0)
    # Decision when no model probability is available (model missing / degraded).
    no_model_decision: Decision = Decision.MANUAL_REVIEW

    @model_validator(mode="after")
    def _ordered(self) -> RiskPolicy:
        if not self.step_up_threshold <= self.review_threshold <= self.block_threshold:
            raise ValueError("thresholds must satisfy step_up <= review <= block")
        return self

    def decision_for(self, score: float) -> Decision:
        if score >= self.block_threshold:
            return Decision.BLOCK
        if score >= self.review_threshold:
            return Decision.MANUAL_REVIEW
        if score >= self.step_up_threshold:
            return Decision.STEP_UP_AUTHENTICATION
        return Decision.ALLOW

    @classmethod
    def from_file(cls, path: Path) -> RiskPolicy:
        return cls.model_validate(json.loads(path.read_text()))
