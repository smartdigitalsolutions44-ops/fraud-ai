"""Versioned risk policies (``risk-policy-schema-1.0.0``).

A policy is the *complete*, immutable configuration of a decision:

* **the model set:**
  * the primary classifier;
  * an optional secondary classifier, sequence model and anomaly signal;
  * each pinned to its artefact SHA-256, with the calibration it uses embedded;
* **decision bands** on the calibrated primary score. Each band carries a risk level and a
  decision;
* **the rule set:** its version and fingerprint, and the minimum decision per rule
  severity;
* **escalations:** for secondary/sequence disagreement, for anomaly signals and for late
  events;
* **fallbacks:** one per failure category. None may be ``ALLOW`` or
  ``ALLOW_WITH_MONITORING``, so a failure never silently allows.

The definition is hashed (``sha256()``). Stored policies are verified against the hash
every time they are loaded, so an active policy cannot be modified silently. A change is
always a new version.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fraud_ai.core.enums import Decision, RuleSeverity

POLICY_SCHEMA_VERSION = "risk-policy-schema-1.0.0"
VERSION_PATTERN = r"^risk-policy-[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$"
MODEL_REF_PATTERN = r"^[a-z][a-z0-9-]*-[0-9]+\.[0-9]+\.[0-9]+$"
RISK_LEVELS = ("very_low", "moderate", "elevated", "high", "extreme")
UNKNOWN_RISK = "unknown"


class FailureCategory(StrEnum):
    """Every failure the hot path handles explicitly."""

    POLICY_UNAVAILABLE = "policy_unavailable"
    FEATURE_EXTRACTION_FAILED = "feature_extraction_failed"
    SEQUENCE_EXTRACTION_FAILED = "sequence_extraction_failed"
    PRIMARY_MODEL_UNAVAILABLE = "primary_model_unavailable"
    PRIMARY_ARTIFACT_INVALID = "primary_artifact_invalid"
    CALIBRATION_UNAVAILABLE = "calibration_unavailable"
    SECONDARY_MODEL_FAILED = "secondary_model_failed"
    SEQUENCE_MODEL_FAILED = "sequence_model_failed"
    ANOMALY_MODEL_FAILED = "anomaly_model_failed"
    RULES_FAILED = "rules_failed"
    INFORMATION_CUTOFF_VIOLATED = "information_cutoff_violated"
    DATABASE_UNAVAILABLE = "database_unavailable"
    EVENT_REJECTED = "event_rejected"


#: Failures that leave no trustworthy primary score: the fallback *is* the decision.
BLOCKING_FAILURES = frozenset(
    {
        FailureCategory.POLICY_UNAVAILABLE,
        FailureCategory.FEATURE_EXTRACTION_FAILED,
        FailureCategory.PRIMARY_MODEL_UNAVAILABLE,
        FailureCategory.PRIMARY_ARTIFACT_INVALID,
        FailureCategory.CALIBRATION_UNAVAILABLE,
        FailureCategory.INFORMATION_CUTOFF_VIOLATED,
        FailureCategory.DATABASE_UNAVAILABLE,
        FailureCategory.EVENT_REJECTED,
    }
)
#: Used when there is no policy at all (or it cannot be trusted).
SYSTEM_FALLBACK = Decision.MANUAL_REVIEW

DEFAULT_FALLBACKS: dict[FailureCategory, Decision] = {
    FailureCategory.POLICY_UNAVAILABLE: Decision.MANUAL_REVIEW,
    FailureCategory.FEATURE_EXTRACTION_FAILED: Decision.MANUAL_REVIEW,
    FailureCategory.SEQUENCE_EXTRACTION_FAILED: Decision.STEP_UP_AUTHENTICATION,
    FailureCategory.PRIMARY_MODEL_UNAVAILABLE: Decision.MANUAL_REVIEW,
    FailureCategory.PRIMARY_ARTIFACT_INVALID: Decision.MANUAL_REVIEW,
    FailureCategory.CALIBRATION_UNAVAILABLE: Decision.MANUAL_REVIEW,
    FailureCategory.SECONDARY_MODEL_FAILED: Decision.STEP_UP_AUTHENTICATION,
    FailureCategory.SEQUENCE_MODEL_FAILED: Decision.STEP_UP_AUTHENTICATION,
    FailureCategory.ANOMALY_MODEL_FAILED: Decision.STEP_UP_AUTHENTICATION,
    FailureCategory.RULES_FAILED: Decision.MANUAL_REVIEW,
    FailureCategory.INFORMATION_CUTOFF_VIOLATED: Decision.MANUAL_REVIEW,
    FailureCategory.DATABASE_UNAVAILABLE: Decision.MANUAL_REVIEW,
    FailureCategory.EVENT_REJECTED: Decision.MANUAL_REVIEW,
}
DEFAULT_SEVERITY_MINIMUM: dict[RuleSeverity, Decision] = {
    RuleSeverity.LOW: Decision.ALLOW_WITH_MONITORING,
    RuleSeverity.MEDIUM: Decision.STEP_UP_AUTHENTICATION,
    RuleSeverity.HIGH: Decision.MANUAL_REVIEW,
    RuleSeverity.CRITICAL: Decision.MANUAL_REVIEW,
}


class CalibrationSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    calibration_id: str
    method: str = Field(pattern=r"^(sigmoid|isotonic)$")
    parameters: dict[str, Any]


class ModelSlot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ref: str = Field(pattern=MODEL_REF_PATTERN)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    threshold: float = Field(ge=0.0, le=1.0)
    calibration: CalibrationSpec | None = None


class Band(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    lower: float = Field(ge=0.0, le=1.0)
    risk_level: str
    decision: Decision

    @field_validator("risk_level")
    @classmethod
    def _level(cls, value: str) -> str:
        if value not in RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {RISK_LEVELS}")
        return value


class RiskPolicyDefinition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = POLICY_SCHEMA_VERSION
    policy_version: str = Field(pattern=VERSION_PATTERN, max_length=32)
    description: str = Field(default="", max_length=500)
    primary: ModelSlot
    secondary: ModelSlot | None = None
    sequence: ModelSlot | None = None
    anomaly: ModelSlot | None = None
    bands: tuple[Band, ...]
    rules_version: str
    rules_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    severity_minimum: dict[RuleSeverity, Decision] = Field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_MINIMUM)
    )
    secondary_escalation: Decision = Decision.ALLOW_WITH_MONITORING
    anomaly_escalation: Decision = Decision.ALLOW_WITH_MONITORING
    late_event_seconds: float = Field(default=900.0, gt=0)
    late_event_minimum: Decision = Decision.ALLOW_WITH_MONITORING
    #: A temporary block needs more than one model score: a matched rule of at least
    #: medium severity, or a flagging secondary/sequence model. Otherwise it is reviewed.
    block_requires_corroboration: bool = True
    temporary_block_hours: int = Field(default=24, ge=1, le=168)
    monitoring_hours: int = Field(default=72, ge=1, le=720)
    fallbacks: dict[FailureCategory, Decision] = Field(
        default_factory=lambda: dict(DEFAULT_FALLBACKS)
    )
    decision_event_kinds: tuple[str, ...] = ("transaction",)
    synthetic_derived: bool = True

    @model_validator(mode="after")
    def _consistent(self) -> RiskPolicyDefinition:
        if self.schema_version != POLICY_SCHEMA_VERSION:
            raise ValueError(f"unsupported policy schema {self.schema_version!r}")
        if self.primary.calibration is None:
            raise ValueError("the primary model needs a calibration: bands are calibrated")
        if not self.bands or self.bands[0].lower != 0.0:
            raise ValueError("bands must start at 0.0")
        lowers = [b.lower for b in self.bands]
        if lowers != sorted(set(lowers)):
            raise ValueError("band lower bounds must be strictly increasing")
        severities = [b.decision.severity for b in self.bands]
        if severities != sorted(severities):
            raise ValueError("band decisions must never become less restrictive as risk rises")
        levels = [RISK_LEVELS.index(b.risk_level) for b in self.bands]
        if levels != sorted(set(levels)):
            raise ValueError("band risk levels must be distinct and increasing")
        missing = set(FailureCategory) - set(self.fallbacks)
        if missing:
            raise ValueError(f"fallbacks missing for {sorted(m.value for m in missing)}")
        unsafe = [
            f.value
            for f, d in self.fallbacks.items()
            if d.severity < Decision.STEP_UP_AUTHENTICATION.severity
        ]
        if unsafe:
            raise ValueError(f"a failure must never allow; unsafe fallbacks: {sorted(unsafe)}")
        if set(self.severity_minimum) != set(RuleSeverity):
            raise ValueError("severity_minimum must cover every rule severity")
        if not self.decision_event_kinds or not set(self.decision_event_kinds) <= {
            "transaction",
            "login",
        }:
            raise ValueError("decision_event_kinds must be a subset of {transaction, login}")
        return self

    def slots(self) -> dict[str, ModelSlot]:
        out = {"primary": self.primary}
        for role in ("secondary", "sequence", "anomaly"):
            slot = getattr(self, role)
            if slot is not None:
                out[role] = slot
        return out

    def canonical_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    def band_for(self, score: float) -> Band:
        band = self.bands[0]
        for candidate in self.bands:
            if score >= candidate.lower:
                band = candidate
        return band
