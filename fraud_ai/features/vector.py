"""The canonical fraud feature vector.

A :class:`FraudFeatureVector` is typed by its feature set: every value is checked against
the :class:`~fraud_ai.features.definitions.FeatureDefinition` of the same name (type,
bounds, allowed categories, applicability) when the vector is constructed, so an invalid
vector cannot exist.

Missing data is explicit. A feature is either present in ``values`` (a real observation -
including a genuine ``0`` or ``False``) or present in ``missing`` with a
:class:`MissingReason`. Sentinel numbers such as ``-1`` or ``999`` are never used; ML
preprocessing (Stage 3) decides how each reason is encoded.

Only ``feature_version``, ``values`` and ``missing`` are hashed. Identifiers, timestamps
and generation metadata are context, so two events with identical features hash equally
and a recomputation never differs because of wall-clock time.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from fraud_ai.features.definitions import EventKind, get_feature_set
from fraud_ai.utils.time import ensure_utc

FeatureScalar = bool | int | float | str


class MissingReason(StrEnum):
    UNKNOWN = "unknown"  # the source could not tell us (e.g. intel gave no verdict)
    NOT_OBSERVED = "not_observed"  # nothing in history to compute from yet
    NOT_APPLICABLE = "not_applicable"  # the feature does not apply to this event


FLOAT_DECIMALS = 6


def canonical_float(value: float) -> float:
    """Fixed precision so the same inputs hash identically on every platform/backend."""
    rounded = round(float(value), FLOAT_DECIMALS)
    return 0.0 if rounded == 0 else rounded  # normalise -0.0


class FraudFeatureVector(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    feature_version: str
    event_id: uuid.UUID
    event_kind: EventKind
    event_timestamp: AwareDatetime
    as_of_timestamp: AwareDatetime
    user_id: uuid.UUID | None = None
    transaction_id: uuid.UUID | None = None
    login_event_id: uuid.UUID | None = None
    source_event_count: int = Field(ge=0)
    values: dict[str, FeatureScalar]
    missing: dict[str, MissingReason]

    @field_validator("event_timestamp", "as_of_timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _validate(self) -> FraudFeatureVector:
        from fraud_ai.features.validation import validate_vector

        validate_vector(self)
        return self

    # ------------------------------------------------------------------ access
    def get(self, name: str) -> FeatureScalar | None:
        if name in self.values:
            return self.values[name]
        if name in self.missing:
            return None
        raise KeyError(name)

    def is_missing(self, name: str) -> bool:
        self.get(name)
        return name in self.missing

    def ordered_values(self) -> list[FeatureScalar | None]:
        """Values in feature-set order; ``None`` where missing (no imputation)."""
        return [self.get(n) for n in get_feature_set(self.feature_version).names]

    # ------------------------------------------------------------------ canonical form
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "feature_version": self.feature_version,
            "values": dict(sorted(self.values.items())),
            "missing": {k: v.value for k, v in sorted(self.missing.items())},
        }

    def canonical_json(self) -> str:
        return canonical_json(self.canonical_payload())

    @property
    def feature_hash(self) -> str:
        return hash_payload(self.canonical_payload())


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


class FeatureWriter:
    """Collects values/missing reasons while features are computed, enforcing names."""

    def __init__(self, feature_version: str) -> None:
        self.feature_version = feature_version
        self._names = set(get_feature_set(feature_version).names)
        self.values: dict[str, FeatureScalar] = {}
        self.missing: dict[str, MissingReason] = {}

    def _check(self, name: str) -> None:
        if name not in self._names:
            raise KeyError(f"unknown feature {name!r}")
        if name in self.values or name in self.missing:
            raise ValueError(f"feature {name!r} assigned twice")

    def put(self, name: str, value: FeatureScalar) -> None:
        self._check(name)
        if isinstance(value, float):
            value = canonical_float(value)
        self.values[name] = value

    def miss(self, name: str, reason: MissingReason) -> None:
        self._check(name)
        self.missing[name] = reason

    def put_or_miss(self, name: str, value: FeatureScalar | None, reason: MissingReason) -> None:
        if value is None:
            self.miss(name, reason)
        else:
            self.put(name, value)

    def miss_all(self, names: list[str] | tuple[str, ...], reason: MissingReason) -> None:
        for name in names:
            self.miss(name, reason)

    def unassigned(self) -> set[str]:
        return self._names - set(self.values) - set(self.missing)
