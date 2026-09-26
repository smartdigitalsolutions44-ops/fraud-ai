"""The model matrix: the *only* way feature data reaches an estimator.

A :class:`ModelMatrix` is built from feature values alone. Identifiers, timestamps, hashes,
labels and label provenance live on the dataset examples, never in the matrix:

* :meth:`ModelMatrix.from_vectors` reads only ``FraudFeatureVector.values/missing``;
* :meth:`ModelMatrix.from_records` (external/tabular input) rejects any column that is not
  a feature of the declared feature version, and any column whose *name* looks like an
  identifier, timestamp, hash or label - unless explicitly approved for that version;
* all rows must share one feature version and the current catalogue fingerprint.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.features.definitions import get_feature_set
from fraud_ai.features.vector import FeatureScalar, FraudFeatureVector, MissingReason

# Column names that must never be model inputs, whatever the feature version says.
FORBIDDEN_COLUMN_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"(^|_)ids?$",  # event_id, user_id, id, ...
        r"(^|_)uuid",
        r"timestamp",
        r"_at$",  # occurred_at, labelled_at, created_at
        r"(^|_)dates?(_|$)",
        r"(^|_)labels?(_|$)",
        r"^y$|^target$|^is_fraud$",
        r"fraud_type",
        r"provenance",
        r"(^|_)hash(_|$)",
        r"(^|_)snapshot(_|$)",
        r"(^|_)status$",
    )
)
# Features explicitly approved despite matching a forbidden pattern, per feature version.
# fraud-features-1.0.0 needs none: it has no raw timestamps (only elapsed durations).
APPROVED_COLUMNS: dict[str, frozenset[str]] = {"fraud-features-1.0.0": frozenset()}


class LeakageError(FraudAIError):
    """Something that is not a point-in-time feature tried to enter the model matrix."""


class FeatureVersionMismatchError(FraudAIError):
    pass


def forbidden_reason(name: str) -> str | None:
    for pattern in FORBIDDEN_COLUMN_PATTERNS:
        if pattern.search(name):
            return pattern.pattern
    return None


def assert_safe_feature_names(names: Iterable[str], feature_version: str) -> None:
    fs = get_feature_set(feature_version)
    known = set(fs.names)
    approved = APPROVED_COLUMNS.get(feature_version, frozenset())
    problems = []
    for name in names:
        if name not in known:
            problems.append(f"{name!r} is not a feature of {feature_version}")
        elif (reason := forbidden_reason(name)) is not None and name not in approved:
            problems.append(f"{name!r} matches forbidden pattern {reason!r}")
    if problems:
        raise LeakageError("; ".join(problems))


@dataclass(frozen=True)
class ModelMatrix:
    feature_version: str
    catalogue_fingerprint: str
    feature_names: tuple[str, ...]
    values: tuple[tuple[FeatureScalar | None, ...], ...]
    missing: tuple[tuple[MissingReason | None, ...], ...]

    def __post_init__(self) -> None:
        fs = get_feature_set(self.feature_version)
        if self.catalogue_fingerprint != fs.fingerprint():
            raise FeatureVersionMismatchError(
                f"catalogue fingerprint {self.catalogue_fingerprint[:12]} does not match "
                f"{self.feature_version} ({fs.fingerprint()[:12]})"
            )
        if self.feature_names != fs.names:
            raise FeatureVersionMismatchError("feature order differs from the feature set")
        assert_safe_feature_names(self.feature_names, self.feature_version)
        if len(self.values) != len(self.missing):
            raise ValueError("values/missing row counts differ")

    def __len__(self) -> int:
        return len(self.values)

    def take(self, indices: Sequence[int]) -> ModelMatrix:
        return ModelMatrix(
            self.feature_version,
            self.catalogue_fingerprint,
            self.feature_names,
            tuple(self.values[i] for i in indices),
            tuple(self.missing[i] for i in indices),
        )

    @classmethod
    def from_vectors(
        cls, vectors: Sequence[FraudFeatureVector], feature_version: str | None = None
    ) -> ModelMatrix:
        versions = {v.feature_version for v in vectors}
        if feature_version is not None:
            versions.add(feature_version)
        if len(versions) != 1:
            raise FeatureVersionMismatchError(f"mixed feature versions: {sorted(versions)}")
        version = versions.pop()
        fs = get_feature_set(version)
        names = fs.names
        return cls(
            feature_version=version,
            catalogue_fingerprint=fs.fingerprint(),
            feature_names=names,
            values=tuple(tuple(v.values.get(n) for n in names) for v in vectors),
            missing=tuple(tuple(v.missing.get(n) for n in names) for v in vectors),
        )

    @classmethod
    def from_records(
        cls, records: Sequence[Mapping[str, Any]], feature_version: str
    ) -> ModelMatrix:
        """Tabular input: each record maps feature name -> value or :class:`MissingReason`."""
        fs = get_feature_set(feature_version)
        names = fs.names
        for record in records:
            extra = set(record) - set(names)
            if extra:
                assert_safe_feature_names(sorted(extra), feature_version)
            if absent := set(names) - set(record):
                raise LeakageError(f"record lacks features: {sorted(absent)[:5]}")
        values, missing = [], []
        for record in records:
            values.append(
                tuple(None if isinstance(record[n], MissingReason) else record[n] for n in names)
            )
            missing.append(
                tuple(record[n] if isinstance(record[n], MissingReason) else None for n in names)
            )
        return cls(feature_version, fs.fingerprint(), names, tuple(values), tuple(missing))
