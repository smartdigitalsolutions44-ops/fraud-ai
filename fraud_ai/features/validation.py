"""Feature-vector validation.

Rejects: unknown or missing features, NaN/infinite numbers, wrong types, values outside
declared bounds (negative ages and counts, probabilities outside [0, 1]), unknown
categories, missing values without a reason (or with a reason for a non-nullable feature),
features populated for event kinds they do not apply to, invalid timestamps, and
internally impossible combinations (e.g. more failed logins in 5 minutes than in 1 hour).
"""

from __future__ import annotations

import itertools
import math
from typing import TYPE_CHECKING

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.features.definitions import FeatureDefinition, FeatureType, get_feature_set

if TYPE_CHECKING:
    from fraud_ai.features.vector import FeatureScalar, FraudFeatureVector


class FeatureValidationError(FraudAIError):
    """Raised directly (not wrapped by pydantic) so callers see the full problem list."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


# Monotone window chains: a shorter window can never hold more than a longer one.
_MONOTONE_CHAINS: tuple[tuple[str, ...], ...] = (
    (
        "logins_last_5m",
        "logins_last_15m",
        "logins_last_1h",
        "logins_last_24h",
        "logins_last_7d",
        "logins_last_30d",
    ),
    ("failed_logins_last_5m", "failed_logins_last_15m", "failed_logins_last_1h"),
    (
        "transactions_last_5m",
        "transactions_last_1h",
        "transactions_last_24h",
        "transactions_last_7d",
        "transactions_last_30d",
    ),
)
# (part, whole): part <= whole.
_PART_OF: tuple[tuple[str, str], ...] = (
    ("successful_logins_last_1h", "logins_last_1h"),
    ("failed_logins_last_1h", "logins_last_1h"),
    ("successful_logins_last_1h", "successful_logins_total"),
    ("failed_logins_last_1h", "failed_logins_total"),
    ("successful_orders_to_address", "orders_to_address"),
    ("failed_orders_to_address", "orders_to_address"),
    ("accounts_seen_on_device_last_24h", "accounts_seen_on_device"),
    ("failed_logins_from_network_last_1h", "failed_logins_from_network"),
    ("accounts_per_device", "accounts_seen_on_device"),
)
_FLAG_OF_COUNT = (
    ("shared_device_flag", "accounts_per_device"),
    ("shared_network_flag", "accounts_per_network"),
)


def _check_value(defn: FeatureDefinition, value: FeatureScalar) -> str | None:
    name = defn.name
    if defn.dtype is FeatureType.BOOLEAN:
        return None if isinstance(value, bool) else f"{name}: expected boolean"
    if defn.dtype is FeatureType.CATEGORICAL:
        if not isinstance(value, str) or not value or len(value) > 32:
            return f"{name}: expected a non-empty category string"
        if defn.allowed_values is not None and value not in defn.allowed_values:
            return f"{name}: unknown category {value!r}"
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        return f"{name}: expected {defn.dtype.value}"
    if defn.dtype is FeatureType.INTEGER and not isinstance(value, int):
        return f"{name}: expected integer"
    if isinstance(value, float) and not math.isfinite(value):
        return f"{name}: non-finite value"
    if defn.min_value is not None and value < defn.min_value:
        return f"{name}: {value} below minimum {defn.min_value}"
    if defn.max_value is not None and value > defn.max_value:
        return f"{name}: {value} above maximum {defn.max_value}"
    return None


def validate_vector(vector: FraudFeatureVector) -> None:
    from fraud_ai.features.vector import MissingReason

    problems: list[str] = []
    try:
        fs = get_feature_set(vector.feature_version)
    except KeyError as exc:
        raise FeatureValidationError([str(exc)]) from None

    if vector.as_of_timestamp < vector.event_timestamp:
        problems.append("as_of_timestamp precedes the event timestamp")

    names = set(fs.names)
    present, missing = set(vector.values), set(vector.missing)
    if present & missing:
        problems.append(f"features both present and missing: {sorted(present & missing)}")
    if unknown := (present | missing) - names:
        problems.append(f"unknown features: {sorted(unknown)}")
    if absent := names - present - missing:
        problems.append(f"features not assigned: {sorted(absent)}")

    for defn in fs.definitions:
        applicable = vector.event_kind in defn.applies_to
        if defn.name in vector.values:
            if not applicable:
                problems.append(f"{defn.name}: populated for a {vector.event_kind} event")
            elif (err := _check_value(defn, vector.values[defn.name])) is not None:
                problems.append(err)
        elif defn.name in vector.missing:
            reason = vector.missing[defn.name]
            if not applicable and reason is not MissingReason.NOT_APPLICABLE:
                problems.append(f"{defn.name}: must be not_applicable for {vector.event_kind}")
            elif applicable and not defn.nullable:
                problems.append(f"{defn.name}: is not nullable")

    def num(name: str) -> float | None:
        value = vector.values.get(name)
        return (
            float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None
        )

    for chain in _MONOTONE_CHAINS:
        seen = [(n, num(n)) for n in chain if num(n) is not None]
        for (a, va), (b, vb) in itertools.pairwise(seen):
            if va is not None and vb is not None and va > vb:
                problems.append(f"impossible counts: {a}={va} > {b}={vb}")
    for part, whole in _PART_OF:
        vp, vw = num(part), num(whole)
        if vp is not None and vw is not None and vp > vw:
            problems.append(f"impossible counts: {part}={vp} > {whole}={vw}")
    for flag, count in _FLAG_OF_COUNT:
        f, c = vector.values.get(flag), num(count)
        if isinstance(f, bool) and c is not None and f != (c >= 1):
            problems.append(f"{flag} inconsistent with {count}")

    if problems:
        raise FeatureValidationError(problems)
