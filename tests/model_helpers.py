"""Hand-built feature vectors for model-layer unit tests (no database needed)."""

from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fraud_ai.features.definitions import EventKind, FeatureType, get_feature_set
from fraud_ai.features.vector import FraudFeatureVector, MissingReason

FS = get_feature_set()
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def make_vector(
    overrides: dict[str, Any] | None = None,
    *,
    kind: EventKind = EventKind.TRANSACTION,
    at: datetime = T0,
    seed: int = 0,
) -> FraudFeatureVector:
    """A valid vector: plausible defaults, a few random numeric values, all else missing."""
    rng = random.Random(seed)
    values: dict[str, Any] = {"event_kind": kind.value, "authenticated_user": True}
    missing: dict[str, MissingReason] = {}
    overrides = overrides or {}
    for d in FS.definitions:
        if d.name in values:
            continue
        if kind not in d.applies_to:
            missing[d.name] = MissingReason.NOT_APPLICABLE
        elif d.name in overrides:
            continue
        elif d.dtype is FeatureType.INTEGER and d.max_value is None and "last" not in d.name:
            values[d.name] = rng.randint(0, 5)
        else:
            missing[d.name] = (
                rng.choice(list(MissingReason)) if d.nullable else MissingReason.UNKNOWN
            )
    for name, value in overrides.items():
        missing.pop(name, None)
        if isinstance(value, MissingReason):
            missing[name] = value
            values.pop(name, None)
        else:
            values[name] = value
    if kind is EventKind.LOGIN:
        values.setdefault("login_outcome", "success")
        missing.pop("login_outcome", None)
    else:
        missing["login_outcome"] = MissingReason.NOT_APPLICABLE
    # Keep the few cross-field invariants consistent.
    for flag, count in (
        ("shared_device_flag", "accounts_per_device"),
        ("shared_network_flag", "accounts_per_network"),
    ):
        if count in values:
            values[flag] = values[count] >= 1
            missing.pop(flag, None)
        elif flag in values and count not in values:
            del values[flag]
            missing[flag] = MissingReason.NOT_OBSERVED
    for part, whole in (
        ("accounts_per_device", "accounts_seen_on_device"),
        ("successful_orders_to_address", "orders_to_address"),
        ("failed_orders_to_address", "orders_to_address"),
        ("accounts_seen_on_device_last_24h", "accounts_seen_on_device"),
        ("failed_logins_from_network_last_1h", "failed_logins_from_network"),
    ):
        if part in values and whole in values and values[part] > values[whole]:
            values[whole] = values[part]
    return FraudFeatureVector(
        feature_version=FS.version,
        event_id=uuid.uuid4(),
        event_kind=kind,
        event_timestamp=at,
        as_of_timestamp=at,
        source_event_count=0,
        values=values,
        missing=missing,
    )


def make_vectors(n: int, *, fraud_every: int = 5) -> tuple[list[FraudFeatureVector], list[int]]:
    """``n`` transaction vectors; every ``fraud_every``-th is 'fraud' with a learnable signal."""
    vectors, labels = [], []
    for i in range(n):
        fraud = i % fraud_every == 0
        vectors.append(
            make_vector(
                {
                    "transaction_amount_minor_units": 90000 + i if fraud else 2000 + (i % 7) * 100,
                    "new_device": fraud if i % 3 else not fraud,
                    "network_type": "datacenter" if fraud else "residential",
                    "transaction_currency": "GBP",
                },
                at=T0 + timedelta(hours=i),
                seed=i,
            )
        )
        labels.append(int(fraud))
    return vectors, labels
