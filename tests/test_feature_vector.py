import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import literal, select

from fraud_ai.database.base import UTCDateTime
from fraud_ai.features.definitions import EventKind, get_feature_set
from fraud_ai.features.validation import FeatureValidationError
from fraud_ai.features.vector import (
    FeatureWriter,
    FraudFeatureVector,
    MissingReason,
    canonical_float,
    hash_payload,
)
from fraud_ai.features.windows import (
    W5M,
    W24H,
    WINDOWS,
    WINDOWS_BY_NAME,
    count_if,
    elapsed_days,
    elapsed_hours,
    elapsed_minutes,
    upto,
    window_params,
)

T = datetime(2026, 3, 1, 12, tzinfo=UTC)
FS = get_feature_set()


def _base(kind: EventKind = EventKind.LOGIN) -> tuple[dict[str, Any], dict[str, MissingReason]]:
    """A valid all-missing vector for ``kind`` (only non-nullable context populated)."""
    values: dict[str, Any] = {"event_kind": kind.value, "authenticated_user": True}
    missing: dict[str, MissingReason] = {}
    for d in FS.definitions:
        if d.name in values:
            continue
        missing[d.name] = (
            MissingReason.NOT_APPLICABLE if kind not in d.applies_to else MissingReason.UNKNOWN
        )
    return values, missing


def _vector(
    values: dict[str, Any],
    missing: dict[str, MissingReason],
    *,
    kind: EventKind = EventKind.LOGIN,
    as_of: datetime = T,
) -> FraudFeatureVector:
    return FraudFeatureVector(
        feature_version=FS.version,
        event_id=uuid.uuid4(),
        event_kind=kind,
        event_timestamp=T,
        as_of_timestamp=as_of,
        source_event_count=0,
        values=values,
        missing=missing,
    )


def _with(**values: Any) -> FraudFeatureVector:
    base_values, missing = _base()
    for k in values:
        missing.pop(k, None)
    return _vector({**base_values, **values}, missing)


def test_valid_minimal_vector() -> None:
    v = _with(account_age_days=10.5, successful_logins_total=0, device_seen_before=False)
    assert v.get("successful_logins_total") == 0  # a real zero ...
    assert v.get("email_verified") is None  # ... is distinct from missing
    assert v.is_missing("email_verified") and not v.is_missing("successful_logins_total")
    assert v.missing["email_verified"] is MissingReason.UNKNOWN
    with pytest.raises(KeyError):
        v.get("nope")
    assert len(v.ordered_values()) == len(FS.names)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("account_age_days", math.nan),
        ("account_age_days", math.inf),
        ("account_age_days", -0.5),
        ("successful_logins_total", -1),
        ("successful_logins_total", 1.5),
        ("successful_logins_total", True),
        ("device_seen_before", 1),
        ("network_type", "satellite"),
        ("network_type", ""),
        ("rapid_multi_change_count", 8),
    ],
)
def test_rejects_invalid_values(name: str, value: Any) -> None:
    with pytest.raises(FeatureValidationError, match=name):
        _with(**{name: value})


def test_rejects_invalid_probabilities() -> None:
    # vpn/proxy probabilities only apply to... any event with a network; validation bounds.
    with pytest.raises(FeatureValidationError, match="vpn_probability"):
        _with(vpn_probability=1.2)
    assert _with(vpn_probability=0.93).get("vpn_probability") == 0.93


def test_structural_errors() -> None:
    values, missing = _base()
    with pytest.raises(FeatureValidationError, match="not assigned"):
        _vector(values, {k: v for k, v in missing.items() if k != "email_verified"})
    with pytest.raises(FeatureValidationError, match="unknown features"):
        _vector({**values, "bogus": 1}, missing)
    with pytest.raises(FeatureValidationError, match="both present and missing"):
        _vector({**values, "email_verified": True}, missing)
    with pytest.raises(FeatureValidationError, match="not nullable"):
        _vector({"authenticated_user": True}, {**missing, "event_kind": MissingReason.UNKNOWN})
    with pytest.raises(FeatureValidationError, match="precedes"):
        _vector(values, missing, as_of=T - timedelta(seconds=1))
    with pytest.raises(FeatureValidationError, match="unknown feature version"):
        FraudFeatureVector(
            feature_version="nope",
            event_id=uuid.uuid4(),
            event_kind=EventKind.LOGIN,
            event_timestamp=T,
            as_of_timestamp=T,
            source_event_count=0,
            values={},
            missing={},
        )


def test_not_applicable_is_enforced_by_event_kind() -> None:
    values, missing = _base(EventKind.LOGIN)
    missing.pop("transaction_amount_minor_units")
    with pytest.raises(FeatureValidationError, match="populated for a login"):
        _vector({**values, "transaction_amount_minor_units": 10}, missing)
    missing["transaction_amount_minor_units"] = MissingReason.UNKNOWN
    with pytest.raises(FeatureValidationError, match="must be not_applicable"):
        _vector(values, missing)


@pytest.mark.parametrize(
    "values",
    [
        {"failed_logins_last_5m": 3, "failed_logins_last_15m": 2},
        {"logins_last_1h": 2, "logins_last_24h": 1},
        {"successful_logins_last_1h": 3, "logins_last_1h": 2},
        {"accounts_per_device": 1, "shared_device_flag": False},
        {"successful_orders_to_address": 3},
    ],
)
def test_impossible_combinations_rejected(values: dict[str, Any]) -> None:
    if values == {"successful_orders_to_address": 3}:
        values = {"successful_orders_to_address": 3, "orders_to_address": 2}
        base, missing = _base(EventKind.TRANSACTION)
        for k in values:
            missing.pop(k)
        with pytest.raises(FeatureValidationError, match="impossible counts"):
            _vector({**base, **values}, missing, kind=EventKind.TRANSACTION)
        return
    with pytest.raises(FeatureValidationError):
        _with(**values)


def test_hash_is_canonical_and_excludes_context() -> None:
    a = _with(account_age_days=1.0, successful_logins_total=2)
    b = FraudFeatureVector(
        **{
            **a.model_dump(),
            "event_id": uuid.uuid4(),
            "as_of_timestamp": T + timedelta(days=1),
            "source_event_count": 9,
        }
    )
    assert a.feature_hash == b.feature_hash  # context/metadata is not hashed
    assert len(a.feature_hash) == 64
    reordered = dict(reversed(list(a.canonical_payload()["values"].items())))
    assert hash_payload({**a.canonical_payload(), "values": reordered}) == a.feature_hash
    c = _with(account_age_days=1.0, successful_logins_total=3)
    assert c.feature_hash != a.feature_hash
    assert '"missing"' in a.canonical_json() and " " not in a.canonical_json()


def test_float_canonicalisation() -> None:
    assert canonical_float(-0.0) == 0.0 and str(canonical_float(-0.0)) == "0.0"
    assert canonical_float(1 / 3) == 0.333333
    w = FeatureWriter(FS.version)
    w.put("account_age_days", 2 / 3)
    assert w.values["account_age_days"] == 0.666667


def test_writer_guards() -> None:
    w = FeatureWriter(FS.version)
    w.put("account_age_days", 1.0)
    with pytest.raises(ValueError, match="twice"):
        w.miss("account_age_days", MissingReason.UNKNOWN)
    with pytest.raises(KeyError):
        w.put("bogus", 1)
    w.put_or_miss("email_verified", None, MissingReason.UNKNOWN)
    assert w.missing["email_verified"] is MissingReason.UNKNOWN
    assert "phone_verified" in w.unassigned()


# --------------------------------------------------------------------------- windows
def test_window_catalogue() -> None:
    assert [w.name for w in WINDOWS] == ["5m", "15m", "1h", "6h", "24h", "7d", "30d"]
    assert WINDOWS_BY_NAME["24h"] is W24H


def test_window_bounds_are_half_open() -> None:
    assert W5M.lower_bound(T) == T - timedelta(minutes=5)
    assert not W5M.contains(T - timedelta(minutes=5), T)  # lower bound excluded
    assert W5M.contains(T - timedelta(minutes=4, seconds=59), T)
    assert W5M.contains(T, T)  # upper bound included
    assert not W5M.contains(T + timedelta(microseconds=1), T)  # the future is never inside
    params = window_params(T)
    assert params["as_of"] == T and params["lower_7d"] == T - timedelta(days=7)
    assert set(params) == {"as_of", *(f"lower_{w.name}" for w in WINDOWS)}


def test_window_sql_clauses(session) -> None:  # type: ignore[no-untyped-def]
    stamps = [T - timedelta(minutes=m) for m in (0, 4, 5, 6)] + [T + timedelta(minutes=1)]
    inside = [
        s
        for s in stamps
        if session.scalar(select(count_if(W5M.clause(literal(s, UTCDateTime()), T)))) == 1
    ]
    assert inside == [T, T - timedelta(minutes=4)]
    assert session.scalar(select(count_if(upto(literal(T, UTCDateTime()), T)))) == 1
    later = literal(T + timedelta(seconds=1), UTCDateTime())
    assert session.scalar(select(count_if(upto(later, T)))) == 0


def test_elapsed_helpers() -> None:
    assert elapsed_days(T - timedelta(days=2), T) == 2.0
    assert elapsed_hours(T - timedelta(minutes=90), T) == 1.5
    assert elapsed_minutes(T - timedelta(seconds=30), T) == 0.5
