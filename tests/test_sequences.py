"""Stage 6 point-in-time sequences: ordering, truncation, padding, masking, time deltas,
known flags, future leakage (later events, late labels, late chargebacks, mutable tables),
fingerprints, batch/single equality."""

from __future__ import annotations

import math
import uuid
from datetime import timedelta

import numpy as np
import pytest
from sqlalchemy import update
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType
from fraud_ai.database.models import Device, UserDevice
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.sequences.definition import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    SEQUENCE_VERSION,
    SequenceDefinition,
    vocabulary,
)
from fraud_ai.sequences.extraction import (
    NUMERIC_NAMES,
    VOCABULARIES,
    SequenceBatch,
    SequenceError,
    build_sequence,
    build_sequences,
)
from fraud_ai.sequences.inputs import SequenceMatrix
from tests.conftest import T0
from tests.feature_helpers import HOME, VPN, Scenario

H = timedelta(hours=1)


def col(name: str) -> int:
    return NUMERIC_NAMES.index(name)


def etype(batch: SequenceBatch, row: int = 0) -> list[str]:
    return [p["event_type"] for p in batch.decode(row)]


@pytest.fixture
def sc(session: Session, processor: EventProcessor) -> Scenario:
    return Scenario(session, processor)


def _history(sc: Scenario) -> tuple[uuid.UUID, uuid.UUID]:
    """A user: account, logins, a VPN login from a new device, then a purchase at T0+10h."""
    user = sc.user(T0)
    sc.login(user, T0 + H)
    sc.login(user, T0 + 2 * H, ok=False)
    sc.login(user, T0 + 3 * H, device="dev-B", network=VPN)
    address = sc.address(user, T0 + 4 * H)
    event, _ = sc.purchase(user, T0 + 10 * H, "25.00", address=address)
    sc.session.flush()
    return user, event.event_id


# ------------------------------------------------------------------ definition
def test_definition_fingerprint_and_validation() -> None:
    d = SequenceDefinition()
    assert d.version == SEQUENCE_VERSION and d.length == 17 and d.padding == "right"
    assert d.fingerprint() == SequenceDefinition().fingerprint()
    assert d.fingerprint() != SequenceDefinition(max_events=8).fingerprint()
    assert d.fingerprint() != SequenceDefinition(max_age_days=30).fingerprint()
    assert SequenceDefinition.from_dict(d.to_dict()) == d
    tampered = {**d.to_dict(), "fingerprint": "0" * 64}
    with pytest.raises(ValueError, match="fingerprint"):
        SequenceDefinition.from_dict(tampered)
    for bad in (
        {"max_events": 0},
        {"max_age_days": -1},
        {"lookback_days": 0},
        {"max_age_days": 400, "lookback_days": 365},
        {"version": "x"},
    ):
        with pytest.raises(ValueError):
            SequenceDefinition(**bad)  # type: ignore[arg-type]
    described = d.describe()
    assert [f["name"] for f in described["numeric_features"]] == [n for n, _ in NUMERIC_FEATURES]
    for name, values in CATEGORICAL_FEATURES.items():
        vocab = vocabulary(values)
        assert vocab["<pad>"] == 0 and vocab["<unk>"] == 1 and len(vocab) == len(values) + 2
        assert described["vocabularies"][name] == vocab


def test_no_identifier_vocabularies() -> None:
    """Embeddings are over types only: no user, IP, device or address tokens exist."""
    assert set(CATEGORICAL_FEATURES) == {
        "event_type",
        "network_type",
        "device_type",
        "auth_method",
        "channel",
    }
    for name in NUMERIC_NAMES:
        assert not any(bad in name for bad in ("user_id", "ip_hash", "address_id", "token"))


# ------------------------------------------------------------------ ordering + content
def test_order_padding_mask_and_target(sc: Scenario) -> None:
    _, event_id = _history(sc)
    batch = build_sequence(sc.session, event_id, SequenceDefinition(max_events=8))
    assert batch.lengths.tolist() == [6]  # 5 history events + the scored event
    types = etype(batch)
    assert types == [
        "ACCOUNT_CREATED",
        "LOGIN_SUCCESS",
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "ADDRESS_ADDED",
        "TRANSACTION_CREATED",
    ]
    assert "TRANSACTION_APPROVED" not in types  # the purchase's own outcome is after T
    num = batch.numeric[0]
    assert num[:5, col("is_target")].tolist() == [0.0] * 5 and num[5, col("is_target")] == 1.0
    hours = [math.expm1(v) for v in num[:6, col("log_hours_before_target")]]
    assert hours == sorted(hours, reverse=True) and hours[-1] == 0.0
    assert hours[0] == pytest.approx(10.0, abs=1e-3)
    mask = batch.mask()[0]
    assert mask.tolist() == [True] * 6 + [False] * 3
    assert np.all(batch.categorical[0, 6:] == 0) and np.all(batch.numeric[0, 6:] == 0)


def test_time_deltas_and_known_flags(sc: Scenario) -> None:
    _, event_id = _history(sc)
    b = build_sequence(sc.session, event_id, SequenceDefinition())
    positions = b.decode(0)
    gaps = [round(math.expm1(p["log_minutes_since_previous"])) for p in positions]
    assert gaps[1:] == [60, 60, 60, 60, 360]  # minutes; bursts and gaps are distinguished
    vpn_login = next(p for p in positions if p["vpn"])
    assert vpn_login["device_known"] == 0.0 and vpn_login["network_known"] == 0.0
    assert vpn_login["country_changed"] == 1.0 and vpn_login["asn_changed"] == 1.0
    assert vpn_login["network_type"] == "datacenter" and vpn_login["proxy_confidence"] > 0.9
    home_login = positions[1]
    assert home_login["device_known"] == 1.0 and home_login["network_known"] == 1.0
    target = positions[-1]
    assert target["has_amount"] == 1.0
    assert math.expm1(target["log_amount"]) == pytest.approx(25, abs=1e-3)
    assert target["address_known"] == 1.0
    assert math.expm1(target["log_address_age_days"]) == pytest.approx(6 / 24, abs=1e-3)
    assert target["device_known"] == 1.0 and target["device_changed"] == 0.0
    assert vpn_login["device_changed"] == 1.0  # A -> B at the VPN login


def test_truncation_keeps_the_latest_events(sc: Scenario) -> None:
    user = sc.user(T0)
    for i in range(1, 21):
        sc.login(user, T0 + i * H)
    event, _ = sc.purchase(user, T0 + 30 * H, "10.00")
    sc.session.flush()
    b = build_sequence(sc.session, event.event_id, SequenceDefinition(max_events=4))
    assert b.lengths.tolist() == [5]
    hours = [round(math.expm1(v)) for v in b.numeric[0, :5, col("log_hours_before_target")]]
    assert hours == [13, 12, 11, 10, 0]  # logins 17..20, then the purchase
    aged = build_sequence(
        sc.session, event.event_id, SequenceDefinition(max_events=32, max_age_days=0.5)
    )
    assert aged.lengths.tolist() == [4]  # logins at 18h, 19h, 20h (within 12h) + purchase


def test_anonymous_event_has_only_the_target(sc: Scenario) -> None:
    event = sc.login(None, T0, ok=False)
    sc.session.flush()
    b = build_sequence(sc.session, event.event_id, SequenceDefinition())
    assert b.lengths.tolist() == [1] and etype(b) == ["LOGIN_FAILURE"]
    with pytest.raises(SequenceError, match="unknown event"):
        build_sequence(sc.session, uuid.uuid4(), SequenceDefinition())


# ------------------------------------------------------------------ leakage
def test_later_events_do_not_change_the_sequence(sc: Scenario) -> None:
    user, event_id = _history(sc)
    d = SequenceDefinition()
    before = build_sequence(sc.session, event_id, d).digest()
    sc.login(user, T0 + 10 * H + timedelta(minutes=1), device="dev-C", network=VPN)  # 10:01
    sc.purchase(user, T0 + 11 * H, "999.00")
    sc.session.flush()
    assert build_sequence(sc.session, event_id, d).digest() == before


def test_late_labels_and_chargebacks_never_appear(sc: Scenario) -> None:
    user, event_id = _history(sc)
    d = SequenceDefinition()
    before = build_sequence(sc.session, event_id, d)
    _, txn = sc.purchase(user, T0 + 5 * H, "40.00")
    sc.session.flush()
    with_earlier = build_sequence(sc.session, event_id, d)
    # A chargeback and a fraud confirmation that arrive AFTER the scoring point.
    sc.chargeback(user, txn, T0 + 30 * H)
    sc.emit(
        EventType.FRAUD_CONFIRMED,
        T0 + 31 * H,
        user,
        {
            "transaction_id": str(txn),
            "fraud_type": "account_takeover",
            "label_source": "analyst",
            "confidence": 1.0,
        },
    )
    sc.session.flush()
    after = build_sequence(sc.session, event_id, d)
    assert after.digest() == with_earlier.digest() != before.digest()
    assert "CHARGEBACK" not in etype(after) and "FRAUD_CONFIRMED" not in etype(after)
    # A chargeback known BEFORE the scoring point is legitimate history.
    later_target, _ = sc.purchase(user, T0 + 40 * H, "12.00")
    sc.session.flush()
    b = build_sequence(sc.session, later_target.event_id, d)
    assert "CHARGEBACK" in etype(b)
    assert any(p["is_label_event"] for p in b.decode(0))


def test_mutable_tables_are_never_read(sc: Scenario) -> None:
    """Trust decisions and counters written later cannot change a historical sequence."""
    _, event_id = _history(sc)
    d = SequenceDefinition()
    before = build_sequence(sc.session, event_id, d).digest()
    sc.session.execute(update(UserDevice).values(is_trusted=True, successful_logins=999))
    sc.session.execute(update(Device).values(failed_logins=999, successful_logins=999))
    sc.session.flush()
    assert build_sequence(sc.session, event_id, d).digest() == before


def test_same_timestamp_events_are_excluded(sc: Scenario) -> None:
    user = sc.user(T0)
    event, _ = sc.purchase(user, T0 + H, "10.00", decide_after=timedelta(0))
    sc.session.flush()
    b = build_sequence(sc.session, event.event_id, SequenceDefinition())
    assert etype(b) == ["ACCOUNT_CREATED", "TRANSACTION_CREATED"]


# ------------------------------------------------------------------ batch + inputs
def test_batch_equals_single_and_digest_is_stable(sc: Scenario) -> None:
    user, e1 = _history(sc)
    e2, _ = sc.purchase(user, T0 + 20 * H, "30.00")
    sc.session.flush()
    d = SequenceDefinition(max_events=6)
    batch = build_sequences(sc.session, [e2.event_id, e1], d)
    singles = [build_sequence(sc.session, e, d) for e in (e2.event_id, e1)]
    for row, single in enumerate(singles):
        assert np.array_equal(batch.categorical[row], single.categorical[0])
        assert np.array_equal(batch.numeric[row], single.numeric[0])
        assert batch.lengths[row] == single.lengths[0]
    assert batch.digest() == build_sequences(sc.session, [e2.event_id, e1], d).digest()
    assert batch.take([1]).digest() == singles[1].digest()
    assert len(batch) == 2 and len(build_sequences(sc.session, [], d)) == 0
    assert (
        batch.digest()
        != build_sequences(sc.session, [e2.event_id, e1], SequenceDefinition(max_events=7)).digest()
    )


def test_sequence_matrix_keeps_rows_aligned(sc: Scenario) -> None:
    from fraud_ai.models.matrix import ModelMatrix
    from tests.model_helpers import make_vector

    user, e1 = _history(sc)
    e2, _ = sc.purchase(user, T0 + 20 * H, "30.00")
    sc.session.flush()
    seqs = build_sequences(sc.session, [e1, e2.event_id], SequenceDefinition())
    matrix = ModelMatrix.from_vectors([make_vector(seed=1), make_vector(seed=2)])
    combined = SequenceMatrix.attach(matrix, seqs)
    one = combined.take([1])
    assert isinstance(one, SequenceMatrix) and one.values == (matrix.values[1],)
    assert one.sequences.digest() == seqs.take([1]).digest()
    with pytest.raises(SequenceError, match="row counts"):
        SequenceMatrix.attach(matrix.take([0]), seqs)


def test_unknown_tokens_and_vocabulary_decoding(sc: Scenario) -> None:
    user = sc.user(T0)
    sc.login(user, T0 + H, network={**HOME, "network_type": "education"})
    event, _ = sc.purchase(user, T0 + 2 * H, "5.00")
    sc.session.flush()
    b = build_sequence(sc.session, event.event_id, SequenceDefinition())
    assert "education" in [p["network_type"] for p in b.decode(0)]
    assert VOCABULARIES["event_type"]["LOGIN_SUCCESS"] >= 2
