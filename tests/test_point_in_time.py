"""Point-in-time correctness: no future data and no future labels may reach a vector.

These are the most important tests in the repository. A model trained on leaked features
looks excellent offline and fails in production.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, update
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType, FraudType, LabelSource, LabelValue, TransactionStatus
from fraud_ai.data.synthetic import SyntheticDataGenerator
from fraud_ai.database.engine import create_db_engine, make_session_factory
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import (
    Device,
    NetworkIdentity,
    Transaction,
    UserDevice,
)
from fraud_ai.database.repositories import record_label
from fraud_ai.features.context import SCORABLE_EVENT_TYPES
from fraud_ai.features.extractor import extract_features
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import TEST_KEY
from tests.feature_helpers import VPN, Scenario, net

T10 = datetime(2026, 1, 5, 10, 0, tzinfo=UTC)


@pytest.fixture
def pit(any_engine: Engine) -> Scenario:
    """A scenario on each available backend (SQLite always, PostgreSQL when configured)."""
    session = make_session_factory(any_engine)()
    return Scenario(session, EventProcessor(session, Pseudonymiser(TEST_KEY.encode())))


def test_ten_oclock_vector_is_identical_after_eleven_oclock_events(pit: Scenario) -> None:
    """The canonical leakage test.

    1. create user, 2. login from device A, 3. features at 10:00,
    4. at 11:00: new device, new IP, fraud label, chargeback,
    5. the 10:00 vector must be identical.
    """
    uid = pit.user(T10 - timedelta(days=90))
    addr = pit.address(uid, T10 - timedelta(days=90))
    pm = pit.payment_method(uid, T10 - timedelta(days=90))
    _, earlier_txn = pit.purchase(uid, T10 - timedelta(days=3), "20.00", pm=pm, address=addr)
    login = pit.login(uid, T10, device="dev-A")
    purchase, txn = pit.purchase(uid, T10 + timedelta(seconds=30), "25.00", pm=pm, address=addr)
    at_ten = pit.features(login)
    at_ten_txn = pit.features(purchase)

    eleven = T10 + timedelta(hours=1)
    pit.emit(
        EventType.NEW_DEVICE,
        eleven,
        uid,
        {"device": {"device_type": "mobile"}, "network": VPN},
        device="dev-B",
    )
    pit.login(
        uid,
        eleven + timedelta(minutes=1),
        device="dev-B",
        network=net("198.51.100.99", asn=65002, country="RO"),
    )
    pit.lifecycle(uid, eleven + timedelta(minutes=2), EventType.PASSWORD_RESET)
    pit.lifecycle(uid, eleven + timedelta(minutes=2), EventType.EMAIL_CHANGED)
    pit.chargeback(uid, earlier_txn, eleven + timedelta(minutes=3))
    pit.chargeback(uid, txn, eleven + timedelta(minutes=4))
    pit.confirm_fraud(uid, eleven + timedelta(minutes=5), target=login.event_id)
    other = pit.user(eleven, device="dev-A", network=net("10.1.2.3"))  # shares device + IP
    pit.login(other, eleven + timedelta(minutes=6), device="dev-A")

    again = pit.features(login)
    again_txn = pit.features(purchase)
    assert again == at_ten
    assert again.feature_hash == at_ten.feature_hash
    assert again_txn == at_ten_txn
    # ...while a vector as of 11:30 does see the new history.
    later = pit.features(login, as_of=eleven + timedelta(minutes=30))
    assert later.feature_hash != at_ten.feature_hash
    assert later.get("historical_chargebacks") == 2
    assert later.get("accounts_per_device") == 1
    assert later.get("recent_password_reset") is True
    pit.session.rollback()


def test_label_leakage_chargeback_arriving_later(pit: Scenario) -> None:
    """Jan 1 transaction, Jan 20 chargeback: the Jan 1 vector must not know."""
    jan1 = datetime(2026, 1, 1, 12, tzinfo=UTC)
    uid = pit.user(jan1 - timedelta(days=200))
    pm = pit.payment_method(uid, jan1 - timedelta(days=200))
    _, old_txn = pit.purchase(uid, jan1 - timedelta(days=60), "30.00", pm=pm)
    pit.chargeback(uid, old_txn, jan1 - timedelta(days=30))  # known before Jan 1
    event, txn = pit.purchase(uid, jan1, "900.00", pm=pm)
    pit.chargeback(uid, txn, datetime(2026, 1, 20, tzinfo=UTC))
    pit.confirm_fraud(uid, datetime(2026, 1, 21, tzinfo=UTC), txn=txn)

    vector = pit.features(event)
    assert vector.get("historical_chargebacks") == 1  # only the one known before Jan 1
    assert vector.get("historical_confirmed_fraud_events") == 0
    # The previous transaction's chargeback overwrote its status - but it *was* approved
    # before Jan 1, and features read the immutable decision, not the status.
    assert vector.get("successful_transactions_total") == 1

    # Even when rescoring later, a label on the scored transaction itself never leaks.
    retro = pit.features(event, as_of=datetime(2026, 2, 1, tzinfo=UTC))
    assert retro.get("historical_chargebacks") == 1
    assert retro.get("historical_confirmed_fraud_events") == 0
    pit.session.rollback()


def test_future_decisions_verifications_and_label_rows_are_invisible(pit: Scenario) -> None:
    uid = pit.user(T10 - timedelta(days=10))
    addr = pit.address(uid, T10 - timedelta(days=10))
    pm = pit.payment_method(uid, T10 - timedelta(days=10))
    _, pending = pit.purchase(
        uid, T10 - timedelta(hours=2), "10.00", pm=pm, address=addr, decision=None
    )
    event, _ = pit.purchase(uid, T10, "12.00", pm=pm, address=addr)
    before = pit.features(event)
    assert before.get("successful_transactions_total") == 0
    assert before.get("orders_to_address") == 1  # created before, decided later
    assert before.get("address_verified") is False

    later = T10 + timedelta(hours=1)
    pit.decide(uid, pending, later)  # decided after the scored event
    pit.emit(EventType.ADDRESS_VERIFIED, later, uid, {"address_id": str(addr)})
    pit.emit(EventType.PAYMENT_METHOD_VERIFIED, later, uid, {"payment_method_id": str(pm)})
    pit.lifecycle(uid, later, EventType.EMAIL_VERIFIED)
    record_label(
        pit.session,
        user_id=uid,
        label=LabelValue.FRAUD,
        fraud_type=FraudType.OTHER,
        label_source=LabelSource.ANALYST,
        labelled_at=later,
    )
    assert pit.features(event) == before
    pit.session.rollback()


def test_mutable_entity_state_is_never_read(pit: Scenario) -> None:
    """Corrupting every current-state cache must not change a historical vector."""
    uid = pit.user(T10 - timedelta(days=5))
    pit.login(uid, T10 - timedelta(days=1), mfa=True)
    event = pit.login(uid, T10)
    before = pit.features(event)
    s = pit.session
    s.execute(
        update(Device).values(
            successful_logins=999, failed_logins=999, last_seen_at=T10 + timedelta(days=99)
        )
    )
    s.execute(update(UserDevice).values(is_trusted=False, successful_logins=999))
    s.execute(
        update(NetworkIdentity).values(
            distinct_user_count=999,
            is_known_vpn=True,
            is_tor=True,
            proxy_confidence=1.0,
            successful_login_count=999,
        )
    )
    s.execute(update(Transaction).values(status=TransactionStatus.CHARGEBACK))
    s.expire_all()
    assert pit.features(event) == before
    pit.session.rollback()


def _ingest(url: str, events: list, extra_labels: bool) -> Session:  # type: ignore[type-arg]
    upgrade(url)
    session = make_session_factory(create_db_engine(url))()
    processor = EventProcessor(session, Pseudonymiser(TEST_KEY.encode()))
    for e in events:
        processor.process(e, atomic=False)
    if extra_labels:  # ground-truth labels "known" only at the very end
        from sqlalchemy import select

        for txn in session.scalars(select(Transaction)):
            record_label(
                session,
                user_id=txn.user_id,
                transaction_id=txn.transaction_id,
                label=LabelValue.LEGITIMATE,
                label_source=LabelSource.SYNTHETIC_GROUND_TRUTH,
                labelled_at=events[-1].timestamp,
            )
    session.commit()
    return session


def test_full_history_equals_history_truncated_at_t(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Property test over the synthetic scenarios.

    Database A holds the full history; database B was built only from events up to T.
    For every scorable event at or before T, the vector computed in A must equal the one
    computed in B. Any feature reading the future (events, labels, decisions, mutable
    entity state) would make them differ.
    """
    ref = datetime(2026, 6, 1, tzinfo=UTC)
    events = (
        SyntheticDataGenerator(seed=11, reference_time=ref, activity_days=40).generate(18).events
    )
    cutoff = ref - timedelta(days=12)  # after most attacks start, before their labels
    past = [e for e in events if e.timestamp <= cutoff]
    full = _ingest(f"sqlite:///{tmp_path / 'full.db'}", events, extra_labels=True)
    truncated = _ingest(f"sqlite:///{tmp_path / 'past.db'}", past, extra_labels=False)

    candidates = [e for e in past if e.event_type in SCORABLE_EVENT_TYPES]
    rng = random.Random(5)
    # Always include the events right before the cutoff (the riskiest for leakage).
    sample = candidates[-40:] + rng.sample(candidates[:-40], k=min(80, len(candidates) - 40))
    kinds = set()
    for e in sample:
        a = extract_features(full, e.event_id)
        b = extract_features(truncated, e.event_id)
        assert a.canonical_payload() == b.canonical_payload(), e.event_type
        kinds.add(a.event_kind)
    assert kinds == {"login", "transaction"}
    full.close()
    truncated.close()


def test_label_on_scored_transaction_excluded_even_without_event_link(pit: Scenario) -> None:
    """Defence in depth: a label that references only the transaction id (no event id)
    must still never count as the transaction's own history."""
    jan1 = datetime(2026, 1, 1, 12, tzinfo=UTC)
    uid = pit.user(jan1 - timedelta(days=100))
    event, txn = pit.purchase(uid, jan1, "50.00")
    record_label(
        pit.session,
        user_id=uid,
        transaction_id=txn,
        label=LabelValue.FRAUD,
        fraud_type=FraudType.OTHER,
        label_source=LabelSource.CHARGEBACK,
        labelled_at=jan1 + timedelta(days=5),
    )
    retro = pit.features(event, as_of=jan1 + timedelta(days=10))
    assert retro.get("historical_chargebacks") == 0
    pit.session.rollback()
