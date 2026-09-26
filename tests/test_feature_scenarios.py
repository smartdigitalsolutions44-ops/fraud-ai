"""Features reflect the synthetic behaviour scenarios realistically."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType, LabelValue
from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import Address, EventRecord, FraudLabel, Transaction, User
from fraud_ai.features.batch import iter_vectors
from fraud_ai.features.context import LOGIN_EVENT_TYPES
from fraud_ai.features.vector import FraudFeatureVector
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import TEST_KEY

REF = datetime(2026, 8, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def world(migrated_template: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Session]:
    path = tmp_path_factory.mktemp("scenarios") / "w.db"
    shutil.copy(migrated_template, path)
    engine = create_db_engine(f"sqlite:///{path}")
    with session_scope(make_session_factory(engine)) as s:
        seed_synthetic_data(
            s,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=40,
            seed=21,
            reference_time=REF,
            activity_days=30,
        )
    with make_session_factory(engine)() as session:
        yield session
    engine.dispose()


def _txn_vectors(s: Session, scenario: str) -> list[FraudFeatureVector]:
    ids = list(
        s.scalars(
            select(Transaction.event_id)
            .join(User)
            .where(User.synthetic_scenario == scenario)
            .order_by(Transaction.occurred_at)
        )
    )
    return list(iter_vectors(s, ids))


def _login_vectors(s: Session, scenario: str | None) -> list[FraudFeatureVector]:
    q = select(EventRecord.event_id).where(EventRecord.event_type.in_(LOGIN_EVENT_TYPES))
    if scenario is None:
        q = q.where(EventRecord.user_id.is_(None))
    else:
        q = q.join(User, User.user_id == EventRecord.user_id).where(
            User.synthetic_scenario == scenario
        )
    return list(iter_vectors(s, list(s.scalars(q.order_by(EventRecord.occurred_at)))))


def test_account_takeover_pattern(world: Session) -> None:
    attack_txns = list(
        world.scalars(
            select(FraudLabel.transaction_id)
            .join(User, User.user_id == FraudLabel.user_id)
            .where(
                User.synthetic_scenario == "account_takeover",
                FraudLabel.label == LabelValue.FRAUD,
                FraudLabel.transaction_id.is_not(None),
            )
        )
    )
    assert attack_txns
    events = list(
        world.scalars(
            select(Transaction.event_id).where(Transaction.transaction_id.in_(attack_txns))
        )
    )
    loud = quiet = 0
    for v in iter_vectors(world, events):
        # Loud takeovers (failed logins, then a reset) come from a new device; stealthy ones
        # may reuse the victim's own device, address or buy digital goods - there is no
        # single giveaway signal.
        if v.get("recent_password_reset") is True:
            loud += 1
            assert v.get("new_device") is True and v.get("device_changed_recently") is True
            assert int(v.get("rapid_multi_change_count") or 0) >= 3
            if v.get("previous_transactions_same_currency"):
                assert float(v.get("transaction_vs_median_ratio") or 0) > 1.5
        else:
            quiet += 1
        if not v.get("previous_transactions_same_currency"):
            # no purchase history: the ratio is honestly unknown, not zero
            assert v.missing["transaction_vs_median_ratio"].value == "not_observed"
        assert float(v.get("account_age_days") or 0) > 150
        # The chargeback arrives later: the attack vector does not know about it.
        assert v.get("historical_chargebacks") == 0
    # Variety across takeovers is asserted on a larger world in test_synthetic.py; this
    # 40-user world has only a handful of victims.
    assert loud + quiet >= 1


def test_legitimate_vpn_customer(world: Session) -> None:
    vectors = [v for v in _txn_vectors(world, "legitimate_vpn") if v.get("vpn_detected")]
    assert vectors
    later = vectors[5:]  # once history exists
    assert later
    # Digital goods have no address (None); a gift to a new address is occasional.
    assert sum(v.get("device_seen_before") is True for v in later) >= 0.8 * len(later)
    assert sum(v.get("address_seen_before") is not False for v in later) >= 0.8 * len(later)
    assert all(int(v.get("rapid_multi_change_count") or 0) <= 2 for v in later)
    assert not world.scalars(
        select(FraudLabel)
        .join(User)
        .where(User.synthetic_scenario == "legitimate_vpn", FraudLabel.label == LabelValue.FRAUD)
    ).all()


def test_new_address_customer(world: Session) -> None:
    movers = list(
        world.scalars(select(User.user_id).where(User.synthetic_scenario == "new_home_address"))
    )
    new_addresses = set(
        world.scalars(
            select(Address.address_id).where(
                Address.user_id.in_(movers), Address.replaces_address_id.is_not(None)
            )
        )
    )
    events = list(
        world.scalars(
            select(Transaction.event_id)
            .where(Transaction.shipping_address_id.in_(new_addresses))
            .order_by(Transaction.occurred_at)
        )
    )
    first_to_new = {v.user_id: v for v in reversed(list(iter_vectors(world, events)))}
    assert first_to_new
    for v in first_to_new.values():
        assert float(v.get("address_age_days") or 99) < 7
        assert v.get("address_seen_before") is False
        assert v.get("recent_password_reset") is False and v.get("recent_email_change") is False
        assert int(v.get("rapid_multi_change_count") or 0) <= 1


def test_normal_customer_is_stable(world: Session) -> None:
    vectors = _txn_vectors(world, "normal")[-60:]
    # Legitimate customers occasionally forget their password (~2%) or use a one-off device.
    assert sum(v.get("recent_password_reset") is True for v in vectors) <= 0.1 * len(vectors)
    assert sum(v.get("device_seen_before") is True for v in vectors) >= 0.85 * len(vectors)
    # Changes are isolated (a new phone, a reset, a gift address); never a takeover burst.
    assert all(int(v.get("rapid_multi_change_count") or 0) <= 2 for v in vectors)


def test_shared_office_network_and_carrier_nat(world: Session) -> None:
    office = [
        v for v in _login_vectors(world, "shared_network") if v.get("network_type") == "business"
    ]
    assert office and max(int(v.get("accounts_per_network") or 0) for v in office) >= 1
    carrier = [v for v in _login_vectors(world, "normal") if v.get("mobile_network") is True]
    assert carrier and any(v.get("shared_network_flag") for v in carrier)


def test_high_login_velocity_from_shared_attack_infrastructure(world: Session) -> None:
    anonymous = _login_vectors(world, None)
    assert anonymous
    assert max(int(v.get("failed_logins_from_network_last_1h") or 0) for v in anonymous) >= 5
    assert max(int(v.get("accounts_seen_on_device_last_24h") or 0) for v in anonymous) >= 3
    victims = [
        v
        for v in _login_vectors(world, "suspicious_velocity")
        if v.get("login_outcome") == "failure" and v.get("datacenter_detected")
    ]
    assert victims and max(int(v.get("accounts_per_device") or 0) for v in victims) >= 2
    assert EventType.LOGIN_FAILURE  # scenario uses real failure events
