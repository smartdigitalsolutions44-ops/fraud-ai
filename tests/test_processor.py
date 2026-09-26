import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import (
    EventType,
    FraudType,
    LabelSource,
    LabelValue,
    LoginOutcome,
    SecurityEventType,
    SignalSource,
    TransactionStatus,
)
from fraud_ai.core.exceptions import EventProcessingError
from fraud_ai.database.models import (
    Address,
    Device,
    EventRecord,
    FraudLabel,
    FraudSignal,
    LoginEvent,
    NetworkEvent,
    NetworkIdentity,
    PaymentMethod,
    SecurityEvent,
    Transaction,
    User,
    UserDevice,
)
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import DESKTOP, HOME_NET, T0, VPN_NET, create_user, make_event


def _count(session: Session, model: Any) -> int:
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


def _login(
    processor: EventProcessor,
    uid: uuid.UUID | None,
    *,
    ok: bool = True,
    net: dict[str, Any] = HOME_NET,
    device: str = "device-A",
    minutes: int = 1,
    mfa: bool = False,
) -> None:
    processor.process(
        make_event(
            EventType.LOGIN_SUCCESS if ok else EventType.LOGIN_FAILURE,
            uid,
            {
                "auth_method": "password",
                "mfa_used": mfa,
                "network": net,
                "device": DESKTOP,
                **({} if ok else {"failure_reason": "bad_password"}),
            },
            ts=T0 + timedelta(minutes=minutes),
            device_id=device,
        )
    )


def _setup_purchase_prereqs(
    processor: EventProcessor, uid: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID]:
    addr, pm = uuid.uuid4(), uuid.uuid4()
    processor.process(
        make_event(
            EventType.ADDRESS_ADDED,
            uid,
            {"address_id": str(addr), "full_address": "1 Test Road, Leeds LS1", "country": "gb"},
            ts=T0 + timedelta(minutes=2),
        )
    )
    processor.process(
        make_event(
            EventType.PAYMENT_METHOD_ADDED,
            uid,
            {
                "payment_method_id": str(pm),
                "token_reference": "tok_test_1",
                "card_last4": "4242",
                "card_brand": "visa",
                "fingerprint": "fp_raw_value",
            },
            ts=T0 + timedelta(minutes=3),
        )
    )
    return addr, pm


def _create_txn(
    processor: EventProcessor,
    uid: uuid.UUID,
    pm: uuid.UUID,
    addr: uuid.UUID,
    amount: str = "25.10",
    minutes: int = 10,
) -> uuid.UUID:
    txn = uuid.uuid4()
    processor.process(
        make_event(
            EventType.TRANSACTION_CREATED,
            uid,
            {
                "transaction_id": str(txn),
                "amount": amount,
                "currency": "GBP",
                "payment_method_id": str(pm),
                "shipping_address_id": str(addr),
                "network": HOME_NET,
            },
            ts=T0 + timedelta(minutes=minutes),
        )
    )
    return txn


def test_account_creation_builds_entities(
    session: Session, processor: EventProcessor, pseudonymiser: Pseudonymiser
) -> None:
    uid = create_user(processor)
    user = session.get(User, uid)
    assert user is not None and user.account_created_at == T0
    device = session.scalar(select(Device))
    assert device is not None
    assert device.device_hash == pseudonymiser.hash_device("device-A")
    assert device.os_family == "Windows"
    assert session.get(UserDevice, (uid, device.device_id)) is not None
    net = session.scalar(select(NetworkIdentity))
    assert net is not None and net.ip_hash == pseudonymiser.hash_ip("10.1.2.3")
    assert net.distinct_user_count == 1
    assert _count(session, EventRecord) == 1 and _count(session, NetworkEvent) == 1


def test_raw_identifiers_never_stored_by_default(
    session: Session, processor: EventProcessor
) -> None:
    uid = create_user(processor)
    _setup_purchase_prereqs(processor, uid)
    net = session.scalar(select(NetworkIdentity))
    assert net is not None and net.ip_address is None
    for record in session.scalars(select(EventRecord)):
        blob = str(record.metadata_json)
        assert "10.1.2.3" not in blob
        assert "1 Test Road" not in blob
        assert "fp_raw_value" not in blob
        assert "device-A" not in blob
    stored = session.scalar(
        select(EventRecord).where(EventRecord.event_type == EventType.ADDRESS_ADDED)
    )
    assert stored is not None and "address_hash" in stored.metadata_json


def test_raw_ip_stored_only_when_enabled(session: Session, pseudonymiser: Pseudonymiser) -> None:
    create_user(EventProcessor(session, pseudonymiser, store_raw_ip=True))
    net = session.scalar(select(NetworkIdentity))
    assert net is not None and net.ip_address == "10.1.2.3"


def test_login_counters_and_trust(session: Session, processor: EventProcessor) -> None:
    uid = create_user(processor)
    _login(processor, uid, ok=False, minutes=1)
    _login(processor, uid, ok=True, minutes=2)
    link = session.scalar(select(UserDevice))
    assert link is not None and not link.is_trusted
    _login(processor, uid, ok=True, minutes=3, mfa=True)
    device = session.scalar(select(Device))
    net = session.scalar(select(NetworkIdentity))
    assert device is not None and net is not None and link is not None
    assert (device.successful_logins, device.failed_logins) == (2, 1)
    assert (link.successful_logins, link.failed_logins) == (2, 1)
    assert link.is_trusted  # trusted after an MFA-completed login
    assert (net.successful_login_count, net.failed_login_count) == (2, 1)
    assert device.last_seen_at == T0 + timedelta(minutes=3)
    outcomes = sorted(o.value for o in session.scalars(select(LoginEvent.outcome)))
    assert outcomes == ["FAILURE", "SUCCESS", "SUCCESS"]


def test_anonymous_failed_login_counts_on_ip(session: Session, processor: EventProcessor) -> None:
    _login(processor, None, ok=False)
    login = session.scalar(select(LoginEvent))
    assert login is not None and login.user_id is None and login.outcome is LoginOutcome.FAILURE
    net = session.scalar(select(NetworkIdentity))
    assert net is not None and net.failed_login_count == 1 and net.distinct_user_count == 0


def test_shared_ip_counts_distinct_users(session: Session, processor: EventProcessor) -> None:
    users = [create_user(processor, device_id=f"dev-{i}") for i in range(3)]
    for uid in users:
        _login(processor, uid, device=f"dev-{users.index(uid)}")
    net = session.scalar(select(NetworkIdentity))
    assert net is not None and net.distinct_user_count == 3
    assert _count(session, NetworkIdentity) == 1


def test_device_shared_across_accounts(session: Session, processor: EventProcessor) -> None:
    a = create_user(processor, device_id="shared-bot")
    b = create_user(processor, device_id="shared-bot")
    assert _count(session, Device) == 1
    assert _count(session, UserDevice) == 2
    assert {link.user_id for link in session.scalars(select(UserDevice))} == {a, b}


def test_vpn_is_recorded_as_signal_not_verdict(session: Session, processor: EventProcessor) -> None:
    uid = create_user(processor)
    _login(processor, uid, net=VPN_NET)
    signals = session.scalars(select(FraudSignal)).all()
    assert {s.signal_name for s in signals} == {"vpn_detected", "datacenter_network"}
    assert all(s.signal_source is SignalSource.NETWORK_INTEL and s.value == 0.93 for s in signals)
    obs = session.scalars(select(NetworkEvent).order_by(NetworkEvent.observed_at)).all()
    assert [o.is_known_vpn for o in obs] == [False, True]
    assert _count(session, FraudLabel) == 0  # no fraud verdict from VPN usage


def test_address_change_supersedes_history(session: Session, processor: EventProcessor) -> None:
    uid = create_user(processor)
    old, _ = _setup_purchase_prereqs(processor, uid)
    new = uuid.uuid4()
    processor.process(
        make_event(
            EventType.ADDRESS_CHANGED,
            uid,
            {
                "address_id": str(new),
                "full_address": "9 New Street, York YO1",
                "country": "GB",
                "replaces_address_id": str(old),
            },
            ts=T0 + timedelta(days=30),
        )
    )
    old_row, new_row = session.get(Address, old), session.get(Address, new)
    assert old_row is not None and new_row is not None
    assert not old_row.is_active and old_row.superseded_at == T0 + timedelta(days=30)
    assert new_row.is_active and new_row.replaces_address_id == old
    kinds = set(session.scalars(select(SecurityEvent.security_event_type)))
    assert SecurityEventType.ADDRESS_CHANGED in kinds


def test_transaction_lifecycle_and_chargeback_label(
    session: Session, processor: EventProcessor
) -> None:
    uid = create_user(processor)
    addr, pm = _setup_purchase_prereqs(processor, uid)
    assert session.get(PaymentMethod, pm).fingerprint_hash is not None  # type: ignore[union-attr]
    txn_id = _create_txn(processor, uid, pm, addr)
    txn = session.get(Transaction, txn_id)
    assert txn is not None and txn.status is TransactionStatus.PENDING and txn.amount_minor == 2510
    processor.process(
        make_event(
            EventType.TRANSACTION_APPROVED,
            uid,
            {"transaction_id": str(txn_id)},
            ts=T0 + timedelta(minutes=11),
        )
    )
    assert txn.status is TransactionStatus.APPROVED and txn.decided_at is not None
    with pytest.raises(EventProcessingError, match="already"):
        processor.process(
            make_event(
                EventType.TRANSACTION_DECLINED,
                uid,
                {"transaction_id": str(txn_id)},
                ts=T0 + timedelta(minutes=12),
            )
        )
    cb = make_event(
        EventType.CHARGEBACK,
        uid,
        {"transaction_id": str(txn_id), "reason_code": "10.4", "fraud_type": "account_takeover"},
        ts=T0 + timedelta(days=20),
    )
    processor.process(cb)
    assert txn.status is TransactionStatus.CHARGEBACK
    label = session.scalar(select(FraudLabel))
    assert label is not None
    assert (label.label, label.label_source, label.fraud_type) == (
        LabelValue.FRAUD,
        LabelSource.CHARGEBACK,
        FraudType.ACCOUNT_TAKEOVER,
    )
    assert label.labelled_at == T0 + timedelta(days=20)
    assert label.source_event_id == cb.event_id and label.transaction_id == txn_id


def test_fraud_confirmed_targets_event(session: Session, processor: EventProcessor) -> None:
    uid = create_user(processor)
    login = make_event(
        EventType.LOGIN_SUCCESS, uid, {"network": VPN_NET}, ts=T0 + timedelta(hours=1)
    )
    processor.process(login)
    processor.process(
        make_event(
            EventType.FRAUD_CONFIRMED,
            uid,
            {
                "target_event_id": str(login.event_id),
                "fraud_type": "credential_stuffing",
                "label_source": "analyst",
                "confidence": 0.8,
            },
            ts=T0 + timedelta(days=1),
        )
    )
    label = session.scalar(select(FraudLabel))
    assert label is not None and label.event_id == login.event_id and label.confidence == 0.8
    with pytest.raises(EventProcessingError, match="target event"):
        processor.process(
            make_event(
                EventType.FRAUD_CONFIRMED,
                uid,
                {"target_event_id": str(uuid.uuid4()), "fraud_type": "other"},
                ts=T0 + timedelta(days=2),
            )
        )


def test_duplicate_events_are_idempotent(session: Session, processor: EventProcessor) -> None:
    uid = uuid.uuid4()
    event = make_event(EventType.ACCOUNT_CREATED, uid, {"external_ref": "dup"})
    assert not processor.process(event).duplicate
    assert processor.process(event).duplicate
    assert _count(session, User) == 1 and _count(session, EventRecord) == 1


@pytest.mark.parametrize(
    "case",
    [
        "unknown_user",
        "foreign_payment_method",
        "unknown_txn",
        "new_device_without_id",
        "change_without_replaces",
    ],
)
def test_rejected_events_leave_no_partial_state(
    session: Session, processor: EventProcessor, case: str
) -> None:
    uid = create_user(processor)
    other = create_user(processor, device_id="device-B")
    _, other_pm = _setup_purchase_prereqs(processor, other)
    before = {
        m.__name__: _count(session, m) for m in (EventRecord, Device, NetworkIdentity, Transaction)
    }
    events = {
        "unknown_user": make_event(
            EventType.LOGIN_SUCCESS,
            uuid.uuid4(),
            {"network": VPN_NET},
            device_id="brand-new-device",
        ),
        "foreign_payment_method": make_event(
            EventType.TRANSACTION_CREATED,
            uid,
            {
                "transaction_id": str(uuid.uuid4()),
                "amount": "5",
                "currency": "GBP",
                "payment_method_id": str(other_pm),
                "network": VPN_NET,
            },
            device_id="brand-new-device",
        ),
        "unknown_txn": make_event(
            EventType.TRANSACTION_APPROVED, uid, {"transaction_id": str(uuid.uuid4())}
        ),
        "new_device_without_id": make_event(
            EventType.NEW_DEVICE, uid, {"device": DESKTOP}, device_id=None
        ),
        "change_without_replaces": make_event(
            EventType.ADDRESS_CHANGED,
            uid,
            {"address_id": str(uuid.uuid4()), "full_address": "x road", "country": "GB"},
        ),
    }
    with pytest.raises(EventProcessingError):
        processor.process(events[case])
    after = {
        m.__name__: _count(session, m) for m in (EventRecord, Device, NetworkIdentity, Transaction)
    }
    assert after == before
    # The session remains usable after a rejected event.
    _login(processor, uid, minutes=30)


# --------------------------------------------------------------------------- Stage 2 events
def test_decision_outcome_is_immutable_across_chargeback(
    session: Session, processor: EventProcessor
) -> None:
    from fraud_ai.core.enums import TransactionDecision

    uid = create_user(processor)
    addr, pm = _setup_purchase_prereqs(processor, uid)
    txn_id = _create_txn(processor, uid, pm, addr)
    processor.process(
        make_event(
            EventType.TRANSACTION_APPROVED,
            uid,
            {"transaction_id": str(txn_id)},
            ts=T0 + timedelta(minutes=11),
        )
    )
    processor.process(
        make_event(
            EventType.CHARGEBACK,
            uid,
            {"transaction_id": str(txn_id), "reason_code": "4837"},
            ts=T0 + timedelta(days=9),
        )
    )
    txn = session.get(Transaction, txn_id)
    assert txn is not None and txn.status is TransactionStatus.CHARGEBACK
    assert txn.decision_outcome is TransactionDecision.APPROVED


@pytest.mark.parametrize(
    "kind",
    [
        "EMAIL_VERIFIED",
        "EMAIL_CHANGED",
        "PHONE_VERIFIED",
        "PHONE_CHANGED",
        "MFA_ENABLED",
        "MFA_DISABLED",
    ],
)
def test_lifecycle_events_become_security_events(
    session: Session, processor: EventProcessor, kind: str
) -> None:
    uid = create_user(processor)
    processor.process(
        make_event(
            EventType(kind), uid, {"method": "sms", "network": VPN_NET}, ts=T0 + timedelta(hours=1)
        )
    )
    row = session.scalar(select(SecurityEvent).where(SecurityEvent.security_event_type == kind))
    assert row is not None and row.details == {"method": "sms"}
    assert row.network_identity_id is not None


def test_lifecycle_payload_rejects_contact_details() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        make_event(EventType.EMAIL_CHANGED, uuid.uuid4(), {"new_email": "a@example.com"})


def test_verification_events(session: Session, processor: EventProcessor) -> None:
    uid = create_user(processor)
    addr, pm = _setup_purchase_prereqs(processor, uid)
    first = T0 + timedelta(days=1)
    processor.process(
        make_event(EventType.ADDRESS_VERIFIED, uid, {"address_id": str(addr)}, ts=first)
    )
    processor.process(
        make_event(
            EventType.ADDRESS_VERIFIED, uid, {"address_id": str(addr)}, ts=first + timedelta(days=3)
        )
    )
    processor.process(
        make_event(EventType.PAYMENT_METHOD_VERIFIED, uid, {"payment_method_id": str(pm)}, ts=first)
    )
    assert session.get(Address, addr).verified_at == first  # type: ignore[union-attr]
    assert session.get(PaymentMethod, pm).verified_at == first  # type: ignore[union-attr]
    other = create_user(processor, device_id="device-Z")
    for event in (
        make_event(EventType.ADDRESS_VERIFIED, other, {"address_id": str(addr)}, ts=first),
        make_event(
            EventType.PAYMENT_METHOD_VERIFIED, other, {"payment_method_id": str(pm)}, ts=first
        ),
        make_event(EventType.ADDRESS_VERIFIED, uid, {"address_id": str(addr)}, ts=T0),
        make_event(EventType.PAYMENT_METHOD_VERIFIED, uid, {"payment_method_id": str(pm)}, ts=T0),
    ):
        with pytest.raises(EventProcessingError):
            processor.process(event)


def test_network_observation_records_mobile_flag(
    session: Session, processor: EventProcessor
) -> None:
    uid = create_user(
        processor, net={**HOME_NET, "is_mobile_network": True, "network_type": "mobile"}
    )
    obs = session.scalar(select(NetworkEvent).where(NetworkEvent.user_id == uid))
    assert obs is not None and obs.is_mobile_network is True
