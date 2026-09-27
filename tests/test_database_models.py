import uuid
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from fraud_ai.core.enums import (
    AddressType,
    Decision,
    EventSource,
    EventType,
    LabelSource,
    LabelValue,
    PaymentMethodType,
    TransactionChannel,
)
from fraud_ai.database.engine import make_session_factory
from fraud_ai.database.models import (
    Address,
    Device,
    EventRecord,
    FraudLabel,
    ModelPrediction,
    ModelVersion,
    PaymentMethod,
    RiskAssessment,
    Transaction,
    User,
    UserDevice,
)

T = datetime(2026, 2, 1, 10, tzinfo=UTC)


def _user(session: Session) -> User:
    user = User(external_ref=f"u-{uuid.uuid4().hex[:8]}", account_created_at=T)
    session.add(user)
    session.flush()
    return user


def _event(
    session: Session, user: User, etype: EventType = EventType.TRANSACTION_CREATED
) -> EventRecord:
    ev = EventRecord(
        event_id=uuid.uuid4(),
        event_type=etype,
        occurred_at=T,
        user_id=user.user_id,
        source=EventSource.API,
        metadata_json={},
        schema_version=1,
    )
    session.add(ev)
    session.flush()
    return ev


def _txn(
    session: Session, user: User, amount_minor: int = 1999, currency: str = "GBP"
) -> Transaction:
    ev = _event(session, user)
    txn = Transaction(
        transaction_id=uuid.uuid4(),
        event_id=ev.event_id,
        user_id=user.user_id,
        amount_minor=amount_minor,
        currency=currency,
        channel=TransactionChannel.WEB,
        occurred_at=T,
    )
    session.add(txn)
    session.flush()
    return txn


def _model(session: Session, name: str = "baseline", version: str = "1") -> ModelVersion:
    mv = ModelVersion(
        model_name=name,
        model_version=version,
        training_timestamp=T,
        training_dataset_version="ds1",
        feature_version="fv1",
        model_path="m.bin",
    )
    session.add(mv)
    session.flush()
    return mv


@pytest.fixture
def db(any_engine: Engine) -> Session:
    factory = make_session_factory(any_engine)
    sess = factory()
    yield sess  # type: ignore[misc]
    sess.rollback()
    sess.close()


def test_payment_schema_has_no_sensitive_columns(any_engine: Engine) -> None:
    forbidden = {"card_number", "pan", "cvv", "cvc", "pin", "password", "password_hash", "secret"}
    insp = inspect(any_engine)
    for table in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns(table)}
        assert not cols & forbidden, table


def test_defaults_and_utc_round_trip(db: Session) -> None:
    user = User(
        external_ref="ref-1",
        account_created_at=datetime(2026, 1, 1, 14, tzinfo=timezone(timedelta(hours=2))),
    )
    db.add(user)
    db.commit()
    db.expire_all()
    loaded = db.get(User, user.user_id)
    assert loaded is not None
    assert loaded.account_created_at == datetime(2026, 1, 1, 12, tzinfo=UTC)
    assert loaded.account_created_at.tzinfo is not None
    assert loaded.status.value == "active"


def test_money_precision_round_trip(db: Session) -> None:
    user = _user(db)
    big = _txn(db, user, amount_minor=9_007_199_254_740_993)  # > 2**53: float would corrupt it
    small = _txn(db, user, amount_minor=10)
    jpy = _txn(db, user, amount_minor=1500, currency="JPY")
    db.commit()
    db.expire_all()
    assert db.get(Transaction, big.transaction_id).amount_minor == 9_007_199_254_740_993  # type: ignore[union-attr]
    assert db.get(Transaction, small.transaction_id).amount == Decimal("0.10")  # type: ignore[union-attr]
    assert db.get(Transaction, jpy.transaction_id).amount == Decimal("1500")  # type: ignore[union-attr]


def test_relationships(db: Session) -> None:
    user = _user(db)
    device = Device(device_hash="h" * 64, first_seen_at=T, last_seen_at=T)
    db.add(device)
    db.flush()
    db.add(
        UserDevice(
            user_id=user.user_id, device_id=device.device_id, first_seen_at=T, last_seen_at=T
        )
    )
    pm = PaymentMethod(
        payment_method_id=uuid.uuid4(),
        user_id=user.user_id,
        token_reference="tok_1",
        method_type=PaymentMethodType.CARD,
        card_last4="4242",
        added_at=T,
    )
    addr = Address(
        address_id=uuid.uuid4(),
        user_id=user.user_id,
        address_hash="a" * 64,
        address_type=AddressType.HOME,
        country="GB",
        added_at=T,
    )
    db.add_all([pm, addr])
    txn = _txn(db, user)
    txn.payment_method_id = pm.payment_method_id
    db.add(
        FraudLabel(
            user_id=user.user_id,
            transaction_id=txn.transaction_id,
            label=LabelValue.LEGITIMATE,
            label_source=LabelSource.ANALYST,
            labelled_at=T,
        )
    )
    db.commit()
    db.expire_all()
    loaded = db.get(User, user.user_id)
    assert loaded is not None
    assert [link.device.device_hash for link in loaded.device_links] == ["h" * 64]
    assert loaded.payment_methods[0].token_reference == "tok_1"
    assert loaded.addresses[0].country == "GB"
    assert loaded.transactions[0].payment_method is not None
    assert loaded.fraud_labels[0].label is LabelValue.LEGITIMATE


def _expect_integrity_error(db: Session, obj: object) -> None:
    db.add(obj)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_constraint_negative_amount(db: Session) -> None:
    user = _user(db)
    ev = _event(db, user)
    _expect_integrity_error(
        db,
        Transaction(
            transaction_id=uuid.uuid4(),
            event_id=ev.event_id,
            user_id=user.user_id,
            amount_minor=-1,
            currency="GBP",
            channel=TransactionChannel.WEB,
            occurred_at=T,
        ),
    )


def test_constraint_foreign_keys_enforced(db: Session) -> None:
    _expect_integrity_error(
        db,
        Address(
            address_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            address_hash="x" * 64,
            address_type=AddressType.HOME,
            country="GB",
            added_at=T,
        ),
    )


def test_constraint_unique_token_reference(db: Session) -> None:
    user = _user(db)
    db.add(
        PaymentMethod(
            payment_method_id=uuid.uuid4(),
            user_id=user.user_id,
            token_reference="tok_dup",
            method_type=PaymentMethodType.CARD,
            added_at=T,
        )
    )
    db.flush()
    _expect_integrity_error(
        db,
        PaymentMethod(
            payment_method_id=uuid.uuid4(),
            user_id=user.user_id,
            token_reference="tok_dup",
            method_type=PaymentMethodType.CARD,
            added_at=T,
        ),
    )


def test_constraint_last4_length(db: Session) -> None:
    user = _user(db)
    _expect_integrity_error(
        db,
        PaymentMethod(
            payment_method_id=uuid.uuid4(),
            user_id=user.user_id,
            token_reference="tok_x",
            method_type=PaymentMethodType.CARD,
            card_last4="411",
            added_at=T,
        ),
    )


def test_constraint_enum_check_at_database_level(db: Session) -> None:
    user = _user(db)
    db.commit()
    with pytest.raises(IntegrityError):
        db.execute(
            text("UPDATE users SET status = 'hacked' WHERE external_ref = :r"),
            {"r": user.external_ref},
        )
    db.rollback()
    with pytest.raises(StatementError):  # rejected in Python before reaching the database
        db.execute(select(User).where(User.status == "hacked"))


def test_constraint_fraud_label_requires_type(db: Session) -> None:
    user = _user(db)
    _expect_integrity_error(
        db,
        FraudLabel(
            user_id=user.user_id,
            label=LabelValue.FRAUD,
            label_source=LabelSource.ANALYST,
            labelled_at=T,
        ),
    )


def test_constraint_seen_order(db: Session) -> None:
    _expect_integrity_error(
        db, Device(device_hash="z" * 64, first_seen_at=T, last_seen_at=T - timedelta(seconds=1))
    )


def test_model_version_unique_and_single_active(db: Session) -> None:
    _model(db, version="1")
    _expect_integrity_error(
        db,
        ModelVersion(
            model_name="baseline",
            model_version="1",
            training_timestamp=T,
            training_dataset_version="d",
            feature_version="f",
            model_path="p",
        ),
    )
    a = _model(db, version="1")
    b = _model(db, version="2")
    other = _model(db, name="other", version="1")
    a.active = True
    other.active = True
    db.flush()
    b.active = True
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_prediction_constraints(db: Session) -> None:
    user = _user(db)
    ev = _event(db, user)
    _model(db)

    def pred(**kw: object) -> ModelPrediction:
        base: dict[str, object] = dict(
            event_id=ev.event_id,
            user_id=user.user_id,
            model_name="baseline",
            model_version="1",
            fraud_probability=0.7,
            predicted_class=1,
            threshold=0.5,
            feature_version="fv1",
        )
        base.update(kw)
        return ModelPrediction(**base)

    db.add(pred())
    db.flush()
    for bad in (
        dict(fraud_probability=1.2),
        dict(threshold=-0.1),
        dict(predicted_class=0),
        dict(model_version="does-not-exist"),
    ):
        db.begin_nested()
        db.add(pred(**bad))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()


def test_risk_assessment_constraints(db: Session) -> None:
    user = _user(db)
    ev = _event(db, user)

    def assessment(**overrides: object) -> RiskAssessment:
        base: dict[str, object] = {
            "event_id": ev.event_id,
            "user_id": user.user_id,
            "ml_probability": 0.78,
            "final_risk_score": 0.88,
            "risk_level": "elevated",
            "decision": Decision.STEP_UP_AUTHENTICATION,
            "policy_version": "risk-policy-1.0.0",
            "idempotency_key": "k" * 64,
            "triggered_rules": {"results": []},
        }
        base.update(overrides)
        return RiskAssessment(**base)

    db.add(assessment())
    db.flush()
    # A fallback assessment has no score.
    db.add(assessment(assessment_version=2, final_risk_score=None, idempotency_key="f" * 64))
    db.flush()
    for bad in (
        {"final_risk_score": 1.5, "assessment_version": 3, "idempotency_key": "a" * 64},
        {"assessment_version": 0, "idempotency_key": "b" * 64},
        {"assessment_version": 1, "idempotency_key": "c" * 64},  # duplicate version
        {"assessment_version": 4},  # duplicate idempotency key
        {"assessment_version": 5, "idempotency_key": "d" * 64, "decision": "BLOCK"},
    ):
        savepoint = db.begin_nested()
        db.add(assessment(**bad))
        with pytest.raises((IntegrityError, StatementError)):
            db.flush()
        savepoint.rollback()
    db.rollback()
