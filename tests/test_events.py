import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from fraud_ai.core.enums import EventSource, EventType
from fraud_ai.core.events import (
    CURRENT_SCHEMA_VERSION,
    PAYLOAD_SCHEMAS,
    Event,
    TransactionCreatedPayload,
    parse_event,
)
from fraud_ai.core.exceptions import EventValidationError, SecurityViolationError

UID = uuid.uuid4()
TS = datetime(2026, 1, 1, 12, tzinfo=UTC)


def _txn_meta(**overrides: object) -> dict[str, object]:
    meta: dict[str, object] = {
        "transaction_id": str(uuid.uuid4()),
        "amount": "10.50",
        "currency": "gbp",
    }
    meta.update(overrides)
    return meta


def test_every_event_type_has_a_payload_schema() -> None:
    assert set(PAYLOAD_SCHEMAS) == set(EventType)


def test_event_envelope_fields_and_defaults() -> None:
    e = Event(
        event_type=EventType.LOGIN_SUCCESS,
        timestamp=TS,
        user_id=UID,
        session_id="s1",
        device_id="d1",
        source=EventSource.WEB,
        metadata={},
    )
    assert isinstance(e.event_id, uuid.UUID)
    assert e.schema_version == CURRENT_SCHEMA_VERSION
    assert set(Event.model_fields) == {
        "event_id",
        "event_type",
        "timestamp",
        "user_id",
        "session_id",
        "device_id",
        "source",
        "metadata",
        "schema_version",
    }
    with pytest.raises(ValidationError):
        e.session_id = "other"  # type: ignore[misc]  # frozen


def test_timestamp_normalised_to_utc_and_naive_rejected() -> None:
    plus2 = timezone(timedelta(hours=2))
    e = Event(
        event_type=EventType.LOGIN_SUCCESS,
        timestamp=datetime(2026, 1, 1, 14, tzinfo=plus2),
        user_id=UID,
        source=EventSource.WEB,
    )
    assert e.timestamp == TS and e.timestamp.utcoffset() == timedelta(0)
    with pytest.raises(ValidationError):
        Event(
            event_type=EventType.LOGIN_SUCCESS,
            timestamp=datetime(2026, 1, 1),
            user_id=UID,
            source=EventSource.WEB,
        )


def test_user_required_except_for_anonymous_login_events() -> None:
    Event(event_type=EventType.LOGIN_FAILURE, timestamp=TS, source=EventSource.WEB)
    with pytest.raises(ValidationError, match="requires user_id"):
        Event(
            event_type=EventType.TRANSACTION_CREATED,
            timestamp=TS,
            source=EventSource.WEB,
            metadata=_txn_meta(),
        )


def test_payload_is_typed_and_validated() -> None:
    e = Event(
        event_type=EventType.TRANSACTION_CREATED,
        timestamp=TS,
        user_id=UID,
        source=EventSource.API,
        metadata=_txn_meta(),
    )
    payload = e.payload()
    assert isinstance(payload, TransactionCreatedPayload)
    assert payload.currency == "GBP" and payload.amount_minor == 1050


@pytest.mark.parametrize(
    "meta",
    [
        _txn_meta(amount=10.5),
        _txn_meta(amount="-1"),
        _txn_meta(amount="1.005"),
        _txn_meta(currency="XX"),
        _txn_meta(unexpected="field"),
        {"amount": "1", "currency": "GBP"},
    ],
)
def test_invalid_transaction_payloads_rejected(meta: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Event(
            event_type=EventType.TRANSACTION_CREATED,
            timestamp=TS,
            user_id=UID,
            source=EventSource.API,
            metadata=meta,
        )


def test_unsupported_schema_version() -> None:
    with pytest.raises(ValidationError, match="schema_version"):
        Event(
            event_type=EventType.LOGIN_SUCCESS,
            timestamp=TS,
            user_id=UID,
            source=EventSource.WEB,
            schema_version=99,
        )


def test_network_context_validation() -> None:
    base = {
        "event_type": "LOGIN_SUCCESS",
        "timestamp": "2026-01-01T00:00:00Z",
        "user_id": str(UID),
        "source": "web",
    }
    ok = parse_event({**base, "metadata": {"network": {"ip": "2001:DB8:0::1", "country": "gb"}}})
    assert ok.payload().network.ip == "2001:db8::1"
    assert ok.payload().network.country == "GB"
    for bad in ({"ip": "999.1.1.1"}, {"ip": "10.0.0.1", "proxy_confidence": 1.5}):
        with pytest.raises(EventValidationError):
            parse_event({**base, "metadata": {"network": bad}})


@pytest.mark.parametrize(
    "extra",
    [
        {"card_number": "4111111111111111"},
        {"cvv": "123"},
        {"password": "hunter2"},
        {"notes": "card 4111 1111 1111 1111"},
        {"pin": "0000"},
    ],
)
def test_forbidden_payment_and_auth_data_rejected(extra: dict[str, str]) -> None:
    raw = {
        "event_type": "PAYMENT_METHOD_ADDED",
        "timestamp": "2026-01-01T00:00:00Z",
        "user_id": str(UID),
        "source": "api",
        "metadata": {
            "payment_method_id": str(uuid.uuid4()),
            "token_reference": "tok_1234",
            **extra,
        },
    }
    with pytest.raises(SecurityViolationError) as info:
        parse_event(raw)
    # The error names the path but never echoes the sensitive value.
    for value in extra.values():
        assert value not in str(info.value)
    with pytest.raises(ValidationError):
        Event.model_validate(raw)


def test_parse_event_errors_do_not_echo_input() -> None:
    with pytest.raises(EventValidationError) as info:
        parse_event(
            {
                "event_type": "TRANSACTION_CREATED",
                "timestamp": "2026-01-01T00:00:00Z",
                "user_id": str(UID),
                "source": "api",
                "metadata": _txn_meta(amount="secret-looking-amount"),
            }
        )
    assert "secret-looking-amount" not in str(info.value)


def test_card_last4_must_be_four_digits() -> None:
    base = {"payment_method_id": str(uuid.uuid4()), "token_reference": "tok_1234"}
    for last4 in ("123", "12345", "12a4"):
        with pytest.raises(ValidationError):
            Event(
                event_type=EventType.PAYMENT_METHOD_ADDED,
                timestamp=TS,
                user_id=UID,
                source=EventSource.API,
                metadata={**base, "card_last4": last4},
            )


def test_event_json_round_trip() -> None:
    e = Event(
        event_type=EventType.TRANSACTION_CREATED,
        timestamp=TS,
        user_id=UID,
        source=EventSource.API,
        metadata=_txn_meta(),
    )
    assert parse_event(e.model_dump(mode="json")) == e
