"""The internal event model.

Every piece of activity enters the platform as an :class:`Event` envelope. Downstream
components (event processor, feature engineering, scoring) all consume this one format.

Envelope fields: event_id, event_type, timestamp, user_id, session_id, device_id, source,
metadata, schema_version. ``metadata`` carries an event-type specific payload which is
validated against a strict schema (:data:`PAYLOAD_SCHEMAS`) - unknown fields are rejected so
that sensitive data cannot slip in unnoticed.

``device_id`` is the application-level device identifier reported by the client (for
example an app-install ID). It is pseudonymised before storage.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from fraud_ai.core.enums import (
    AddressType,
    AuthMethod,
    CardFunding,
    DeviceType,
    EventSource,
    EventType,
    FraudType,
    LabelSource,
    NetworkType,
    PaymentMethodType,
    TransactionChannel,
)
from fraud_ai.core.exceptions import EventValidationError, SecurityViolationError
from fraud_ai.security.redaction import find_forbidden_data
from fraud_ai.utils.money import MoneyError, normalise_currency, to_minor_units
from fraud_ai.utils.time import ensure_utc

CURRENT_SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})

# Events that may legitimately arrive without a resolved user (e.g. a login attempt
# against an unknown username).
USER_OPTIONAL_EVENTS = frozenset({EventType.LOGIN_ATTEMPT, EventType.LOGIN_FAILURE})


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NetworkContext(_Payload):
    """Network information legitimately visible to the application.

    Intelligence attributes (VPN, proxy, Tor, datacenter...) come from whatever upstream
    intel source the deployment uses and are recorded with ``intel_source``. They are risk
    signals, never proof of fraud. The platform does not attempt to unmask VPN/proxy users.
    """

    ip: str
    asn: int | None = Field(default=None, ge=0)
    asn_org: str | None = Field(default=None, max_length=255)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    region: str | None = Field(default=None, max_length=100)
    network_type: NetworkType = NetworkType.UNKNOWN
    is_mobile_network: bool | None = None
    is_datacenter: bool | None = None
    is_known_proxy: bool | None = None
    is_known_vpn: bool | None = None
    is_tor: bool | None = None
    proxy_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    intel_source: str | None = Field(default=None, max_length=64)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return ipaddress.ip_address(value.strip()).compressed

    @field_validator("country")
    @classmethod
    def _upper_country(cls, value: str | None) -> str | None:
        return value.upper() if value else value


class DeviceContext(_Payload):
    """Coarse, application-level device description. No fingerprinting or surveillance."""

    os_family: str | None = Field(default=None, max_length=64)
    client_family: str | None = Field(default=None, max_length=64)
    device_type: DeviceType = DeviceType.UNKNOWN


class AccountCreatedPayload(_Payload):
    external_ref: str = Field(min_length=1, max_length=128)
    home_country: str | None = Field(default=None, min_length=2, max_length=2)
    synthetic_scenario: str | None = Field(default=None, max_length=64)
    network: NetworkContext | None = None
    device: DeviceContext | None = None


class LoginPayload(_Payload):
    auth_method: AuthMethod = AuthMethod.PASSWORD
    mfa_used: bool = False
    failure_reason: str | None = Field(default=None, max_length=64)
    network: NetworkContext | None = None
    device: DeviceContext | None = None


class PasswordResetPayload(_Payload):
    method: str = Field(default="email_link", max_length=32)
    network: NetworkContext | None = None
    device: DeviceContext | None = None


class NewDevicePayload(_Payload):
    device: DeviceContext
    network: NetworkContext | None = None


class AddressPayload(_Payload):
    """``full_address`` is only used to derive a keyed hash and is never persisted."""

    address_id: uuid.UUID
    address_type: AddressType = AddressType.HOME
    full_address: str = Field(min_length=3, max_length=1000)
    country: str = Field(min_length=2, max_length=2)
    region: str | None = Field(default=None, max_length=100)
    postal_prefix: str | None = Field(default=None, max_length=10)
    replaces_address_id: uuid.UUID | None = None


class PaymentMethodAddedPayload(_Payload):
    """Safe payment metadata only. Card numbers, CVV and PINs are rejected upstream."""

    payment_method_id: uuid.UUID
    token_reference: str = Field(min_length=4, max_length=128)
    method_type: PaymentMethodType = PaymentMethodType.CARD
    card_brand: str | None = Field(default=None, max_length=32)
    card_last4: str | None = Field(default=None, pattern=r"^\d{4}$")
    funding: CardFunding | None = None
    issuer_country: str | None = Field(default=None, min_length=2, max_length=2)
    fingerprint: str | None = Field(default=None, max_length=128)


class TransactionCreatedPayload(_Payload):
    transaction_id: uuid.UUID
    amount: Decimal
    currency: str
    payment_method_id: uuid.UUID | None = None
    shipping_address_id: uuid.UUID | None = None
    merchant_category: str | None = Field(default=None, pattern=r"^\d{4}$")
    channel: TransactionChannel = TransactionChannel.WEB
    network: NetworkContext | None = None
    device: DeviceContext | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _no_float_money(cls, value: Any) -> Any:
        if isinstance(value, float):
            raise ValueError("amount must be a string or integer, never a float")
        return value

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        return normalise_currency(value)

    @model_validator(mode="after")
    def _amount_fits_currency(self) -> TransactionCreatedPayload:
        if self.amount < 0:
            raise ValueError("amount must not be negative")
        try:
            to_minor_units(self.amount, self.currency)
        except MoneyError as exc:
            raise ValueError(str(exc)) from exc
        return self

    @property
    def amount_minor(self) -> int:
        return to_minor_units(self.amount, self.currency)


class TransactionDecisionPayload(_Payload):
    transaction_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=64)


class ChargebackPayload(_Payload):
    transaction_id: uuid.UUID
    reason_code: str = Field(min_length=1, max_length=32)
    fraud_type: FraudType = FraudType.STOLEN_PAYMENT_METHOD


class FraudConfirmedPayload(_Payload):
    transaction_id: uuid.UUID | None = None
    target_event_id: uuid.UUID | None = None
    fraud_type: FraudType
    label_source: LabelSource = LabelSource.ANALYST
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    notes: str | None = Field(default=None, max_length=1000)


PAYLOAD_SCHEMAS: dict[EventType, type[_Payload]] = {
    EventType.ACCOUNT_CREATED: AccountCreatedPayload,
    EventType.LOGIN_ATTEMPT: LoginPayload,
    EventType.LOGIN_SUCCESS: LoginPayload,
    EventType.LOGIN_FAILURE: LoginPayload,
    EventType.PASSWORD_RESET: PasswordResetPayload,
    EventType.NEW_DEVICE: NewDevicePayload,
    EventType.ADDRESS_ADDED: AddressPayload,
    EventType.ADDRESS_CHANGED: AddressPayload,
    EventType.PAYMENT_METHOD_ADDED: PaymentMethodAddedPayload,
    EventType.TRANSACTION_CREATED: TransactionCreatedPayload,
    EventType.TRANSACTION_APPROVED: TransactionDecisionPayload,
    EventType.TRANSACTION_DECLINED: TransactionDecisionPayload,
    EventType.CHARGEBACK: ChargebackPayload,
    EventType.FRAUD_CONFIRMED: FraudConfirmedPayload,
}


class Event(BaseModel):
    """Immutable event envelope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_type: EventType
    timestamp: AwareDatetime
    user_id: uuid.UUID | None = None
    session_id: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=256)
    source: EventSource
    metadata: dict[str, Any] = Field(default_factory=dict)
    schema_version: int = CURRENT_SCHEMA_VERSION

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _validate(self) -> Event:
        if self.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.user_id is None and self.event_type not in USER_OPTIONAL_EVENTS:
            raise ValueError(f"{self.event_type} requires user_id")
        forbidden = find_forbidden_data(self.metadata, "metadata")
        if forbidden:
            # Do not echo the values - only the offending paths.
            raise ValueError(f"forbidden sensitive data at: {', '.join(forbidden)}")
        # Validate eagerly so an invalid event can never be constructed.
        PAYLOAD_SCHEMAS[self.event_type].model_validate(self.metadata)
        return self

    def payload(self) -> Any:
        """Return the metadata parsed into its typed, event-type specific schema."""
        return PAYLOAD_SCHEMAS[self.event_type].model_validate(self.metadata)


def parse_event(data: dict[str, Any]) -> Event:
    """Build an :class:`Event` from untrusted input, raising domain errors."""
    forbidden = find_forbidden_data(data)
    if forbidden:
        raise SecurityViolationError(f"event contains forbidden sensitive data at: {forbidden}")
    try:
        return Event.model_validate(data)
    except ValidationError as exc:
        # include_input=False keeps raw (potentially sensitive) values out of errors/logs.
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise EventValidationError(details) from None
