"""Fraud database schema (SQLAlchemy 2.0 ORM).

Design notes
------------
* Every row is historical: entities carry first/last-seen timestamps and nothing is
  overwritten in a way that destroys history (e.g. address changes supersede, not update).
* ``events`` is the append-only log of every ingested event. Domain tables reference the
  event that produced each row so any feature can be traced back to raw activity.
* Identifiers that could identify a person (IP, device identifier, address) are stored as
  keyed HMAC hashes. Raw IPs are only stored when STORE_RAW_IP is enabled.
* Money is stored as integer minor units plus an ISO 4217 currency code.
* Card numbers, CVV, PINs and passwords have no column anywhere in this schema.
* Counters and "latest" attributes on entity rows (``devices.successful_logins``,
  ``network_identities.distinct_user_count``, ``user_devices.is_trusted``, ``last_seen_at``,
  ``transactions.status`` ...) are *current-state caches*. They are not point-in-time safe
  and are never read by feature engineering, which derives everything from timestamped
  event/observation rows instead.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    false,
    text,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fraud_ai.core.enums import (
    AddressType,
    AuthenticationMethod,
    AuthenticationResult,
    AuthMethod,
    CardFunding,
    ChallengePurpose,
    CredentialStatus,
    Decision,
    DeviceType,
    EventSource,
    EventType,
    FraudType,
    LabelSource,
    LabelValue,
    LoginOutcome,
    NetworkType,
    PaymentAuthStatus,
    PaymentMethodType,
    ReviewResolution,
    ReviewStatus,
    SecurityEventType,
    SignalSource,
    TransactionChannel,
    TransactionDecision,
    TransactionStatus,
    UserStatus,
)
from fraud_ai.database.base import Base, JSONType, enum_type
from fraud_ai.utils.money import from_minor_units
from fraud_ai.utils.time import utcnow


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4)


def _counter() -> Mapped[int]:
    return mapped_column(Integer, nullable=False, default=0, server_default="0")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("length(home_country) = 2", name="home_country_iso2"),)

    user_id: Mapped[uuid.UUID] = _uuid_pk()
    # The application's own (pseudonymous) customer reference. No names/emails stored.
    external_ref: Mapped[str] = mapped_column(String(128), unique=True)
    account_created_at: Mapped[datetime]
    home_country: Mapped[str | None] = mapped_column(String(2))
    status: Mapped[UserStatus] = mapped_column(
        enum_type(UserStatus, "user_status"), default=UserStatus.ACTIVE
    )
    # Synthetic data only: the generating scenario. Must never be used as a model feature.
    synthetic_scenario: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    device_links: Mapped[list[UserDevice]] = relationship(back_populates="user")
    addresses: Mapped[list[Address]] = relationship(back_populates="user")
    payment_methods: Mapped[list[PaymentMethod]] = relationship(back_populates="user")
    transactions: Mapped[list[Transaction]] = relationship(back_populates="user")
    fraud_labels: Mapped[list[FraudLabel]] = relationship(back_populates="user")


class Device(Base):
    """Application-level device history (no invasive fingerprinting)."""

    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("last_seen_at >= first_seen_at", name="seen_order"),
        CheckConstraint(
            "successful_logins >= 0 AND failed_logins >= 0", name="counters_non_negative"
        ),
    )

    device_id: Mapped[uuid.UUID] = _uuid_pk()
    device_hash: Mapped[str] = mapped_column(String(64), unique=True)
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    os_family: Mapped[str | None] = mapped_column(String(64))
    client_family: Mapped[str | None] = mapped_column(String(64))
    device_type: Mapped[DeviceType] = mapped_column(
        enum_type(DeviceType, "device_type"), default=DeviceType.UNKNOWN
    )
    successful_logins: Mapped[int] = _counter()
    failed_logins: Mapped[int] = _counter()

    user_links: Mapped[list[UserDevice]] = relationship(back_populates="device")


class UserDevice(Base):
    """Which accounts have used which device, and whether the user trusts it."""

    __tablename__ = "user_devices"
    __table_args__ = (
        CheckConstraint("last_seen_at >= first_seen_at", name="seen_order"),
        Index("ix_user_devices_device_id", "device_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.device_id", ondelete="CASCADE"), primary_key=True
    )
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    successful_logins: Mapped[int] = _counter()
    failed_logins: Mapped[int] = _counter()

    user: Mapped[User] = relationship(back_populates="device_links")
    device: Mapped[Device] = relationship(back_populates="user_links")


class NetworkIdentity(Base):
    """One IP address as seen by the application, with its intelligence attributes.

    VPN/proxy/Tor flags are risk signals, not proof of fraud. No attempt is made to
    discover the true origin behind an anonymising network.
    """

    __tablename__ = "network_identities"
    __table_args__ = (
        CheckConstraint("ip_version IN (4, 6)", name="ip_version"),
        CheckConstraint(
            "proxy_confidence IS NULL OR (proxy_confidence >= 0 AND proxy_confidence <= 1)",
            name="proxy_confidence_range",
        ),
        CheckConstraint("last_seen_at >= first_seen_at", name="seen_order"),
        CheckConstraint(
            "distinct_user_count >= 0 AND failed_login_count >= 0 AND successful_login_count >= 0",
            name="counters_non_negative",
        ),
        Index("ix_network_identities_asn", "asn"),
    )

    network_identity_id: Mapped[uuid.UUID] = _uuid_pk()
    ip_hash: Mapped[str] = mapped_column(String(64), unique=True)
    ip_address: Mapped[str | None] = mapped_column(String(45))  # only if STORE_RAW_IP
    ip_version: Mapped[int] = mapped_column(SmallInteger)
    asn: Mapped[int | None] = mapped_column(BigInteger)
    asn_org: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(2))
    region: Mapped[str | None] = mapped_column(String(100))
    network_type: Mapped[NetworkType] = mapped_column(
        enum_type(NetworkType, "network_type"), default=NetworkType.UNKNOWN
    )
    is_mobile_network: Mapped[bool | None] = mapped_column(Boolean)
    is_datacenter: Mapped[bool | None] = mapped_column(Boolean)
    is_known_proxy: Mapped[bool | None] = mapped_column(Boolean)
    is_known_vpn: Mapped[bool | None] = mapped_column(Boolean)
    is_tor: Mapped[bool | None] = mapped_column(Boolean)
    proxy_confidence: Mapped[float | None] = mapped_column(Float)
    intel_source: Mapped[str | None] = mapped_column(String(64))
    intel_updated_at: Mapped[datetime | None]
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    distinct_user_count: Mapped[int] = _counter()
    failed_login_count: Mapped[int] = _counter()
    successful_login_count: Mapped[int] = _counter()


class EventRecord(Base):
    """Append-only log of every ingested event (sanitised metadata)."""

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_user_id_occurred_at", "user_id", "occurred_at"),
        Index("ix_events_event_type_occurred_at", "event_type", "occurred_at"),
        Index("ix_events_device_id_occurred_at", "device_id", "occurred_at"),
        CheckConstraint("schema_version >= 1", name="schema_version_positive"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    event_type: Mapped[EventType] = mapped_column(enum_type(EventType, "event_type", 40))
    occurred_at: Mapped[datetime]
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    session_id: Mapped[str | None] = mapped_column(String(128))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.device_id"))
    source: Mapped[EventSource] = mapped_column(enum_type(EventSource, "event_source"))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", default=dict)
    schema_version: Mapped[int] = mapped_column(SmallInteger)
    ingested_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Stage 8: when the event reached the platform (NULL for historical/bulk loads, which
    # are treated as arriving on time). Decisions only use what had arrived by then.
    arrival_time: Mapped[datetime | None]


class NetworkEvent(Base):
    """A single observation of a network identity, with the intel snapshot at that time."""

    __tablename__ = "network_events"
    __table_args__ = (
        Index("ix_network_events_user_id_observed_at", "user_id", "observed_at"),
        Index("ix_network_events_identity_observed_at", "network_identity_id", "observed_at"),
        Index("ix_network_events_identity_user", "network_identity_id", "user_id"),
    )

    network_event_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"), unique=True)
    network_identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("network_identities.network_identity_id")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.device_id"))
    observed_at: Mapped[datetime]
    asn: Mapped[int | None] = mapped_column(BigInteger)
    country: Mapped[str | None] = mapped_column(String(2))
    network_type: Mapped[NetworkType] = mapped_column(
        enum_type(NetworkType, "network_event_network_type"), default=NetworkType.UNKNOWN
    )
    is_known_vpn: Mapped[bool | None] = mapped_column(Boolean)
    is_known_proxy: Mapped[bool | None] = mapped_column(Boolean)
    is_tor: Mapped[bool | None] = mapped_column(Boolean)
    is_datacenter: Mapped[bool | None] = mapped_column(Boolean)
    is_mobile_network: Mapped[bool | None] = mapped_column(Boolean)
    proxy_confidence: Mapped[float | None] = mapped_column(Float)

    network_identity: Mapped[NetworkIdentity] = relationship()


class LoginEvent(Base):
    __tablename__ = "login_events"
    __table_args__ = (
        Index("ix_login_events_user_id_occurred_at", "user_id", "occurred_at"),
        Index("ix_login_events_identity_occurred_at", "network_identity_id", "occurred_at"),
        Index("ix_login_events_device_id_occurred_at", "device_id", "occurred_at"),
    )

    login_event_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"), unique=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.device_id"))
    network_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_identities.network_identity_id")
    )
    session_id: Mapped[str | None] = mapped_column(String(128))
    occurred_at: Mapped[datetime]
    outcome: Mapped[LoginOutcome] = mapped_column(enum_type(LoginOutcome, "login_outcome"))
    auth_method: Mapped[AuthMethod] = mapped_column(enum_type(AuthMethod, "auth_method"))
    mfa_used: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    failure_reason: Mapped[str | None] = mapped_column(String(64))


class Address(Base):
    """Postal address history. Only a keyed hash and coarse location are stored."""

    __tablename__ = "addresses"
    __table_args__ = (
        CheckConstraint(
            "superseded_at IS NULL OR superseded_at >= added_at", name="superseded_order"
        ),
        CheckConstraint("length(country) = 2", name="country_iso2"),
        Index("ix_addresses_user_id_added_at", "user_id", "added_at"),
    )

    address_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id", ondelete="CASCADE"))
    address_hash: Mapped[str] = mapped_column(String(64), index=True)
    address_type: Mapped[AddressType] = mapped_column(enum_type(AddressType, "address_type"))
    country: Mapped[str] = mapped_column(String(2))
    region: Mapped[str | None] = mapped_column(String(100))
    postal_prefix: Mapped[str | None] = mapped_column(String(10))
    added_at: Mapped[datetime]
    superseded_at: Mapped[datetime | None]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    # First successful verification (e.g. AVS / postal). Point-in-time: verified at T iff
    # verified_at <= T.
    verified_at: Mapped[datetime | None]
    replaces_address_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("addresses.address_id")
    )
    created_event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("events.event_id"))

    user: Mapped[User] = relationship(back_populates="addresses")


class PaymentMethod(Base):
    """Tokenised payment method. Never holds a PAN, CVV or PIN - only a vault token ref."""

    __tablename__ = "payment_methods"
    __table_args__ = (
        CheckConstraint("card_last4 IS NULL OR length(card_last4) = 4", name="last4_length"),
        Index("ix_payment_methods_user_id", "user_id"),
    )

    payment_method_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id", ondelete="CASCADE"))
    token_reference: Mapped[str] = mapped_column(String(128), unique=True)
    method_type: Mapped[PaymentMethodType] = mapped_column(
        enum_type(PaymentMethodType, "payment_method_type")
    )
    card_brand: Mapped[str | None] = mapped_column(String(32))
    card_last4: Mapped[str | None] = mapped_column(String(4))
    funding: Mapped[CardFunding | None] = mapped_column(enum_type(CardFunding, "card_funding"))
    issuer_country: Mapped[str | None] = mapped_column(String(2))
    fingerprint_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    added_at: Mapped[datetime]
    # First successful verification (e.g. 3-D Secure). Verified at T iff verified_at <= T.
    verified_at: Mapped[datetime | None]
    created_event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("events.event_id"))

    user: Mapped[User] = relationship(back_populates="payment_methods")


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        CheckConstraint("amount_minor >= 0", name="amount_non_negative"),
        CheckConstraint("length(currency) = 3", name="currency_iso4217"),
        CheckConstraint("decided_at IS NULL OR decided_at >= occurred_at", name="decided_order"),
        Index("ix_transactions_user_id_occurred_at", "user_id", "occurred_at"),
        Index("ix_transactions_payment_method_id", "payment_method_id"),
        Index("ix_transactions_status", "status"),
        # Stage 2: "orders to this address" (point-in-time) was a sequential scan.
        Index(
            "ix_transactions_shipping_address_id_occurred_at", "shipping_address_id", "occurred_at"
        ),
    )

    transaction_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id"))
    payment_method_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("payment_methods.payment_method_id")
    )
    shipping_address_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("addresses.address_id")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.device_id"))
    network_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_identities.network_identity_id")
    )
    session_id: Mapped[str | None] = mapped_column(String(128))
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    merchant_category: Mapped[str | None] = mapped_column(String(4))
    channel: Mapped[TransactionChannel] = mapped_column(
        enum_type(TransactionChannel, "transaction_channel")
    )
    # Current lifecycle state - a later chargeback overwrites it, so it is NOT point-in-time
    # safe. Feature code uses ``decision_outcome`` + ``decided_at`` and labels instead.
    status: Mapped[TransactionStatus] = mapped_column(
        enum_type(TransactionStatus, "transaction_status"), default=TransactionStatus.PENDING
    )
    occurred_at: Mapped[datetime]
    decided_at: Mapped[datetime | None]
    # Immutable authorisation outcome, known from ``decided_at``.
    decision_outcome: Mapped[TransactionDecision | None] = mapped_column(
        enum_type(TransactionDecision, "transaction_decision", 16)
    )
    decision_reason: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User] = relationship(back_populates="transactions")
    payment_method: Mapped[PaymentMethod | None] = relationship()

    @property
    def amount(self) -> Decimal:
        return from_minor_units(self.amount_minor, self.currency)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index(
            "ix_security_events_user_type_occurred", "user_id", "security_event_type", "occurred_at"
        ),
    )

    security_event_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id"))
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.device_id"))
    network_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_identities.network_identity_id")
    )
    security_event_type: Mapped[SecurityEventType] = mapped_column(
        enum_type(SecurityEventType, "security_event_type", 40)
    )
    occurred_at: Mapped[datetime]
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)


class FraudSignal(Base):
    """An individual piece of risk evidence (e.g. VPN detected, velocity exceeded)."""

    __tablename__ = "fraud_signals"
    __table_args__ = (
        CheckConstraint(
            "event_id IS NOT NULL OR user_id IS NOT NULL OR transaction_id IS NOT NULL",
            name="has_subject",
        ),
        Index("ix_fraud_signals_user_id_observed_at", "user_id", "observed_at"),
        Index("ix_fraud_signals_transaction_id", "transaction_id"),
    )

    signal_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("events.event_id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("transactions.transaction_id")
    )
    signal_name: Mapped[str] = mapped_column(String(64))
    signal_source: Mapped[SignalSource] = mapped_column(enum_type(SignalSource, "signal_source"))
    value: Mapped[float | None] = mapped_column(Float)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    observed_at: Mapped[datetime]


class ModelVersion(Base):
    """Reproducibility record for every trained model artefact."""

    __tablename__ = "model_versions"
    __table_args__ = (
        UniqueConstraint("model_name", "model_version"),
        # At most one active version per model name.
        Index(
            "uq_model_versions_one_active",
            "model_name",
            unique=True,
            postgresql_where=text("active"),
            sqlite_where=text("active"),
        ),
    )

    model_version_id: Mapped[uuid.UUID] = _uuid_pk()
    model_name: Mapped[str] = mapped_column(String(100))
    model_version: Mapped[str] = mapped_column(String(50))
    algorithm: Mapped[str | None] = mapped_column(String(64))
    training_timestamp: Mapped[datetime]
    training_dataset_version: Mapped[str] = mapped_column(String(100))
    feature_version: Mapped[str] = mapped_column(String(50))
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    model_path: Mapped[str] = mapped_column(String(1024))
    active: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Stage 3 (migration 0003): everything needed to reproduce and verify a model.
    dataset_fingerprint: Mapped[str | None] = mapped_column(String(64))
    feature_catalogue_fingerprint: Mapped[str | None] = mapped_column(String(64))
    preprocessing_version: Mapped[str | None] = mapped_column(String(50))
    train_rows: Mapped[int | None] = mapped_column(Integer)
    validation_rows: Mapped[int | None] = mapped_column(Integer)
    test_rows: Mapped[int | None] = mapped_column(Integer)
    random_seed: Mapped[int | None] = mapped_column(Integer)
    hyperparameters: Mapped[dict[str, Any] | None]
    training_manifest: Mapped[dict[str, Any] | None]
    # SHA-256 of the serialised estimator; verified before the artefact is ever loaded.
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    # Evaluation threshold recorded with the model - an analysis setting, not a decision.
    default_threshold: Mapped[float | None] = mapped_column(Float)

    predictions: Mapped[list[ModelPrediction]] = relationship(back_populates="model")
    # Stage 11: Ed25519 signatures over the artefact (loaded with the row, so a detached
    # record can still be verified at load time).
    signatures: Mapped[list[ModelArtifactSignature]] = relationship(
        back_populates="model",
        lazy="selectin",
        order_by="ModelArtifactSignature.signed_at.desc()",
    )


class ModelPrediction(Base):
    """Every model output is stored so model versions can be compared over time."""

    __tablename__ = "model_predictions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["model_name", "model_version"],
            ["model_versions.model_name", "model_versions.model_version"],
        ),
        CheckConstraint(
            "fraud_probability >= 0 AND fraud_probability <= 1", name="probability_range"
        ),
        CheckConstraint("threshold >= 0 AND threshold <= 1", name="threshold_range"),
        CheckConstraint(
            "(predicted_class = 1 AND fraud_probability >= threshold) OR "
            "(predicted_class = 0 AND fraud_probability < threshold)",
            name="class_matches_threshold",
        ),
        Index(
            "ix_model_predictions_model_ts", "model_name", "model_version", "prediction_timestamp"
        ),
        Index("ix_model_predictions_transaction_id", "transaction_id"),
        Index("ix_model_predictions_event_id", "event_id"),
        # One prediction per event per model version: a rescore never silently replaces it.
        UniqueConstraint("event_id", "model_name", "model_version"),
    )

    prediction_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"))
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("transactions.transaction_id")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    model_name: Mapped[str] = mapped_column(String(100))
    model_version: Mapped[str] = mapped_column(String(50))
    prediction_timestamp: Mapped[datetime] = mapped_column(default=utcnow)
    fraud_probability: Mapped[float] = mapped_column(Float)
    predicted_class: Mapped[int] = mapped_column(SmallInteger)
    threshold: Mapped[float] = mapped_column(Float)
    feature_version: Mapped[str] = mapped_column(String(50))
    feature_snapshot_reference: Mapped[str | None] = mapped_column(String(512))
    # Stage 3: the exact persisted vector the model scored.
    feature_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("feature_snapshots.snapshot_id")
    )

    model: Mapped[ModelVersion] = relationship(back_populates="predictions")


class RiskAssessment(Base):
    """An issued risk decision (Stage 8): model scores + rules + a versioned policy.

    Immutable once written. New evidence produces a new ``assessment_version`` that
    ``supersedes`` the earlier row; nothing is updated in place. ``idempotency_key`` is
    SHA-256 of (event, policy version, assessment version), so a duplicate delivery of an
    event returns the stored assessment instead of deciding again.
    """

    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint(
            "ml_probability IS NULL OR (ml_probability >= 0 AND ml_probability <= 1)",
            name="ml_probability_range",
        ),
        CheckConstraint(
            "final_risk_score IS NULL OR (final_risk_score >= 0 AND final_risk_score <= 1)",
            name="final_score_range",
        ),
        CheckConstraint("assessment_version >= 1", name="assessment_version_positive"),
        UniqueConstraint("event_id", "assessment_version"),
        UniqueConstraint("idempotency_key"),
        Index("ix_risk_assessments_user_id_assessed_at", "user_id", "assessed_at"),
        Index("ix_risk_assessments_transaction_id", "transaction_id"),
        Index("ix_risk_assessments_assessed_at", "assessed_at"),
    )

    assessment_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"))
    assessment_version: Mapped[int] = mapped_column(Integer, default=1)
    supersedes_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("risk_assessments.assessment_id")
    )
    idempotency_key: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16), default="live")
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("transactions.transaction_id")
    )
    prediction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("model_predictions.prediction_id")
    )
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("policy_deployments.deployment_id")
    )
    assessed_at: Mapped[datetime] = mapped_column(default=utcnow)
    event_time: Mapped[datetime | None]
    arrival_time: Mapped[datetime | None]
    lateness_seconds: Mapped[float | None] = mapped_column(Float)
    policy_version: Mapped[str] = mapped_column(String(32))
    rules_version: Mapped[str | None] = mapped_column(String(32))
    primary_model: Mapped[str | None] = mapped_column(String(120))
    ml_probability: Mapped[float | None] = mapped_column(Float)
    calibrated_score: Mapped[float | None] = mapped_column(Float)
    final_risk_score: Mapped[float | None] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(16))
    decision: Mapped[Decision] = mapped_column(enum_type(Decision, "decision"))
    reason_codes: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    model_scores: Mapped[dict[str, Any]] = mapped_column(default=dict)
    triggered_rules: Mapped[dict[str, Any]] = mapped_column(default=dict)
    shadow: Mapped[dict[str, Any]] = mapped_column(default=dict)
    action: Mapped[dict[str, Any]] = mapped_column(default=dict)
    latency_ms: Mapped[dict[str, Any]] = mapped_column(default=dict)
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False)
    failures: Mapped[list[Any]] = mapped_column(JSONType, default=list)


class RiskPolicyRecord(Base):
    """An immutable, versioned risk policy (Stage 8).

    ``definition`` is the complete policy (model set, calibrations, bands, rule set, rule
    severities, fallbacks); ``definition_sha256`` is verified on every load, so a policy
    that was edited in place is refused. ``derivation`` records how the bands were
    proposed (synthetic Stage 4 analysis) and the drift baselines.
    """

    __tablename__ = "risk_policies"
    __table_args__ = (
        UniqueConstraint("policy_version"),
        CheckConstraint("length(definition_sha256) = 64", name="definition_sha256_length"),
    )

    policy_id: Mapped[uuid.UUID] = _uuid_pk()
    policy_version: Mapped[str] = mapped_column(String(32))
    definition: Mapped[dict[str, Any]]
    definition_sha256: Mapped[str] = mapped_column(String(64))
    derivation: Mapped[dict[str, Any]] = mapped_column(default=dict)
    synthetic_derived: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class PolicyDeployment(Base):
    """Append-only deployment history. The row with the highest ``sequence`` is active.

    A deployment names the active policy plus shadow models and shadow policies, which are
    scored and recorded but can never affect a decision.
    """

    __tablename__ = "policy_deployments"
    __table_args__ = (UniqueConstraint("sequence"),)

    deployment_id: Mapped[uuid.UUID] = _uuid_pk()
    sequence: Mapped[int] = mapped_column(Integer)
    policy_version: Mapped[str] = mapped_column(ForeignKey("risk_policies.policy_version"))
    shadow_models: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    shadow_policies: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    config_sha256: Mapped[str] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(String(500))
    activated_at: Mapped[datetime] = mapped_column(default=utcnow)
    activated_by: Mapped[str | None] = mapped_column(String(200))  # Stage 10


class ReviewItem(Base):
    """A manual-review queue entry for one assessment. Resolving it never changes the
    assessment; the outcome is recorded in ``review_outcomes``."""

    __tablename__ = "review_queue"
    __table_args__ = (
        UniqueConstraint("assessment_id"),
        CheckConstraint("priority >= 1 AND priority <= 5", name="priority_range"),
        Index("ix_review_queue_status_priority", "status", "priority"),
    )

    review_id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("risk_assessments.assessment_id"))
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"))
    priority: Mapped[int] = mapped_column(SmallInteger)
    reason_codes: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    status: Mapped[ReviewStatus] = mapped_column(
        enum_type(ReviewStatus, "review_status"), default=ReviewStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    reviewed_at: Mapped[datetime | None]
    outcome: Mapped[ReviewResolution | None] = mapped_column(
        enum_type(ReviewResolution, "review_resolution")
    )


class ReviewOutcome(Base):
    """An analyst's review outcome (append-only; several per item are possible when more
    information was requested first)."""

    __tablename__ = "review_outcomes"
    __table_args__ = (Index("ix_review_outcomes_review_id", "review_id"),)

    outcome_id: Mapped[uuid.UUID] = _uuid_pk()
    review_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("review_queue.review_id"))
    resolution: Mapped[ReviewResolution] = mapped_column(
        enum_type(ReviewResolution, "review_resolution")
    )
    note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class FraudLabel(Base):
    """Ground truth for supervised learning.

    ``labelled_at`` is when the label became known; training must only use labels known
    at the relevant point in time to avoid leakage.
    """

    __tablename__ = "fraud_labels"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        CheckConstraint("label <> 'FRAUD' OR fraud_type IS NOT NULL", name="fraud_requires_type"),
        Index("ix_fraud_labels_user_id", "user_id"),
        Index("ix_fraud_labels_transaction_id", "transaction_id"),
    )

    label_id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id"))
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("transactions.transaction_id")
    )
    # The labelled event (e.g. a malicious login) and the event that produced the label.
    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("events.event_id"))
    source_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("events.event_id"), unique=True
    )
    label: Mapped[LabelValue] = mapped_column(enum_type(LabelValue, "label_value"))
    fraud_type: Mapped[FraudType | None] = mapped_column(enum_type(FraudType, "fraud_type"))
    label_source: Mapped[LabelSource] = mapped_column(enum_type(LabelSource, "label_source"))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    labelled_at: Mapped[datetime]
    notes: Mapped[str | None] = mapped_column(Text)

    user: Mapped[User] = relationship(back_populates="fraud_labels")


class ModelCalibration(Base):
    """A post-hoc calibrator fitted for a model version (Stage 4, migration 0004).

    Always fitted on a non-test split (``fitted_on``) of the model's recorded dataset. The
    uncalibrated model is unchanged; calibration is an additional, explicit transformation.
    """

    __tablename__ = "model_calibrations"
    __table_args__ = (
        UniqueConstraint("model_version_id", "method", "dataset_fingerprint"),
        CheckConstraint("fitted_on <> 'test'", name="never_fitted_on_test"),
    )

    calibration_id: Mapped[uuid.UUID] = _uuid_pk()
    model_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("model_versions.model_version_id")
    )
    method: Mapped[str] = mapped_column(String(32))
    fitted_on: Mapped[str] = mapped_column(String(32))
    dataset_fingerprint: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict[str, Any]]
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class FeatureSnapshot(Base):
    """The exact feature vector computed for an event, as of a point in time.

    ``features`` holds the canonical payload (values + missing reasons) and ``feature_hash``
    is the SHA-256 of its canonical JSON serialisation. Snapshots are immutable: the same
    (event, feature_version, as_of_timestamp) always maps to one row, and a recomputation
    that disagrees with the stored hash is reported as drift, never silently overwritten.
    """

    __tablename__ = "feature_snapshots"
    __table_args__ = (
        UniqueConstraint("event_id", "feature_version", "as_of_timestamp"),
        CheckConstraint("length(feature_hash) = 64", name="feature_hash_sha256"),
        CheckConstraint("source_event_count >= 0", name="source_event_count_non_negative"),
        Index("ix_feature_snapshots_version_as_of", "feature_version", "as_of_timestamp"),
        Index("ix_feature_snapshots_user_id", "user_id"),
        Index("ix_feature_snapshots_transaction_id", "transaction_id"),
    )

    snapshot_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.user_id"))
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("transactions.transaction_id")
    )
    login_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("login_events.login_event_id")
    )
    feature_version: Mapped[str] = mapped_column(String(50))
    generated_at: Mapped[datetime] = mapped_column(default=utcnow)
    as_of_timestamp: Mapped[datetime]
    features: Mapped[dict[str, Any]]
    feature_hash: Mapped[str] = mapped_column(String(64))
    source_event_count: Mapped[int] = mapped_column(Integer)


class Investigation(Base):
    """A validated analyst explanation of one event from the local LLM layer (Stage 7).

    Decision support only: nothing here changes a score, label, threshold, rule or decision.
    Rows are append-only. Re-investigating an event adds ``explanation_version`` + 1 and
    never overwrites an earlier explanation. Only output that passed validation is stored.
    ``evidence_packet`` is the privacy-checked packet the model saw (no raw identifiers), and
    ``evidence_packet_sha256`` is the SHA-256 of its canonical JSON.
    """

    __tablename__ = "investigations"
    __table_args__ = (
        UniqueConstraint("event_id", "explanation_version"),
        CheckConstraint("explanation_version >= 1", name="explanation_version_positive"),
        CheckConstraint("length(evidence_packet_sha256) = 64", name="packet_hash_sha256"),
        Index("ix_investigations_event_id", "event_id"),
    )

    investigation_id: Mapped[uuid.UUID] = _uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("events.event_id"))
    explanation_version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    explanation_text: Mapped[str] = mapped_column(Text)
    explanation_json: Mapped[dict[str, Any]]
    explanation_schema_version: Mapped[str] = mapped_column(String(64))
    evidence_packet: Mapped[dict[str, Any]]
    evidence_packet_sha256: Mapped[str] = mapped_column(String(64))
    evidence_schema_version: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(64))
    llm_runtime: Mapped[str] = mapped_column(String(32))
    llm_model: Mapped[str] = mapped_column(String(200))
    llm_model_version: Mapped[str | None] = mapped_column(String(200))
    generation_parameters: Mapped[dict[str, Any]]
    validation: Mapped[dict[str, Any]]
    latency_seconds: Mapped[float] = mapped_column(Float)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)


class ServiceApiKey(Base):
    """A service-to-service API key (Stage 9). Only a salted SHA-256 of the 256-bit
    random secret is stored; the secret is shown once at creation."""

    __tablename__ = "service_api_keys"
    __table_args__ = (
        UniqueConstraint("key_id"),
        CheckConstraint("length(secret_sha256) = 64", name="secret_sha256_length"),
    )

    api_key_pk: Mapped[uuid.UUID] = _uuid_pk()
    key_id: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(100))
    secret_salt: Mapped[str] = mapped_column(String(64))
    secret_sha256: Mapped[str] = mapped_column(String(64))
    scopes: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]
    # Stage 10: expiry, last use (throttled updates) and rotation lineage.
    expires_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    rotated_from_key_id: Mapped[str | None] = mapped_column(String(40))

    def status_at(self, now: datetime) -> str:
        """``revoked``, ``expired`` or ``active`` (derived, never stored separately)."""
        if self.revoked_at is not None:
            return "revoked"
        expires = self.expires_at
        if expires is not None:
            aware = expires if expires.tzinfo else expires.replace(tzinfo=now.tzinfo)
            if aware <= now:
                return "expired"
        return "active"


class RequestIdempotency(Base):
    """Idempotency-Key records: the first response for (key, route, Idempotency-Key)."""

    __tablename__ = "request_idempotency"
    __table_args__ = (
        UniqueConstraint("api_key_id", "route", "idempotency_key"),
        Index("ix_request_idempotency_created_at", "created_at"),
    )

    record_id: Mapped[uuid.UUID] = _uuid_pk()
    api_key_id: Mapped[str] = mapped_column(String(40))
    route: Mapped[str] = mapped_column(String(100))
    idempotency_key: Mapped[str] = mapped_column(String(100))
    request_sha256: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), default="in_progress")
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    policy_version: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class RequestReplayToken(Base):
    """Signatures already accepted (replay protection); kept until they expire."""

    __tablename__ = "request_replay_tokens"
    __table_args__ = (
        UniqueConstraint("signature_sha256"),
        Index("ix_request_replay_tokens_expires_at", "expires_at"),
    )

    token_id: Mapped[uuid.UUID] = _uuid_pk()
    signer: Mapped[str] = mapped_column(String(64))
    signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    received_at: Mapped[datetime] = mapped_column(default=utcnow)


class WebAuthnCredential(Base):
    """A registered passkey: public key material only. The private key never leaves the
    user's authenticator."""

    __tablename__ = "webauthn_credentials"
    __table_args__ = (
        UniqueConstraint("credential_id"),
        Index("ix_webauthn_credentials_user_id", "user_id"),
        CheckConstraint("sign_count >= 0", name="sign_count_non_negative"),
    )

    credential_pk: Mapped[uuid.UUID] = _uuid_pk()
    credential_id: Mapped[str] = mapped_column(String(1400))  # base64url
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id"))
    public_key: Mapped[bytes] = mapped_column(LargeBinary)  # COSE public key
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    transports: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    status: Mapped[CredentialStatus] = mapped_column(
        enum_type(CredentialStatus, "credential_status"), default=CredentialStatus.ACTIVE
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None]


class AuthenticationChallenge(Base):
    """A single-use, short-lived WebAuthn challenge. Only its SHA-256 is stored."""

    __tablename__ = "authentication_challenges"
    __table_args__ = (
        UniqueConstraint("challenge_sha256"),
        Index("ix_authentication_challenges_assessment_id", "assessment_id"),
    )

    challenge_id: Mapped[uuid.UUID] = _uuid_pk()
    purpose: Mapped[ChallengePurpose] = mapped_column(
        enum_type(ChallengePurpose, "challenge_purpose")
    )
    challenge_sha256: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id"))
    session_id: Mapped[str | None] = mapped_column(String(128))
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("risk_assessments.assessment_id")
    )
    api_key_id: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]


class AuthenticationAttempt(Base):
    """Append-only outcome of one step-up attempt for an assessment."""

    __tablename__ = "authentication_attempts"
    __table_args__ = (
        UniqueConstraint("assessment_id", "attempt_number"),
        CheckConstraint("attempt_number >= 1", name="attempt_number_positive"),
    )

    attempt_id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("risk_assessments.assessment_id"))
    method: Mapped[AuthenticationMethod] = mapped_column(
        enum_type(AuthenticationMethod, "authentication_method")
    )
    attempt_number: Mapped[int] = mapped_column(Integer)
    result: Mapped[AuthenticationResult] = mapped_column(
        enum_type(AuthenticationResult, "authentication_result")
    )
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    credential_ref: Mapped[str | None] = mapped_column(String(100))
    challenge_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("authentication_challenges.challenge_id")
    )
    payment_request_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("payment_auth_requests.request_id")
    )
    followup_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("risk_assessments.assessment_id")
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class PaymentAuthRequest(Base):
    """A request to an EXTERNAL payment-authentication provider (e.g. a processor's
    3-D Secure service). Only the processor's token reference is used, stored as a keyed
    hash. No PAN, CVV, PIN or track data exists anywhere."""

    __tablename__ = "payment_auth_requests"
    __table_args__ = (
        UniqueConstraint("provider", "provider_reference"),
        Index("ix_payment_auth_requests_assessment_id", "assessment_id"),
    )

    request_id: Mapped[uuid.UUID] = _uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("risk_assessments.assessment_id"))
    provider: Mapped[str] = mapped_column(String(32))
    provider_reference: Mapped[str] = mapped_column(String(100))
    token_ref_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[PaymentAuthStatus] = mapped_column(
        enum_type(PaymentAuthStatus, "payment_auth_status")
    )
    attempt_number: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    completed_at: Mapped[datetime | None]


class AuditEvent(Base):
    """An append-only, hash-chained record of an administrative action (Stage 10).

    ``event_sha256`` covers the event's fields and ``previous_sha256``, so editing or
    deleting any event breaks the chain (``fraud-ai audit verify``). Database triggers
    refuse UPDATE and DELETE. Details never contain secrets.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("sequence"),
        Index("ix_audit_events_action", "action"),
        CheckConstraint("length(event_sha256) = 64", name="event_sha256_length"),
    )

    event_id: Mapped[uuid.UUID] = _uuid_pk()
    sequence: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(120))
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    previous_sha256: Mapped[str | None] = mapped_column(String(64))
    event_sha256: Mapped[str] = mapped_column(String(64))


class PolicyLifecycleEvent(Base):
    """Append-only promotion history of a policy (Stage 10):
    ``shadow`` → ``evaluation`` → ``candidate`` (or ``rejected``). Activation is separate
    and explicit; nothing is promoted automatically."""

    __tablename__ = "policy_lifecycle_events"
    __table_args__ = (
        CheckConstraint(
            "stage IN ('shadow', 'evaluation', 'candidate', 'rejected')", name="stage_known"
        ),
        Index("ix_policy_lifecycle_policy", "policy_version"),
    )

    lifecycle_id: Mapped[uuid.UUID] = _uuid_pk()
    policy_version: Mapped[str] = mapped_column(ForeignKey("risk_policies.policy_version"))
    stage: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str] = mapped_column(String(200))
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class ModelArtifactSignature(Base):
    """An Ed25519 signature over a model artefact (Stage 11).

    The signed statement names the model row, its registered digest and the SHA-256 of
    **every** file in the artefact directory (``files``), so no file can be added, removed
    or changed without invalidating it. The private key never reaches the database; only the
    key id, algorithm and signature are stored. Rows are never updated: re-signing (for
    example with a rotated key) adds a row.
    """

    __tablename__ = "model_artifact_signatures"
    __table_args__ = (
        CheckConstraint("algorithm = 'ed25519'", name="algorithm_known"),
        Index("ix_model_artifact_signatures_model", "model_version_id"),
    )

    signature_id: Mapped[uuid.UUID] = _uuid_pk()
    model_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("model_versions.model_version_id")
    )
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    files: Mapped[dict[str, Any]] = mapped_column(default=dict)
    key_id: Mapped[str] = mapped_column(String(40))
    algorithm: Mapped[str] = mapped_column(String(16))
    signature: Mapped[str] = mapped_column(String(128))
    signed_at: Mapped[datetime] = mapped_column(default=utcnow)
    signed_by: Mapped[str] = mapped_column(String(200))

    model: Mapped[ModelVersion] = relationship(back_populates="signatures")


class PolicyApproval(Base):
    """One operator's approval of a candidate policy (Stage 11 two-person rule).

    Append-only. Activation under ``POLICY_APPROVALS_REQUIRED=2`` needs unexpired approvals
    from two **different** operator identities; the same operator approving twice is
    refused, and the database enforces it too (unique ``(policy_version, operator)``).
    """

    __tablename__ = "policy_approvals"
    __table_args__ = (
        UniqueConstraint("policy_version", "operator", name="uq_policy_approval_operator"),
        Index("ix_policy_approvals_policy", "policy_version"),
    )

    approval_id: Mapped[uuid.UUID] = _uuid_pk()
    policy_version: Mapped[str] = mapped_column(ForeignKey("risk_policies.policy_version"))
    policy_sha256: Mapped[str] = mapped_column(String(64))
    operator: Mapped[str] = mapped_column(String(120))
    note: Mapped[str] = mapped_column(String(500))
    approved_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None]


ALL_TABLES = sorted(Base.metadata.tables)
