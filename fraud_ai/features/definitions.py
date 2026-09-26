"""Machine-readable feature definitions.

Every feature in a feature version is declared here with its type, category, nullability,
units, bounds, applicability, source data and leakage notes. The definitions are the
contract between feature engineering, validation, snapshots, dataset building and the
documentation (FEATURES.md is checked against them by a test).

A feature version is immutable once released. Changing what a feature means, how it is
computed or its type requires a new version (``fraud-features-1.1.0`` ...). The
``fingerprint`` of a feature set is pinned in the test-suite so that an accidental change
to a released version fails loudly instead of silently altering historical vectors.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from fraud_ai.features.windows import RECENT_WINDOW, WINDOWS


class FeatureType(StrEnum):
    FLOAT = "float"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    CATEGORICAL = "categorical"


class FeatureCategory(StrEnum):
    CONTEXT = "context"
    ACCOUNT = "account"
    DEVICE = "device"
    NETWORK = "network"
    ADDRESS = "address"
    PAYMENT = "payment"
    TRANSACTION = "transaction"
    LOGIN_VELOCITY = "login_velocity"
    SECURITY = "security"
    BEHAVIOURAL = "behavioural"
    CROSS_ENTITY = "cross_entity"


class EventKind(StrEnum):
    """The kinds of events a feature vector can be computed for."""

    LOGIN = "login"
    TRANSACTION = "transaction"


BOTH = frozenset({EventKind.LOGIN, EventKind.TRANSACTION})
TXN_ONLY = frozenset({EventKind.TRANSACTION})
LOGIN_ONLY = frozenset({EventKind.LOGIN})

SAFE_AS_OF = "Filtered to records with timestamp <= as_of_timestamp."
SAFE_PRIOR = "Only records with timestamp <= as_of_timestamp, excluding the scored event itself."
SAFE_EVENT = "An attribute of the scored event itself, known at the moment it occurred."
SAFE_SNAPSHOT = (
    "Taken from the network observation recorded with the scored event (the intel as it "
    "was then), never from the mutable network_identities row."
)


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    description: str
    dtype: FeatureType
    category: FeatureCategory
    nullable: bool
    sources: tuple[str, ...]
    leakage_notes: str
    feature_version: str
    rationale: str = ""
    units: str | None = None
    applies_to: frozenset[EventKind] = BOTH
    min_value: float | None = None
    max_value: float | None = None
    allowed_values: tuple[str, ...] | None = None
    missing_when: str = ""

    def computational_signature(self) -> dict[str, Any]:
        """Everything that affects the stored value (documentation excluded)."""
        return {
            "name": self.name,
            "dtype": self.dtype.value,
            "category": self.category.value,
            "nullable": self.nullable,
            "units": self.units,
            "applies_to": sorted(k.value for k in self.applies_to),
            "min_value": self.min_value,
            "max_value": self.max_value,
            "allowed_values": list(self.allowed_values) if self.allowed_values else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.computational_signature(),
            "description": self.description,
            "rationale": self.rationale,
            "sources": list(self.sources),
            "leakage_notes": self.leakage_notes,
            "missing_when": self.missing_when,
            "feature_version": self.feature_version,
        }


@dataclass(frozen=True)
class FeatureSet:
    version: str
    definitions: tuple[FeatureDefinition, ...]
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        names = [d.name for d in self.definitions]
        if len(names) != len(set(names)):
            raise ValueError(f"duplicate feature names in {self.version}")
        if any(d.feature_version != self.version for d in self.definitions):
            raise ValueError("definition version does not match its feature set")

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(d.name for d in self.definitions)

    def get(self, name: str) -> FeatureDefinition:
        for d in self.definitions:
            if d.name == name:
                return d
        raise KeyError(name)

    def by_category(self, category: FeatureCategory) -> tuple[FeatureDefinition, ...]:
        return tuple(d for d in self.definitions if d.category is category)

    def fingerprint(self) -> str:
        payload = {
            "version": self.version,
            "parameters": self.parameters,
            "definitions": [d.computational_signature() for d in self.definitions],
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


# --------------------------------------------------------------------------- v1.0.0
FEATURE_VERSION_1_0_0 = "fraud-features-1.0.0"
_V = FEATURE_VERSION_1_0_0
_DEFS: list[FeatureDefinition] = []


def _add(
    name: str,
    dtype: FeatureType,
    category: FeatureCategory,
    description: str,
    *sources: str,
    nullable: bool = True,
    leakage: str = SAFE_PRIOR,
    rationale: str = "",
    units: str | None = None,
    applies_to: frozenset[EventKind] = BOTH,
    min_value: float | None = None,
    max_value: float | None = None,
    allowed: tuple[str, ...] | None = None,
    missing: str = "",
) -> None:
    _DEFS.append(
        FeatureDefinition(
            name=name,
            description=description,
            dtype=dtype,
            category=category,
            nullable=nullable,
            sources=sources,
            leakage_notes=leakage,
            feature_version=_V,
            rationale=rationale,
            units=units,
            applies_to=applies_to,
            min_value=min_value,
            max_value=max_value,
            allowed_values=allowed,
            missing_when=missing,
        )
    )


F, INT, B, C = FeatureType.FLOAT, FeatureType.INTEGER, FeatureType.BOOLEAN, FeatureType.CATEGORICAL
Cat = FeatureCategory
_NO_USER = "not_applicable for anonymous events (no resolved account)."
_NO_DEVICE = "not_observed when the event carries no device identifier."
_NO_NET = "not_observed when the event carries no network context."
_TXN = "not_applicable for login events."
_ADDR = "not_applicable for logins and for transactions without a shipping address."
_PM = "not_applicable for logins and for transactions without a payment method."
_COUNT: dict[str, Any] = {"units": "count", "min_value": 0}
_DAYS: dict[str, Any] = {"units": "days", "min_value": 0}
_HOURS: dict[str, Any] = {"units": "hours", "min_value": 0}
_MINUTES: dict[str, Any] = {"units": "minutes", "min_value": 0}
_PROB: dict[str, Any] = {"units": "probability", "min_value": 0, "max_value": 1}

# ---- context
_add(
    "event_kind",
    C,
    Cat.CONTEXT,
    "Kind of scored event.",
    "events.event_type",
    nullable=False,
    leakage=SAFE_EVENT,
    allowed=("login", "transaction"),
    rationale="Lets one model consume login and transaction vectors in a shared space.",
)
_add(
    "login_outcome",
    C,
    Cat.CONTEXT,
    "Outcome of the scored login event.",
    "login_events.outcome",
    leakage=SAFE_EVENT,
    applies_to=LOGIN_ONLY,
    allowed=("attempt", "success", "failure"),
    missing="not_applicable for transactions.",
    rationale="Failed and successful logins carry different risk.",
)
_add(
    "authenticated_user",
    B,
    Cat.CONTEXT,
    "Whether the event is attributed to a known account.",
    "events.user_id",
    nullable=False,
    leakage=SAFE_EVENT,
    rationale="Credential-stuffing traffic often targets unknown usernames.",
)

# ---- account
_add(
    "account_age_days",
    F,
    Cat.ACCOUNT,
    "Days between account creation and as_of.",
    "users.account_created_at",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
    rationale="Young accounts have little history; old accounts are takeover targets.",
    **_DAYS,
)
_add(
    "email_verified",
    B,
    Cat.ACCOUNT,
    "Email verified and not changed since the last verification (as of as_of).",
    "security_events.security_event_type",
    "security_events.occurred_at",
    leakage=SAFE_AS_OF,
    missing="unknown when no email lifecycle event exists; " + _NO_USER,
    rationale="An email change after verification is a classic takeover step.",
)
_add(
    "phone_verified",
    B,
    Cat.ACCOUNT,
    "Phone verified and not changed since the last verification (as of as_of).",
    "security_events.security_event_type",
    "security_events.occurred_at",
    leakage=SAFE_AS_OF,
    missing="unknown when no phone lifecycle event exists; " + _NO_USER,
)
_add(
    "mfa_enabled",
    B,
    Cat.ACCOUNT,
    "MFA enrolled at as_of (latest MFA event is enable).",
    "security_events.security_event_type",
    "security_events.occurred_at",
    leakage=SAFE_AS_OF,
    missing="unknown when no MFA event exists; " + _NO_USER,
)
_add(
    "successful_logins_total",
    INT,
    Cat.ACCOUNT,
    "Prior successful logins of the account.",
    "login_events.outcome",
    "login_events.occurred_at",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "failed_logins_total",
    INT,
    Cat.ACCOUNT,
    "Prior failed logins of the account.",
    "login_events.outcome",
    "login_events.occurred_at",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "successful_transactions_total",
    INT,
    Cat.ACCOUNT,
    "Prior transactions approved by as_of (decision time <= as_of).",
    "transactions.decision_outcome",
    "transactions.decided_at",
    leakage="Uses the immutable decision_outcome and decided_at <= as_of; never the "
    "mutable transactions.status.",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "failed_transactions_total",
    INT,
    Cat.ACCOUNT,
    "Prior transactions declined by as_of (decision time <= as_of).",
    "transactions.decision_outcome",
    "transactions.decided_at",
    leakage="As successful_transactions_total.",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "historical_chargebacks",
    INT,
    Cat.ACCOUNT,
    "Chargebacks on the account whose label became known by as_of.",
    "fraud_labels.label_source",
    "fraud_labels.labelled_at",
    leakage="Label leakage guard: labelled_at <= as_of, and labels on the scored "
    "event/transaction itself are always excluded.",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "historical_confirmed_fraud_events",
    INT,
    Cat.ACCOUNT,
    "Non-chargeback fraud confirmations (analyst/customer) known by as_of.",
    "fraud_labels.label",
    "fraud_labels.label_source",
    "fraud_labels.labelled_at",
    leakage="As historical_chargebacks.",
    missing=_NO_USER,
    **_COUNT,
)

# ---- device
_add(
    "device_age_days",
    F,
    Cat.DEVICE,
    "Days since the device was first seen for this account (0 if first seen now).",
    "events.device_id",
    "events.user_id",
    "events.occurred_at",
    leakage=SAFE_AS_OF,
    missing=_NO_DEVICE + " " + _NO_USER,
    **_DAYS,
)
_add(
    "device_seen_before",
    B,
    Cat.DEVICE,
    "The account used this device before.",
    "events.device_id",
    "events.user_id",
    "events.occurred_at",
    missing=_NO_DEVICE + " " + _NO_USER,
)
_add(
    "device_trusted",
    B,
    Cat.DEVICE,
    "The account completed an MFA login on this device before (application trust rule).",
    "login_events.device_id",
    "login_events.mfa_used",
    "login_events.outcome",
    leakage="Derived from prior login rows; the mutable user_devices.is_trusted flag is "
    "never read.",
    missing=_NO_DEVICE + " " + _NO_USER,
)
_add(
    "device_successful_login_count",
    INT,
    Cat.DEVICE,
    "Prior successful logins on this device (any account).",
    "login_events.device_id",
    "login_events.outcome",
    missing=_NO_DEVICE,
    **_COUNT,
)
_add(
    "device_failed_login_count",
    INT,
    Cat.DEVICE,
    "Prior failed logins on this device (any account).",
    "login_events.device_id",
    "login_events.outcome",
    missing=_NO_DEVICE,
    **_COUNT,
)
_add(
    "accounts_seen_on_device",
    INT,
    Cat.DEVICE,
    "Distinct accounts with prior activity on this device (including this account).",
    "events.device_id",
    "events.user_id",
    missing=_NO_DEVICE,
    **_COUNT,
)
_add(
    "accounts_seen_on_device_last_24h",
    INT,
    Cat.DEVICE,
    "Distinct accounts with activity on this device in the last 24 hours.",
    "events.device_id",
    "events.user_id",
    "events.occurred_at",
    missing=_NO_DEVICE,
    rationale="One automation client cycling through accounts.",
    **_COUNT,
)
_add(
    "time_since_device_last_seen_hours",
    F,
    Cat.DEVICE,
    "Hours since the device's previous activity (any account).",
    "events.device_id",
    "events.occurred_at",
    missing="not_observed when the device was never seen before; " + _NO_DEVICE,
    **_HOURS,
)
_add(
    "new_device",
    B,
    Cat.DEVICE,
    "Device first seen for this account within the last 24 hours (including now).",
    "events.device_id",
    "events.user_id",
    "events.occurred_at",
    leakage=SAFE_AS_OF,
    missing=_NO_DEVICE + " " + _NO_USER,
)

# ---- network
_add(
    "network_first_seen_days",
    F,
    Cat.NETWORK,
    "Days since the network (IP) was first observed by the platform (0 if new).",
    "network_events.network_identity_id",
    "network_events.observed_at",
    leakage=SAFE_AS_OF,
    missing=_NO_NET,
    **_DAYS,
)
_add(
    "network_seen_before",
    B,
    Cat.NETWORK,
    "The network was observed before (any account).",
    "network_events.network_identity_id",
    missing=_NO_NET,
)
_add(
    "network_type",
    C,
    Cat.NETWORK,
    "Network type from intel at the time of the event.",
    "network_events.network_type",
    leakage=SAFE_SNAPSHOT,
    allowed=("residential", "mobile", "business", "datacenter", "education"),
    missing="unknown when intel did not classify the network; " + _NO_NET,
)
_add(
    "vpn_detected",
    B,
    Cat.NETWORK,
    "Intel flagged the network as a known VPN.",
    "network_events.is_known_vpn",
    leakage=SAFE_SNAPSHOT,
    rationale="A risk signal only - many legitimate customers use VPNs.",
    missing="unknown when intel gave no VPN verdict; " + _NO_NET,
)
_add(
    "vpn_probability",
    F,
    Cat.NETWORK,
    "Intel confidence for a network flagged as VPN.",
    "network_events.proxy_confidence",
    "network_events.is_known_vpn",
    leakage=SAFE_SNAPSHOT,
    missing="not_applicable when not flagged as VPN; unknown when the flag or confidence "
    "is absent; " + _NO_NET,
    **_PROB,
)
_add(
    "proxy_detected",
    B,
    Cat.NETWORK,
    "Intel flagged the network as a known proxy.",
    "network_events.is_known_proxy",
    leakage=SAFE_SNAPSHOT,
    missing="unknown when intel gave no proxy verdict; " + _NO_NET,
)
_add(
    "proxy_probability",
    F,
    Cat.NETWORK,
    "Intel confidence for a network flagged as proxy.",
    "network_events.proxy_confidence",
    "network_events.is_known_proxy",
    leakage=SAFE_SNAPSHOT,
    missing="not_applicable when not flagged as proxy; unknown when absent; " + _NO_NET,
    **_PROB,
)
_add(
    "tor_detected",
    B,
    Cat.NETWORK,
    "Intel flagged a Tor exit.",
    "network_events.is_tor",
    leakage=SAFE_SNAPSHOT,
    missing="unknown when absent; " + _NO_NET,
)
_add(
    "datacenter_detected",
    B,
    Cat.NETWORK,
    "Intel flagged a datacenter/hosting network.",
    "network_events.is_datacenter",
    leakage=SAFE_SNAPSHOT,
    missing="unknown when absent; " + _NO_NET,
)
_add(
    "mobile_network",
    B,
    Cat.NETWORK,
    "Intel flagged a mobile-carrier network.",
    "network_events.is_mobile_network",
    leakage=SAFE_SNAPSHOT,
    rationale="Carrier NAT legitimately puts many customers on one IP.",
    missing="unknown when absent (including observations recorded before revision "
    "0002); " + _NO_NET,
)
_add(
    "country_changed",
    B,
    Cat.NETWORK,
    "Network country differs from the account's previous network observation.",
    "network_events.country",
    "network_events.observed_at",
    missing="not_observed without a previous observation; unknown when either country "
    "is unknown; " + _NO_NET + " " + _NO_USER,
)
_add(
    "asn_changed",
    B,
    Cat.NETWORK,
    "ASN differs from the account's previous network observation.",
    "network_events.asn",
    "network_events.observed_at",
    missing="as country_changed.",
)
_add(
    "network_type_changed",
    B,
    Cat.NETWORK,
    "Network type differs from the account's previous network observation.",
    "network_events.network_type",
    "network_events.observed_at",
    missing="as country_changed.",
)
_add(
    "accounts_seen_from_network",
    INT,
    Cat.NETWORK,
    "Distinct accounts previously observed on this network.",
    "network_events.user_id",
    "network_events.network_identity_id",
    rationale="High for shared infrastructure - offices, carrier NAT, hotels - which is "
    "not by itself suspicious.",
    missing=_NO_NET,
    **_COUNT,
)
_add(
    "accounts_seen_from_network_last_1h",
    INT,
    Cat.NETWORK,
    "Distinct accounts observed on this network in the last hour.",
    "network_events.user_id",
    "network_events.observed_at",
    missing=_NO_NET,
    **_COUNT,
)
_add(
    "successful_logins_from_network",
    INT,
    Cat.NETWORK,
    "Prior successful logins from this network (any account).",
    "login_events.network_identity_id",
    "login_events.outcome",
    missing=_NO_NET,
    **_COUNT,
)
_add(
    "failed_logins_from_network",
    INT,
    Cat.NETWORK,
    "Prior failed logins from this network (any account, including unknown usernames).",
    "login_events.network_identity_id",
    "login_events.outcome",
    missing=_NO_NET,
    **_COUNT,
)
_add(
    "failed_logins_from_network_last_1h",
    INT,
    Cat.NETWORK,
    "Failed logins from this network in the last hour.",
    "login_events.network_identity_id",
    "login_events.occurred_at",
    missing=_NO_NET,
    **_COUNT,
)

# ---- address
_add(
    "address_age_days",
    F,
    Cat.ADDRESS,
    "Days since the shipping address was added.",
    "addresses.added_at",
    leakage=SAFE_AS_OF,
    applies_to=TXN_ONLY,
    missing=_ADDR,
    **_DAYS,
)
_add(
    "address_seen_before",
    B,
    Cat.ADDRESS,
    "A previous transaction was shipped to this address.",
    "transactions.shipping_address_id",
    applies_to=TXN_ONLY,
    missing=_ADDR,
)
_add(
    "address_verified",
    B,
    Cat.ADDRESS,
    "Address verified by as_of.",
    "addresses.verified_at",
    leakage="verified_at <= as_of.",
    applies_to=TXN_ONLY,
    missing=_ADDR,
)
_add(
    "orders_to_address",
    INT,
    Cat.ADDRESS,
    "Prior transactions shipped to this address.",
    "transactions.shipping_address_id",
    applies_to=TXN_ONLY,
    missing=_ADDR,
    **_COUNT,
)
_add(
    "successful_orders_to_address",
    INT,
    Cat.ADDRESS,
    "Prior transactions to this address approved by as_of.",
    "transactions.decision_outcome",
    "transactions.decided_at",
    applies_to=TXN_ONLY,
    missing=_ADDR,
    **_COUNT,
)
_add(
    "failed_orders_to_address",
    INT,
    Cat.ADDRESS,
    "Prior transactions to this address declined by as_of.",
    "transactions.decision_outcome",
    "transactions.decided_at",
    applies_to=TXN_ONLY,
    missing=_ADDR,
    **_COUNT,
)
_add(
    "new_address",
    B,
    Cat.ADDRESS,
    "Address added within the last 24 hours.",
    "addresses.added_at",
    leakage=SAFE_AS_OF,
    applies_to=TXN_ONLY,
    missing=_ADDR,
    rationale="Common in takeovers - but also in house moves, so never decisive alone.",
)
_add(
    "time_since_address_last_used_hours",
    F,
    Cat.ADDRESS,
    "Hours since the previous transaction to this address.",
    "transactions.shipping_address_id",
    "transactions.occurred_at",
    applies_to=TXN_ONLY,
    missing="not_observed when the address was never used before; " + _ADDR,
    **_HOURS,
)
_add(
    "accounts_sharing_address",
    INT,
    Cat.ADDRESS,
    "Other accounts that registered the same address (keyed hash) by as_of.",
    "addresses.address_hash",
    "addresses.added_at",
    applies_to=TXN_ONLY,
    missing=_ADDR,
    rationale="Drop addresses reused across accounts; households also share addresses.",
    **_COUNT,
)

# ---- payment
_add(
    "payment_method_age_days",
    F,
    Cat.PAYMENT,
    "Days since the payment method was added.",
    "payment_methods.added_at",
    leakage=SAFE_AS_OF,
    applies_to=TXN_ONLY,
    missing=_PM,
    **_DAYS,
)
_add(
    "payment_method_seen_before",
    B,
    Cat.PAYMENT,
    "The payment method was used in a previous transaction.",
    "transactions.payment_method_id",
    applies_to=TXN_ONLY,
    missing=_PM,
)
_add(
    "payment_method_verified",
    B,
    Cat.PAYMENT,
    "Payment method verified by as_of.",
    "payment_methods.verified_at",
    leakage="verified_at <= as_of.",
    applies_to=TXN_ONLY,
    missing=_PM,
)
_add(
    "successful_transactions_on_payment_method",
    INT,
    Cat.PAYMENT,
    "Prior transactions on this payment method approved by as_of.",
    "transactions.decision_outcome",
    "transactions.decided_at",
    applies_to=TXN_ONLY,
    missing=_PM,
    **_COUNT,
)
_add(
    "failed_transactions_on_payment_method",
    INT,
    Cat.PAYMENT,
    "Prior transactions on this payment method declined by as_of.",
    "transactions.decision_outcome",
    "transactions.decided_at",
    applies_to=TXN_ONLY,
    missing=_PM,
    **_COUNT,
)
_add(
    "issuing_country_changed",
    B,
    Cat.PAYMENT,
    "Issuer country differs from that of the account's previous transaction.",
    "payment_methods.issuer_country",
    "transactions.occurred_at",
    applies_to=TXN_ONLY,
    missing="not_observed without a previous transaction with a payment method; unknown "
    "when an issuer country is unknown; " + _PM,
)
_add(
    "new_payment_method",
    B,
    Cat.PAYMENT,
    "Payment method added within the last 24 hours.",
    "payment_methods.added_at",
    leakage=SAFE_AS_OF,
    applies_to=TXN_ONLY,
    missing=_PM,
)
_add(
    "accounts_sharing_payment_fingerprint",
    INT,
    Cat.PAYMENT,
    "Other accounts holding a payment method with the same vault fingerprint by as_of.",
    "payment_methods.fingerprint_hash",
    "payment_methods.added_at",
    applies_to=TXN_ONLY,
    missing="unknown when the vault supplied no fingerprint; " + _PM,
    **_COUNT,
)

# ---- transaction
_TX_STATS = "not_observed when there is no previous transaction in the same currency; " + _TXN
_add(
    "transaction_amount_minor_units",
    INT,
    Cat.TRANSACTION,
    "Amount of the scored transaction in minor units.",
    "transactions.amount_minor",
    leakage=SAFE_EVENT,
    applies_to=TXN_ONLY,
    units="minor currency units",
    min_value=0,
    missing=_TXN,
)
_add(
    "transaction_currency",
    C,
    Cat.TRANSACTION,
    "ISO 4217 currency of the transaction.",
    "transactions.currency",
    leakage=SAFE_EVENT,
    applies_to=TXN_ONLY,
    missing=_TXN,
)
_add(
    "previous_transactions_same_currency",
    INT,
    Cat.TRANSACTION,
    "Number of prior transactions in the same currency (the history behind the stats).",
    "transactions.currency",
    applies_to=TXN_ONLY,
    missing=_TXN,
    **_COUNT,
)
_add(
    "average_previous_transaction_amount",
    F,
    Cat.TRANSACTION,
    "Mean amount of prior same-currency transactions.",
    "transactions.amount_minor",
    applies_to=TXN_ONLY,
    units="minor currency units",
    min_value=0,
    missing=_TX_STATS,
)
_add(
    "median_previous_transaction_amount",
    F,
    Cat.TRANSACTION,
    "Median amount of prior same-currency transactions.",
    "transactions.amount_minor",
    applies_to=TXN_ONLY,
    units="minor currency units",
    min_value=0,
    missing=_TX_STATS,
)
_add(
    "maximum_previous_transaction_amount",
    INT,
    Cat.TRANSACTION,
    "Largest prior same-currency transaction.",
    "transactions.amount_minor",
    applies_to=TXN_ONLY,
    units="minor currency units",
    min_value=0,
    missing=_TX_STATS,
)
_add(
    "transaction_vs_average_ratio",
    F,
    Cat.TRANSACTION,
    "Amount divided by the previous average.",
    "transactions.amount_minor",
    applies_to=TXN_ONLY,
    units="ratio",
    min_value=0,
    missing=_TX_STATS + " not_applicable when the average is zero (division by zero).",
)
_add(
    "transaction_vs_median_ratio",
    F,
    Cat.TRANSACTION,
    "Amount divided by the previous median.",
    "transactions.amount_minor",
    applies_to=TXN_ONLY,
    units="ratio",
    min_value=0,
    missing=_TX_STATS + " not_applicable when the median is zero.",
)
for _w in ("5m", "1h", "24h", "7d", "30d"):
    _add(
        f"transactions_last_{_w}",
        INT,
        Cat.TRANSACTION,
        f"Prior transactions of the account in the last {_w} (any currency).",
        "transactions.occurred_at",
        applies_to=TXN_ONLY,
        missing=_TXN,
        **_COUNT,
    )
_add(
    "transaction_value_last_24h",
    INT,
    Cat.TRANSACTION,
    "Sum of prior same-currency amounts in the last 24 hours (excluding this one).",
    "transactions.amount_minor",
    "transactions.occurred_at",
    applies_to=TXN_ONLY,
    units="minor currency units",
    min_value=0,
    missing=_TXN,
)
_add(
    "time_since_previous_transaction_minutes",
    F,
    Cat.TRANSACTION,
    "Minutes since the account's previous transaction.",
    "transactions.occurred_at",
    applies_to=TXN_ONLY,
    missing="not_observed without a previous transaction; " + _TXN,
    **_MINUTES,
)
_add(
    "unusually_high_transaction",
    B,
    Cat.TRANSACTION,
    "Amount exceeds the account's previous same-currency maximum (descriptive, not a rule).",
    "transactions.amount_minor",
    applies_to=TXN_ONLY,
    missing="not_observed with fewer than 3 prior same-currency transactions; " + _TXN,
)

# ---- login velocity
_LV = "Prior login events of the account (attempts, successes and failures)"
for _w in ("5m", "15m", "1h", "24h", "7d", "30d"):
    _add(
        f"logins_last_{_w}",
        INT,
        Cat.LOGIN_VELOCITY,
        f"{_LV} in the last {_w}.",
        "login_events.user_id",
        "login_events.occurred_at",
        missing=_NO_USER,
        **_COUNT,
    )
for _w in ("5m", "15m", "1h"):
    _add(
        f"failed_logins_last_{_w}",
        INT,
        Cat.LOGIN_VELOCITY,
        f"Prior failed logins of the account in the last {_w}.",
        "login_events.outcome",
        "login_events.occurred_at",
        missing=_NO_USER,
        **_COUNT,
    )
_add(
    "successful_logins_last_1h",
    INT,
    Cat.LOGIN_VELOCITY,
    "Prior successful logins of the account in the last hour.",
    "login_events.outcome",
    "login_events.occurred_at",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "distinct_networks_last_1h",
    INT,
    Cat.LOGIN_VELOCITY,
    "Distinct networks used by the account's logins in the last hour.",
    "login_events.network_identity_id",
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "distinct_devices_last_1h",
    INT,
    Cat.LOGIN_VELOCITY,
    "Distinct devices used by the account's logins in the last hour.",
    "login_events.device_id",
    missing=_NO_USER,
    **_COUNT,
)

# ---- security
for _kind, _label in (
    ("password_reset", "password reset"),
    ("email_change", "email change"),
    ("phone_change", "phone change"),
    ("mfa_change", "MFA enrol/removal"),
):
    _add(
        f"minutes_since_{_kind}",
        F,
        Cat.SECURITY,
        f"Minutes since the latest {_label}.",
        "security_events.security_event_type",
        "security_events.occurred_at",
        leakage=SAFE_AS_OF,
        missing="not_observed when none happened; " + _NO_USER,
        **_MINUTES,
    )
for _kind, _label in (
    ("password_reset", "password reset"),
    ("email_change", "email change"),
    ("phone_change", "phone change"),
    ("mfa_removed", "MFA removal"),
):
    _add(
        f"recent_{_kind}",
        B,
        Cat.SECURITY,
        f"A {_label} in the last 24 hours.",
        "security_events.security_event_type",
        "security_events.occurred_at",
        leakage=SAFE_AS_OF,
        missing=_NO_USER,
    )

# ---- behavioural change
_add(
    "country_changed_recently",
    B,
    Cat.BEHAVIOURAL,
    "The account's network country changed within the last 24 hours.",
    "network_events.country",
    "network_events.observed_at",
    leakage=SAFE_AS_OF,
    missing="not_observed without network observations; unknown when all countries are "
    "unknown; " + _NO_USER,
)
_add(
    "asn_changed_recently",
    B,
    Cat.BEHAVIOURAL,
    "The account's network ASN changed within the last 24 hours.",
    "network_events.asn",
    "network_events.observed_at",
    leakage=SAFE_AS_OF,
    missing="as country_changed_recently.",
)
_add(
    "device_changed_recently",
    B,
    Cat.BEHAVIOURAL,
    "A device first seen in the last 24 hours on an account with an older device.",
    "events.device_id",
    "events.occurred_at",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
)
_add(
    "address_changed_recently",
    B,
    Cat.BEHAVIOURAL,
    "An address added in the last 24 hours on an account with an older address.",
    "addresses.added_at",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
)
_add(
    "payment_method_changed_recently",
    B,
    Cat.BEHAVIOURAL,
    "A payment method added in the last 24 hours on an account with an older one.",
    "payment_methods.added_at",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
)
_add(
    "rapid_multi_change_count",
    INT,
    Cat.BEHAVIOURAL,
    "How many of {password reset, email change, phone change, MFA change, device change, "
    "address change, payment-method change} happened in the last 24 hours.",
    "security_events.occurred_at",
    "events.occurred_at",
    "addresses.added_at",
    "payment_methods.added_at",
    leakage=SAFE_AS_OF,
    rationale="Takeovers chain several changes quickly; onboarding is excluded because "
    "the change features require pre-existing devices/addresses/payment methods.",
    missing=_NO_USER,
    units="count",
    min_value=0,
    max_value=7,
)

# ---- cross-entity
_add(
    "accounts_per_device",
    INT,
    Cat.CROSS_ENTITY,
    "Other accounts seen on this device by as_of.",
    "events.device_id",
    "events.user_id",
    leakage=SAFE_AS_OF,
    missing=_NO_DEVICE,
    **_COUNT,
)
_add(
    "accounts_per_network",
    INT,
    Cat.CROSS_ENTITY,
    "Other accounts seen on this network by as_of.",
    "network_events.user_id",
    leakage=SAFE_AS_OF,
    missing=_NO_NET,
    **_COUNT,
)
_add(
    "addresses_per_account",
    INT,
    Cat.CROSS_ENTITY,
    "Addresses registered by as_of.",
    "addresses.added_at",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "devices_per_account",
    INT,
    Cat.CROSS_ENTITY,
    "Distinct devices used by as_of.",
    "events.device_id",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "payment_methods_per_account",
    INT,
    Cat.CROSS_ENTITY,
    "Payment methods registered by as_of.",
    "payment_methods.added_at",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "networks_per_account",
    INT,
    Cat.CROSS_ENTITY,
    "Distinct networks observed by as_of.",
    "network_events.network_identity_id",
    leakage=SAFE_AS_OF,
    missing=_NO_USER,
    **_COUNT,
)
_add(
    "shared_device_flag",
    B,
    Cat.CROSS_ENTITY,
    "accounts_per_device >= 1.",
    "events.device_id",
    leakage=SAFE_AS_OF,
    missing=_NO_DEVICE,
    rationale="Households share devices; a descriptive flag, not a verdict.",
)
_add(
    "shared_network_flag",
    B,
    Cat.CROSS_ENTITY,
    "accounts_per_network >= 1.",
    "network_events.user_id",
    leakage=SAFE_AS_OF,
    missing=_NO_NET,
    rationale="Carrier NAT, offices, schools, hotels and households share networks "
    "legitimately; a descriptive flag, not a verdict.",
)

FEATURE_SET_1_0_0 = FeatureSet(
    version=_V,
    definitions=tuple(_DEFS),
    parameters={
        "windows": {w.name: int(w.duration.total_seconds()) for w in WINDOWS},
        "recent_window_seconds": int(RECENT_WINDOW.duration.total_seconds()),
        "unusually_high_min_history": 3,
        "float_decimals": 6,
    },
)

FEATURE_SETS: dict[str, FeatureSet] = {FEATURE_SET_1_0_0.version: FEATURE_SET_1_0_0}
DEFAULT_FEATURE_VERSION = FEATURE_VERSION_1_0_0


def get_feature_set(version: str | None = None) -> FeatureSet:
    key = version or DEFAULT_FEATURE_VERSION
    try:
        return FEATURE_SETS[key]
    except KeyError:
        raise KeyError(f"unknown feature version {key!r}; known: {sorted(FEATURE_SETS)}") from None
