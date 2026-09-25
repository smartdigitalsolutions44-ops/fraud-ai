"""Catalogue of planned fraud features and the stored data each depends on.

Every source is ``table.column``; a test asserts they all exist in the schema, so the
database is guaranteed to support the Stage 2 feature vector. All features are computed
point-in-time (only data with timestamps <= the scored event) to avoid leakage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

FEATURE_CATALOG_VERSION = "catalog-1"

Kind = Literal["numeric", "boolean"]


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    kind: Kind
    description: str
    sources: tuple[str, ...]


def _f(name: str, kind: Kind, description: str, *sources: str) -> FeatureSpec:
    return FeatureSpec(name, kind, description, sources)


FEATURE_CATALOG: tuple[FeatureSpec, ...] = (
    _f(
        "account_age_days",
        "numeric",
        "Days since account creation",
        "users.account_created_at",
        "events.occurred_at",
    ),
    _f(
        "device_age_days",
        "numeric",
        "Days since this device was first seen for the user",
        "user_devices.first_seen_at",
    ),
    _f(
        "address_age_days",
        "numeric",
        "Days since the shipping address was added",
        "addresses.added_at",
        "transactions.shipping_address_id",
    ),
    _f(
        "payment_method_age_days",
        "numeric",
        "Days since the payment method was added",
        "payment_methods.added_at",
        "transactions.payment_method_id",
    ),
    _f(
        "new_device",
        "boolean",
        "Device first seen for this user within the lookback",
        "user_devices.first_seen_at",
    ),
    _f(
        "new_address", "boolean", "Shipping address added within the lookback", "addresses.added_at"
    ),
    _f(
        "new_payment_method",
        "boolean",
        "Payment method added within the lookback",
        "payment_methods.added_at",
    ),
    _f(
        "login_velocity_5m",
        "numeric",
        "Login events for the user in the last 5 minutes",
        "login_events.user_id",
        "login_events.occurred_at",
    ),
    _f(
        "login_velocity_1h",
        "numeric",
        "Login events for the user in the last hour",
        "login_events.user_id",
        "login_events.occurred_at",
    ),
    _f(
        "failed_login_velocity",
        "numeric",
        "Failed logins for the user in the last hour",
        "login_events.outcome",
        "login_events.occurred_at",
    ),
    _f(
        "country_changed",
        "boolean",
        "Network country differs from previous observation",
        "network_events.country",
        "network_events.observed_at",
    ),
    _f(
        "asn_changed",
        "boolean",
        "Network ASN differs from previous observation",
        "network_events.asn",
        "network_events.observed_at",
    ),
    _f(
        "network_type_changed",
        "boolean",
        "Network type differs from previous observation",
        "network_events.network_type",
    ),
    _f(
        "accounts_per_ip",
        "numeric",
        "Distinct users seen from this IP (point-in-time)",
        "network_events.network_identity_id",
        "network_events.user_id",
    ),
    _f(
        "accounts_per_device",
        "numeric",
        "Distinct users seen on this device",
        "user_devices.device_id",
        "user_devices.user_id",
    ),
    _f(
        "transaction_amount",
        "numeric",
        "Transaction amount in major units",
        "transactions.amount_minor",
        "transactions.currency",
    ),
    _f(
        "average_transaction_amount",
        "numeric",
        "User's historical mean amount",
        "transactions.amount_minor",
        "transactions.user_id",
    ),
    _f(
        "transaction_vs_average_ratio",
        "numeric",
        "Amount divided by historical mean",
        "transactions.amount_minor",
    ),
    _f(
        "transactions_last_hour",
        "numeric",
        "User transactions in the last hour",
        "transactions.occurred_at",
    ),
    _f(
        "transactions_last_day",
        "numeric",
        "User transactions in the last 24 hours",
        "transactions.occurred_at",
    ),
    _f(
        "time_since_password_reset",
        "numeric",
        "Minutes since the last password reset",
        "security_events.security_event_type",
        "security_events.occurred_at",
    ),
    _f("vpn_detected", "boolean", "Network flagged as a known VPN", "network_events.is_known_vpn"),
    _f(
        "proxy_detected",
        "boolean",
        "Network flagged as a known proxy",
        "network_events.is_known_proxy",
    ),
    _f("tor_detected", "boolean", "Network flagged as Tor", "network_events.is_tor"),
    _f(
        "datacenter_network",
        "boolean",
        "Network flagged as datacenter/hosting",
        "network_events.is_datacenter",
    ),
    _f(
        "proxy_probability",
        "numeric",
        "Intel provider's proxy confidence",
        "network_events.proxy_confidence",
    ),
    _f(
        "historical_fraud_rate",
        "numeric",
        "Share of the user's past labelled activity that "
        "was fraud (labels known at scoring time only)",
        "fraud_labels.label",
        "fraud_labels.labelled_at",
    ),
    _f(
        "address_reuse_count",
        "numeric",
        "Other users sharing this address hash",
        "addresses.address_hash",
    ),
    _f(
        "device_reuse_count", "numeric", "Other users sharing this device", "user_devices.device_id"
    ),
    _f(
        "ip_reuse_count",
        "numeric",
        "Other users sharing this IP",
        "network_identities.distinct_user_count",
        "network_events.user_id",
    ),
)

FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURE_CATALOG)
