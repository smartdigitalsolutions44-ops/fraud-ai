from pathlib import Path

import pytest

from fraud_ai.database.base import Base
from fraud_ai.features.catalog import MARKDOWN_BEGIN, MARKDOWN_END, catalog_json, catalog_markdown
from fraud_ai.features.definitions import (
    DEFAULT_FEATURE_VERSION,
    FEATURE_SET_1_0_0,
    EventKind,
    FeatureCategory,
    FeatureDefinition,
    FeatureSet,
    FeatureType,
    get_feature_set,
)

ROOT = Path(__file__).resolve().parents[1]

# Pinned: fraud-features-1.0.0 is released. If this fails you changed the meaning, type,
# bounds or applicability of a released feature - create a new feature version instead.
FINGERPRINT_1_0_0 = FEATURE_SET_1_0_0.fingerprint()
PINNED_FINGERPRINT_PREFIX = "2b7b6d6afba0f83c"

REQUIRED = {
    # account
    "account_age_days",
    "email_verified",
    "phone_verified",
    "successful_logins_total",
    "failed_logins_total",
    "successful_transactions_total",
    "failed_transactions_total",
    "historical_chargebacks",
    "historical_confirmed_fraud_events",
    # device
    "device_age_days",
    "device_seen_before",
    "device_trusted",
    "device_successful_login_count",
    "device_failed_login_count",
    "accounts_seen_on_device",
    "time_since_device_last_seen_hours",
    "new_device",
    # network
    "network_first_seen_days",
    "network_seen_before",
    "network_type",
    "vpn_probability",
    "proxy_probability",
    "tor_detected",
    "datacenter_detected",
    "mobile_network",
    "country_changed",
    "asn_changed",
    "network_type_changed",
    "accounts_seen_from_network",
    "successful_logins_from_network",
    "failed_logins_from_network",
    # address
    "address_age_days",
    "address_seen_before",
    "address_verified",
    "orders_to_address",
    "successful_orders_to_address",
    "failed_orders_to_address",
    "new_address",
    "time_since_address_last_used_hours",
    # payment
    "payment_method_age_days",
    "payment_method_seen_before",
    "payment_method_verified",
    "successful_transactions_on_payment_method",
    "failed_transactions_on_payment_method",
    "issuing_country_changed",
    "new_payment_method",
    # transaction
    "transaction_amount_minor_units",
    "average_previous_transaction_amount",
    "median_previous_transaction_amount",
    "maximum_previous_transaction_amount",
    "transaction_vs_average_ratio",
    "transaction_vs_median_ratio",
    "transactions_last_5m",
    "transactions_last_1h",
    "transactions_last_24h",
    "transaction_value_last_24h",
    "time_since_previous_transaction_minutes",
    "unusually_high_transaction",
    # login velocity
    "logins_last_5m",
    "logins_last_15m",
    "logins_last_1h",
    "logins_last_24h",
    "failed_logins_last_5m",
    "failed_logins_last_15m",
    "failed_logins_last_1h",
    "successful_logins_last_1h",
    "distinct_networks_last_1h",
    "distinct_devices_last_1h",
    # security
    "minutes_since_password_reset",
    "minutes_since_email_change",
    "minutes_since_phone_change",
    "minutes_since_mfa_change",
    "recent_password_reset",
    "recent_email_change",
    "recent_phone_change",
    "recent_mfa_removed",
    # behavioural
    "country_changed_recently",
    "asn_changed_recently",
    "device_changed_recently",
    "address_changed_recently",
    "payment_method_changed_recently",
    "rapid_multi_change_count",
    # cross-entity
    "accounts_per_device",
    "accounts_per_network",
    "addresses_per_account",
    "devices_per_account",
    "payment_methods_per_account",
    "networks_per_account",
    "shared_device_flag",
    "shared_network_flag",
}


def test_default_version_and_registry() -> None:
    assert DEFAULT_FEATURE_VERSION == "fraud-features-1.0.0"
    assert get_feature_set() is FEATURE_SET_1_0_0
    with pytest.raises(KeyError, match="unknown feature version"):
        get_feature_set("fraud-features-9.9.9")


def test_required_features_present_and_unique() -> None:
    names = FEATURE_SET_1_0_0.names
    assert len(names) == len(set(names))
    assert set(names) >= REQUIRED
    assert len(names) >= 100
    assert {d.category for d in FEATURE_SET_1_0_0.definitions} == set(FeatureCategory)


def test_released_version_fingerprint_is_pinned() -> None:
    assert FINGERPRINT_1_0_0.startswith(PINNED_FINGERPRINT_PREFIX)


def test_every_definition_is_complete() -> None:
    for d in FEATURE_SET_1_0_0.definitions:
        assert d.description and d.leakage_notes and d.sources, d.name
        assert d.feature_version == FEATURE_SET_1_0_0.version
        assert d.applies_to <= set(EventKind) and d.applies_to
        if d.dtype is FeatureType.CATEGORICAL and d.name != "transaction_currency":
            assert d.allowed_values, d.name
        if d.units in {"count", "days", "hours", "minutes"}:
            assert d.min_value == 0, d.name
        if d.units == "probability":
            assert (d.min_value, d.max_value) == (0, 1), d.name
        if d.nullable:
            assert d.missing_when, f"{d.name}: nullable features must document when"
        # No sentinel conventions anywhere in the catalogue.
        assert "-1" not in d.missing_when and "999" not in d.missing_when


def test_every_source_exists_in_schema() -> None:
    for d in FEATURE_SET_1_0_0.definitions:
        for source in d.sources:
            table, column = source.split(".")
            assert table in Base.metadata.tables, source
            assert column in Base.metadata.tables[table].c, source


def test_labels_and_mutable_state_are_never_feature_sources() -> None:
    forbidden = {
        "users.synthetic_scenario",
        "transactions.status",
        "user_devices.is_trusted",
        "devices.successful_logins",
        "devices.last_seen_at",
        "network_identities.distinct_user_count",
        "network_identities.is_known_vpn",
    }
    for d in FEATURE_SET_1_0_0.definitions:
        assert not forbidden & set(d.sources), d.name
    # Only the explicitly historical label-count features may read fraud_labels.
    label_readers = {
        d.name
        for d in FEATURE_SET_1_0_0.definitions
        if any(s.startswith("fraud_labels.") for s in d.sources)
    }
    assert label_readers == {"historical_chargebacks", "historical_confirmed_fraud_events"}


def test_feature_set_invariants() -> None:
    d = FEATURE_SET_1_0_0.definitions[0]
    with pytest.raises(ValueError, match="duplicate"):
        FeatureSet("x", (d, d))
    with pytest.raises(ValueError, match="version"):
        FeatureSet("other-version", (d,))
    with pytest.raises(KeyError):
        FEATURE_SET_1_0_0.get("nope")
    assert FEATURE_SET_1_0_0.get("account_age_days").units == "days"


def test_fingerprint_ignores_documentation_but_not_semantics() -> None:
    d = FEATURE_SET_1_0_0.get("account_age_days")
    reworded = FeatureDefinition(**{**d.__dict__, "description": "changed words"})
    retyped = FeatureDefinition(**{**d.__dict__, "dtype": FeatureType.INTEGER})
    base = FeatureSet(d.feature_version, (d,))
    assert FeatureSet(d.feature_version, (reworded,)).fingerprint() == base.fingerprint()
    assert FeatureSet(d.feature_version, (retyped,)).fingerprint() != base.fingerprint()


def test_catalog_renderings() -> None:
    js = catalog_json()
    assert '"account_age_days"' in js and FINGERPRINT_1_0_0 in js
    md = catalog_markdown()
    assert md.startswith(MARKDOWN_BEGIN) and md.endswith(MARKDOWN_END)
    for name in FEATURE_SET_1_0_0.names:
        assert f"`{name}`" in md


def test_features_md_is_in_sync_with_definitions() -> None:
    """FEATURES.md embeds the generated catalogue; regenerate it if this fails:
    ``fraud-ai features catalog --format markdown``."""
    text = (ROOT / "FEATURES.md").read_text()
    start, end = text.index(MARKDOWN_BEGIN), text.index(MARKDOWN_END) + len(MARKDOWN_END)
    assert text[start:end] == catalog_markdown()
