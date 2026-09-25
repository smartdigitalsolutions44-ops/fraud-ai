from fraud_ai.database.base import Base
from fraud_ai.features.catalog import FEATURE_CATALOG, FEATURE_NAMES

REQUIRED = {
    "account_age_days",
    "device_age_days",
    "address_age_days",
    "payment_method_age_days",
    "new_device",
    "new_address",
    "new_payment_method",
    "login_velocity_5m",
    "login_velocity_1h",
    "failed_login_velocity",
    "country_changed",
    "asn_changed",
    "network_type_changed",
    "accounts_per_ip",
    "accounts_per_device",
    "transaction_amount",
    "average_transaction_amount",
    "transaction_vs_average_ratio",
    "transactions_last_hour",
    "transactions_last_day",
    "time_since_password_reset",
    "vpn_detected",
    "proxy_detected",
    "tor_detected",
    "datacenter_network",
    "historical_fraud_rate",
    "address_reuse_count",
    "device_reuse_count",
    "ip_reuse_count",
}


def test_catalog_covers_required_features_uniquely() -> None:
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    assert set(FEATURE_NAMES) >= REQUIRED


def test_every_feature_source_exists_in_schema() -> None:
    for spec in FEATURE_CATALOG:
        assert spec.sources, spec.name
        for source in spec.sources:
            table, column = source.split(".")
            assert table in Base.metadata.tables, source
            assert column in Base.metadata.tables[table].c, source


def test_synthetic_scenario_is_never_a_feature_source() -> None:
    assert all("synthetic_scenario" not in s for f in FEATURE_CATALOG for s in f.sources)
