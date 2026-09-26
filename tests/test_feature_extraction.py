from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType
from fraud_ai.features.context import FeatureExtractionError, UnsupportedEventError
from fraud_ai.features.extractor import extract_features, extract_many
from fraud_ai.features.vector import MissingReason as R
from fraud_ai.ingestion.processor import EventProcessor
from tests.feature_helpers import HOME, VPN, Scenario, net

T = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
DAY = timedelta(days=1)


@pytest.fixture
def sc(session: Session, processor: EventProcessor) -> Scenario:
    return Scenario(session, processor)


# --------------------------------------------------------------------------- account
def test_account_features_and_unknown_verification(sc: Scenario) -> None:
    uid = sc.user(T - 100 * DAY)
    sc.login(uid, T - 2 * DAY)
    sc.login(uid, T - 2 * DAY + timedelta(minutes=1), ok=False)
    v = sc.features(sc.login(uid, T))
    assert v.get("account_age_days") == 100.0
    assert v.get("successful_logins_total") == 1 and v.get("failed_logins_total") == 1
    for name in ("email_verified", "phone_verified", "mfa_enabled"):
        assert v.missing[name] is R.UNKNOWN  # no lifecycle data is unknown, never False
    assert v.get("historical_chargebacks") == 0
    assert v.get("event_kind") == "login" and v.get("login_outcome") == "success"
    assert v.get("authenticated_user") is True


def test_email_verification_lifecycle(sc: Scenario) -> None:
    uid = sc.user(T - 30 * DAY)
    sc.lifecycle(uid, T - 29 * DAY, EventType.EMAIL_VERIFIED)
    sc.lifecycle(uid, T - 20 * DAY, EventType.MFA_ENABLED)
    first = sc.features(sc.login(uid, T - 10 * DAY))
    assert first.get("email_verified") is True and first.get("mfa_enabled") is True
    sc.lifecycle(uid, T - 5 * DAY, EventType.EMAIL_CHANGED)
    sc.lifecycle(uid, T - 5 * DAY, EventType.PHONE_CHANGED)
    sc.lifecycle(uid, T - 4 * DAY, EventType.MFA_DISABLED)
    second = sc.features(sc.login(uid, T))
    assert second.get("email_verified") is False  # changed after the last verification
    assert second.get("phone_verified") is False
    assert second.get("mfa_enabled") is False
    sc.lifecycle(uid, T + DAY, EventType.EMAIL_VERIFIED)
    assert sc.features(sc.login(uid, T + 2 * DAY)).get("email_verified") is True


# --------------------------------------------------------------------------- device
def test_device_transitions(sc: Scenario) -> None:
    uid = sc.user(T - 50 * DAY, device="dev-A")
    sc.login(uid, T - 10 * DAY, device="dev-A", mfa=True)
    known = sc.features(sc.login(uid, T - 9 * DAY, device="dev-A"))
    assert known.get("device_seen_before") is True and known.get("new_device") is False
    assert known.get("device_trusted") is True
    assert known.get("device_age_days") == 41.0
    assert known.get("time_since_device_last_seen_hours") == 24.0

    new = sc.features(sc.login(uid, T, device="dev-NEW"))
    assert new.get("device_seen_before") is False and new.get("new_device") is True
    assert new.get("device_trusted") is False and new.get("device_age_days") == 0.0
    assert new.missing["time_since_device_last_seen_hours"] is R.NOT_OBSERVED
    assert new.get("device_successful_login_count") == 0
    assert new.get("device_changed_recently") is True  # the account had an older device


def test_device_missing_is_not_observed(sc: Scenario) -> None:
    uid = sc.user(T - DAY)
    v = sc.features(sc.login(uid, T, device=None))
    assert v.missing["device_age_days"] is R.NOT_OBSERVED
    assert v.missing["accounts_per_device"] is R.NOT_OBSERVED


# --------------------------------------------------------------------------- network
def test_network_transitions_and_first_observation(sc: Scenario) -> None:
    uid = sc.user(T - 30 * DAY, network=net("10.0.0.1", asn=64601, country="GB"))
    first = sc.features(sc.login(uid, T - 20 * DAY, network=net("10.0.0.1")))
    assert first.get("country_changed") is False and first.get("network_seen_before") is True
    moved = sc.features(
        sc.login(uid, T, network=net("10.9.9.9", asn=64999, country="RO", network_type="mobile"))
    )
    assert moved.get("country_changed") is True
    assert moved.get("asn_changed") is True and moved.get("network_type_changed") is True
    assert moved.get("network_seen_before") is False and moved.get("network_first_seen_days") == 0.0
    assert moved.get("mobile_network") is True
    assert moved.get("country_changed_recently") is True


def test_first_ever_observation_is_not_observed(sc: Scenario) -> None:
    uid = uuid.uuid4()
    event = sc.emit(EventType.ACCOUNT_CREATED, T - DAY, uid, {"external_ref": "x"})  # no network
    del event
    v = sc.features(sc.login(uid, T))
    assert v.missing["country_changed"] is R.NOT_OBSERVED


def test_vpn_is_evidence_not_verdict(sc: Scenario) -> None:
    uid = sc.user(T - 400 * DAY, network=VPN)
    for d in range(1, 30):
        sc.login(uid, T - d * DAY, network=VPN)
    v = sc.features(sc.login(uid, T, network=VPN))
    assert v.get("vpn_detected") is True and v.get("vpn_probability") == 0.93
    assert v.get("datacenter_detected") is True
    assert v.get("country_changed") is False and v.get("network_seen_before") is True
    assert v.missing["proxy_probability"] is R.NOT_APPLICABLE  # not flagged as proxy
    assert v.get("historical_confirmed_fraud_events") == 0


def test_unknown_intel_is_unknown(sc: Scenario) -> None:
    uid = sc.user(T - DAY)
    bare = {"ip": "10.5.5.5"}  # no intel at all
    v = sc.features(sc.login(uid, T, network=bare))
    for name in (
        "vpn_detected",
        "vpn_probability",
        "proxy_detected",
        "tor_detected",
        "datacenter_detected",
        "mobile_network",
        "network_type",
        "country_changed",
    ):
        assert v.missing[name] is R.UNKNOWN, name
    flagged_no_conf = net("10.5.5.6", is_known_vpn=True)
    v2 = sc.features(sc.login(uid, T + timedelta(minutes=1), network=flagged_no_conf))
    assert v2.missing["vpn_probability"] is R.UNKNOWN


def test_shared_carrier_nat_is_descriptive(sc: Scenario) -> None:
    cgnat = net("100.64.1.5", asn=64701, network_type="mobile")
    users = [sc.user(T - 90 * DAY, device=f"phone-{i}", network=cgnat) for i in range(4)]
    for i, uid in enumerate(users[:3]):
        sc.login(uid, T - timedelta(minutes=30 - i), device=f"phone-{i}", network=cgnat)
    v = sc.features(sc.login(users[3], T, device="phone-3", network=cgnat))
    assert v.get("accounts_per_network") == 3 and v.get("shared_network_flag") is True
    assert v.get("accounts_seen_from_network") == 4  # including this account's signup
    assert v.get("accounts_seen_from_network_last_1h") == 3
    assert v.get("shared_device_flag") is False and v.get("mobile_network") is True
    assert v.get("historical_confirmed_fraud_events") == 0


def test_anonymous_login_features(sc: Scenario) -> None:
    bot = net("203.0.113.9", asn=65101, network_type="datacenter", is_datacenter=True)
    for i in range(5):
        sc.login(None, T - timedelta(seconds=50 - i), ok=False, device="bot", network=bot)
    v = sc.features(sc.login(None, T, ok=False, device="bot", network=bot))
    assert v.get("authenticated_user") is False and v.get("login_outcome") == "failure"
    assert v.get("failed_logins_from_network_last_1h") == 5
    assert v.get("device_failed_login_count") == 5
    for name in (
        "account_age_days",
        "logins_last_5m",
        "device_age_days",
        "country_changed",
        "minutes_since_password_reset",
        "rapid_multi_change_count",
    ):
        assert v.missing[name] is R.NOT_APPLICABLE, name
    assert v.source_event_count == 6  # observations of the network


def test_multiple_accounts_on_suspicious_infrastructure(sc: Scenario) -> None:
    ring = net(
        "203.0.113.70",
        asn=65102,
        network_type="datacenter",
        is_known_proxy=True,
        is_datacenter=True,
        proxy_confidence=0.91,
    )
    victims = [sc.user(T - 300 * DAY, device=f"home-{i}") for i in range(3)]
    for i, uid in enumerate(victims[:2]):
        sc.login(uid, T - timedelta(minutes=40 - i), device="ring-laptop", network=ring)
    v = sc.features(sc.login(victims[2], T, device="ring-laptop", network=ring))
    assert v.get("accounts_per_device") == 2 and v.get("shared_device_flag") is True
    assert v.get("accounts_seen_on_device_last_24h") == 2
    assert v.get("accounts_per_network") == 2 and v.get("proxy_probability") == 0.91
    assert v.get("new_device") is True


# --------------------------------------------------------------------------- velocity
def test_login_velocity_windows_and_boundaries(sc: Scenario) -> None:
    uid = sc.user(T - 40 * DAY)
    sc.login(uid, T - timedelta(minutes=5), ok=False)  # exactly 5m before: outside 5m window
    sc.login(uid, T - timedelta(minutes=4), ok=False, network=net("10.7.7.7"), device="dev-B")
    sc.login(uid, T - timedelta(minutes=14))
    sc.login(uid, T - timedelta(minutes=59))
    sc.login(uid, T - timedelta(hours=23))
    sc.login(uid, T - 6 * DAY)
    sc.login(uid, T - 29 * DAY)
    v = sc.features(sc.login(uid, T))  # the scored login never counts itself
    assert [v.get(f"logins_last_{w}") for w in ("5m", "15m", "1h", "24h", "7d", "30d")] == [
        1,
        3,
        4,
        5,
        6,
        7,
    ]
    assert [v.get(f"failed_logins_last_{w}") for w in ("5m", "15m", "1h")] == [1, 2, 2]
    assert v.get("successful_logins_last_1h") == 2
    assert v.get("distinct_networks_last_1h") == 2 and v.get("distinct_devices_last_1h") == 2


# --------------------------------------------------------------------------- transactions
def test_no_previous_transactions_is_missing_not_zero(sc: Scenario) -> None:
    uid = sc.user(T - DAY)
    event, _ = sc.purchase(uid, T, "40.00")
    v = sc.features(event)
    assert v.get("transaction_amount_minor_units") == 4000
    assert v.get("previous_transactions_same_currency") == 0
    for name in (
        "average_previous_transaction_amount",
        "median_previous_transaction_amount",
        "maximum_previous_transaction_amount",
        "transaction_vs_average_ratio",
        "transaction_vs_median_ratio",
        "unusually_high_transaction",
        "time_since_previous_transaction_minutes",
    ):
        assert v.missing[name] is R.NOT_OBSERVED, name
    assert v.get("transactions_last_24h") == 0  # counts are genuine zeros
    assert v.missing["address_age_days"] is R.NOT_APPLICABLE  # no shipping address
    assert v.missing["payment_method_age_days"] is R.NOT_APPLICABLE


def test_transaction_statistics_and_ratios(sc: Scenario) -> None:
    uid = sc.user(T - 90 * DAY)
    for i, amount in enumerate(("10.00", "20.00", "30.00", "100.00")):
        sc.purchase(uid, T - (10 - i) * DAY, amount)
    sc.purchase(uid, T - timedelta(hours=3), "5.00", decision="decline")
    sc.purchase(uid, T - timedelta(hours=2), "999.00", currency="EUR")  # other currency
    event, _ = sc.purchase(uid, T, "400.00")
    v = sc.features(event)
    assert v.get("previous_transactions_same_currency") == 5
    assert v.get("average_previous_transaction_amount") == 3300.0  # (1000+2000+3000+10000+500)/5
    assert v.get("median_previous_transaction_amount") == 2000.0
    assert v.get("maximum_previous_transaction_amount") == 10000
    assert v.get("transaction_vs_average_ratio") == round(40000 / 3300, 6)
    assert v.get("transaction_vs_median_ratio") == 20.0
    assert v.get("unusually_high_transaction") is True  # 40000 exceeds the previous 10000 max
    assert v.get("transactions_last_24h") == 2  # includes the EUR one
    assert v.get("transaction_value_last_24h") == 500  # same currency only
    assert v.get("time_since_previous_transaction_minutes") == 120.0
    assert v.get("successful_transactions_total") == 5  # 4 GBP + 1 EUR approved
    assert v.get("failed_transactions_total") == 1


def test_even_median_and_zero_denominator(sc: Scenario) -> None:
    uid = sc.user(T - 90 * DAY)
    for i, amount in enumerate(("0.00", "0.00")):
        sc.purchase(uid, T - (5 - i) * DAY, amount)
    event, _ = sc.purchase(uid, T, "10.00")
    v = sc.features(event)
    assert v.get("average_previous_transaction_amount") == 0.0
    assert v.missing["transaction_vs_average_ratio"] is R.NOT_APPLICABLE  # 1000 / 0
    assert v.missing["transaction_vs_median_ratio"] is R.NOT_APPLICABLE
    assert v.missing["unusually_high_transaction"] is R.NOT_OBSERVED  # < 3 prior


def test_unusually_high_needs_history(sc: Scenario) -> None:
    uid = sc.user(T - 90 * DAY)
    for i in range(3):
        sc.purchase(uid, T - (5 - i) * DAY, "10.00")
    event, _ = sc.purchase(uid, T, "10.01")
    assert sc.features(event).get("unusually_high_transaction") is True


# --------------------------------------------------------------------------- address / payment
def test_address_and_payment_transitions(sc: Scenario) -> None:
    uid = sc.user(T - 100 * DAY)
    home = sc.address(uid, T - 100 * DAY)
    pm = sc.payment_method(uid, T - 100 * DAY, issuer="GB", fingerprint="fp-1")
    sc.emit(EventType.ADDRESS_VERIFIED, T - 99 * DAY, uid, {"address_id": str(home)})
    sc.emit(EventType.PAYMENT_METHOD_VERIFIED, T - 99 * DAY, uid, {"payment_method_id": str(pm)})
    sc.purchase(uid, T - 10 * DAY, "10.00", pm=pm, address=home)
    sc.purchase(uid, T - 5 * DAY, "10.00", pm=pm, address=home, decision="decline")
    event, _ = sc.purchase(uid, T, "10.00", pm=pm, address=home)
    v = sc.features(event)
    assert v.get("address_verified") is True and v.get("payment_method_verified") is True
    assert v.get("orders_to_address") == 2 and v.get("successful_orders_to_address") == 1
    assert v.get("failed_orders_to_address") == 1 and v.get("address_seen_before") is True
    assert v.get("time_since_address_last_used_hours") == 120.0
    assert v.get("issuing_country_changed") is False and v.get("new_payment_method") is False
    assert v.get("accounts_sharing_payment_fingerprint") == 0

    drop = sc.address(uid, T + timedelta(hours=1), text="9 Drop St, Lagos", country="NG")
    foreign = sc.payment_method(uid, T + timedelta(hours=1), issuer="RO", fingerprint="fp-1")
    ev2, _ = sc.purchase(uid, T + timedelta(hours=2), "300.00", pm=foreign, address=drop)
    v2 = sc.features(ev2)
    assert v2.get("new_address") is True and v2.get("address_seen_before") is False
    assert v2.missing["time_since_address_last_used_hours"] is R.NOT_OBSERVED
    assert v2.get("address_verified") is False and v2.get("new_payment_method") is True
    assert v2.get("issuing_country_changed") is True
    assert v2.get("address_changed_recently") is True
    assert v2.get("payment_method_changed_recently") is True
    assert v2.get("addresses_per_account") == 2 and v2.get("payment_methods_per_account") == 2
    assert v2.get("accounts_sharing_payment_fingerprint") == 0  # own cards never count


def test_shared_address_and_fingerprint_across_accounts(sc: Scenario) -> None:
    a = sc.user(T - 50 * DAY, device="a")
    b = sc.user(T - 50 * DAY, device="b")
    sc.address(a, T - 40 * DAY, text="5 Shared Lane")
    sc.payment_method(a, T - 40 * DAY, fingerprint="same-card")
    addr = sc.address(b, T - DAY, text="5 shared lane.")  # normalised to the same hash
    pm = sc.payment_method(b, T - DAY, fingerprint="same-card")
    event, _ = sc.purchase(b, T, "10.00", pm=pm, address=addr, device="b")
    v = sc.features(event)
    assert v.get("accounts_sharing_address") == 1
    assert v.get("accounts_sharing_payment_fingerprint") == 1


def test_payment_without_fingerprint_is_unknown(sc: Scenario) -> None:
    uid = sc.user(T - DAY)
    pm = sc.payment_method(uid, T - DAY)
    event, _ = sc.purchase(uid, T, "1.00", pm=pm)
    v = sc.features(event)
    assert v.missing["accounts_sharing_payment_fingerprint"] is R.UNKNOWN
    assert v.missing["issuing_country_changed"] is R.NOT_OBSERVED


# --------------------------------------------------------------------------- security
def test_security_recency_and_rapid_change_count(sc: Scenario) -> None:
    uid = sc.user(T - 300 * DAY, device="dev-A")
    sc.address(uid, T - 300 * DAY)
    sc.payment_method(uid, T - 300 * DAY)
    sc.lifecycle(uid, T - 40 * DAY, EventType.PASSWORD_RESET)
    calm = sc.features(sc.login(uid, T - 30 * DAY))
    assert calm.get("minutes_since_password_reset") == 10 * 24 * 60
    assert calm.get("recent_password_reset") is False and calm.get("rapid_multi_change_count") == 0
    assert calm.missing["minutes_since_email_change"] is R.NOT_OBSERVED
    assert calm.get("recent_email_change") is False

    # Account takeover: reset + email change + MFA removal + new device + new address + new
    # payment method, then an expensive order.
    sc.lifecycle(uid, T - timedelta(minutes=30), EventType.PASSWORD_RESET)
    sc.lifecycle(uid, T - timedelta(minutes=28), EventType.EMAIL_CHANGED)
    sc.lifecycle(uid, T - timedelta(minutes=27), EventType.MFA_DISABLED)
    sc.login(uid, T - timedelta(minutes=25), device="attacker")
    drop = sc.address(uid, T - timedelta(minutes=20), text="Drop house")
    pm = sc.payment_method(uid, T - timedelta(minutes=15))
    event, _ = sc.purchase(uid, T, "900.00", pm=pm, address=drop, device="attacker")
    v = sc.features(event)
    assert v.get("minutes_since_password_reset") == 30.0
    assert v.get("recent_password_reset") is True and v.get("recent_email_change") is True
    assert v.get("recent_mfa_removed") is True and v.get("minutes_since_mfa_change") == 27.0
    assert v.get("device_changed_recently") is True and v.get("address_changed_recently") is True
    assert v.get("rapid_multi_change_count") == 6
    assert v.get("new_device") is True and v.get("new_address") is True


def test_onboarding_is_not_rapid_change(sc: Scenario) -> None:
    uid = sc.user(T - timedelta(hours=1))
    addr = sc.address(uid, T - timedelta(minutes=50))
    pm = sc.payment_method(uid, T - timedelta(minutes=40))
    event, _ = sc.purchase(uid, T, "20.00", pm=pm, address=addr)
    v = sc.features(event)
    assert v.get("rapid_multi_change_count") == 0
    assert v.get("new_address") is True and v.get("address_changed_recently") is False


def test_new_home_address_alone_is_just_one_change(sc: Scenario) -> None:
    uid = sc.user(T - 500 * DAY)
    old = sc.address(uid, T - 500 * DAY)
    new = sc.address(uid, T - timedelta(hours=5), replaces=old, text="9 New Home Rd")
    event, _ = sc.purchase(uid, T, "80.00", address=new)
    v = sc.features(event)
    assert v.get("address_changed_recently") is True
    assert v.get("rapid_multi_change_count") == 1
    assert v.get("recent_password_reset") is False and v.get("new_device") is False


# --------------------------------------------------------------------------- API errors
def test_api_errors(sc: Scenario) -> None:
    uid = sc.user(T - DAY)
    login = sc.login(uid, T)
    sc.session.flush()
    with pytest.raises(UnsupportedEventError):
        created = sc.emit(EventType.PASSWORD_RESET, T, uid, {})
        sc.session.flush()
        extract_features(sc.session, created.event_id)
    with pytest.raises(FeatureExtractionError, match="precedes"):
        extract_features(sc.session, login.event_id, T - timedelta(seconds=1))
    with pytest.raises(FeatureExtractionError, match="unknown event"):
        extract_features(sc.session, uuid.uuid4())
    with pytest.raises(KeyError):
        extract_features(sc.session, login.event_id, feature_version="nope")
    assert extract_many(sc.session, [login.event_id])[0].event_id == login.event_id
    assert HOME["ip"] == "10.1.2.3"
