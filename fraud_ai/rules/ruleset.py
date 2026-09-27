"""The first explicit rule set: ``fraud-rules-1.0.0``.

Few, explainable rules over point-in-time features. They cover patterns that a security
team would want enforced regardless of what a model learned:

| id | reason code | severity |
|---|---|---|
| R001 | `ATO_RESET_NEW_DEVICE_HIGH_VALUE` | high |
| R002 | `FAILED_LOGIN_BURST` | medium |
| R003 | `RAPID_ACCOUNT_CHANGES` | medium |
| R004 | `MFA_REMOVED_NEW_DEVICE` | high |
| R005 | `ANONYMISED_NETWORK_NEW_DEVICE` | low |
| R006 | `NEW_PAYMENT_NEW_ADDRESS_HIGH_VALUE` | medium |

VPN use alone never matches a rule: it is a signal, not proof. R005 needs Tor or a
datacenter network *and* a new device, and its severity is only "low" (monitoring). The
synthetic data contains no compromised-credential signal, so there is no rule for one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fraud_ai.core.enums import RuleSeverity
from fraud_ai.rules.engine import Features, Rule, RuleSet

RULES_VERSION = "fraud-rules-1.0.0"


def _true(features: Features, name: str) -> bool:
    return features.get(name) is True


def _num(features: Features, name: str) -> float:
    value = features.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value)


def _r001(f: Features, p: Mapping[str, Any]) -> bool:
    high_value = _true(f, "unusually_high_transaction") or _num(
        f, "transaction_vs_median_ratio"
    ) >= float(p["median_ratio"])
    return _true(f, "recent_password_reset") and _true(f, "new_device") and high_value


def _r002(f: Features, p: Mapping[str, Any]) -> bool:
    return _num(f, "failed_logins_last_15m") >= float(p["account_failures_15m"]) or _num(
        f, "failed_logins_from_network_last_1h"
    ) >= float(p["network_failures_1h"])


def _r003(f: Features, p: Mapping[str, Any]) -> bool:
    return _num(f, "rapid_multi_change_count") >= float(p["changes_24h"])


def _r004(f: Features, p: Mapping[str, Any]) -> bool:
    return _true(f, "recent_mfa_removed") and _true(f, "new_device")


def _r005(f: Features, p: Mapping[str, Any]) -> bool:
    anonymised = _true(f, "tor_detected") or _true(f, "datacenter_detected")
    return anonymised and _true(f, "new_device")


def _r006(f: Features, p: Mapping[str, Any]) -> bool:
    return (
        _true(f, "new_payment_method")
        and _true(f, "new_address")
        and _true(f, "unusually_high_transaction")
    )


RULES = (
    Rule(
        "R001",
        "reset_new_device_high_value",
        "1.0.0",
        "Password reset and a new device in the last 24 hours, then an unusually high "
        "transaction (the classic takeover cash-out).",
        RuleSeverity.HIGH,
        "ATO_RESET_NEW_DEVICE_HIGH_VALUE",
        "account_takeover",
        _r001,
        ("recent_password_reset", "new_device"),
        ("unusually_high_transaction", "transaction_vs_median_ratio"),
        frozenset({"transaction"}),
        {"median_ratio": 3.0},
    ),
    Rule(
        "R002",
        "failed_login_burst",
        "1.0.0",
        "A burst of failed logins on the account (15 minutes) or from the network (1 hour).",
        RuleSeverity.MEDIUM,
        "FAILED_LOGIN_BURST",
        "velocity",
        _r002,
        ("failed_logins_last_15m",),
        ("failed_logins_from_network_last_1h",),
        parameters={"account_failures_15m": 5, "network_failures_1h": 10},
    ),
    Rule(
        "R003",
        "rapid_account_changes",
        "1.0.0",
        "Three or more kinds of account change (password, email, phone, MFA, device, "
        "address, payment method) within 24 hours.",
        RuleSeverity.MEDIUM,
        "RAPID_ACCOUNT_CHANGES",
        "account_changes",
        _r003,
        ("rapid_multi_change_count",),
        parameters={"changes_24h": 3},
    ),
    Rule(
        "R004",
        "mfa_removed_new_device",
        "1.0.0",
        "MFA was removed in the last 24 hours and the event comes from a new device.",
        RuleSeverity.HIGH,
        "MFA_REMOVED_NEW_DEVICE",
        "account_takeover",
        _r004,
        ("recent_mfa_removed", "new_device"),
    ),
    Rule(
        "R005",
        "anonymised_network_new_device",
        "1.0.0",
        "A Tor or datacenter network together with a new device. VPN use alone is not "
        "matched: it is a signal, not proof.",
        RuleSeverity.LOW,
        "ANONYMISED_NETWORK_NEW_DEVICE",
        "network",
        _r005,
        ("new_device",),
        ("tor_detected", "datacenter_detected"),
    ),
    Rule(
        "R006",
        "new_payment_new_address_high_value",
        "1.0.0",
        "A payment method and a delivery address both added in the last 24 hours, with an "
        "unusually high amount.",
        RuleSeverity.MEDIUM,
        "NEW_PAYMENT_NEW_ADDRESS_HIGH_VALUE",
        "payment",
        _r006,
        ("new_payment_method", "new_address", "unusually_high_transaction"),
        applies_to=frozenset({"transaction"}),
    ),
)

RULE_SETS: dict[str, RuleSet] = {RULES_VERSION: RuleSet(RULES_VERSION, RULES)}


def get_rule_set(version: str = RULES_VERSION) -> RuleSet:
    try:
        return RULE_SETS[version]
    except KeyError:
        raise KeyError(f"unknown rule set {version!r}; known: {sorted(RULE_SETS)}") from None
