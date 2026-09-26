"""Network features from the intel snapshot recorded with the event.

VPN, proxy, Tor and datacenter flags are exposed as evidence for a model to weigh; they
are never treated as fraud by themselves. Nothing here tries to discover the origin behind
an anonymising network.
"""

from __future__ import annotations

from fraud_ai.core.enums import NetworkType
from fraud_ai.features._common import NA, NOT_OBSERVED, UNKNOWN, names
from fraud_ai.features.definitions import FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter, MissingReason
from fraud_ai.features.windows import elapsed_days


def _flag_probability(
    flag: bool | None, confidence: float | None
) -> tuple[float | None, MissingReason]:
    if flag is None:
        return None, UNKNOWN
    if not flag:
        return None, NA  # not flagged: a flag-conditional confidence does not apply
    return confidence, UNKNOWN


def _changed(previous: object, current: object) -> tuple[bool | None, MissingReason]:
    if previous is None or current is None:
        return None, UNKNOWN
    return previous != current, UNKNOWN


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    obs = ctx.network
    if obs is None:
        w.miss_all(names(w, FeatureCategory.NETWORK), NOT_OBSERVED)
        return
    nh = h.network
    first = min(nh.first_seen, ctx.event_time) if nh.first_seen else ctx.event_time
    w.put("network_first_seen_days", elapsed_days(first, ctx.as_of))
    w.put("network_seen_before", nh.prior_observations > 0)
    network_type = obs.network_type if obs.network_type is not NetworkType.UNKNOWN else None
    w.put_or_miss("network_type", network_type.value if network_type else None, UNKNOWN)
    w.put_or_miss("vpn_detected", obs.is_known_vpn, UNKNOWN)
    w.put_or_miss("vpn_probability", *_flag_probability(obs.is_known_vpn, obs.proxy_confidence))
    w.put_or_miss("proxy_detected", obs.is_known_proxy, UNKNOWN)
    w.put_or_miss("proxy_probability", *_flag_probability(obs.is_known_proxy, obs.proxy_confidence))
    w.put_or_miss("tor_detected", obs.is_tor, UNKNOWN)
    w.put_or_miss("datacenter_detected", obs.is_datacenter, UNKNOWN)
    w.put_or_miss("mobile_network", obs.is_mobile_network, UNKNOWN)

    transitions = ("country_changed", "asn_changed", "network_type_changed")
    if ctx.user_id is None:
        w.miss_all(transitions, NA)
    elif (prev := h.previous_user_observation) is None:
        w.miss_all(transitions, NOT_OBSERVED)
    else:
        w.put_or_miss("country_changed", *_changed(prev.country, obs.country))
        w.put_or_miss("asn_changed", *_changed(prev.asn, obs.asn))
        prev_type = prev.network_type if prev.network_type is not NetworkType.UNKNOWN else None
        w.put_or_miss("network_type_changed", *_changed(prev_type, network_type))

    w.put("accounts_seen_from_network", nh.accounts)
    w.put("accounts_seen_from_network_last_1h", nh.accounts_1h)
    w.put("successful_logins_from_network", nh.successful_logins)
    w.put("failed_logins_from_network", nh.failed_logins)
    w.put("failed_logins_from_network_last_1h", nh.failed_logins_1h)
