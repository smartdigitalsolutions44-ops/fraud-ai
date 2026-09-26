"""Behavioural-change features: several changes in a short period.

The change features require something pre-existing (an older device, address or payment
method), so onboarding a brand-new account does not count as "change".
"""

from __future__ import annotations

from fraud_ai.features import security
from fraud_ai.features._common import NA, NOT_OBSERVED, UNKNOWN, names
from fraud_ai.features.definitions import FeatureCategory
from fraud_ai.features.history import EntityCounts, History
from fraud_ai.features.vector import FeatureWriter


def _changed(counts: EntityCounts) -> bool:
    return counts.in_recent_window >= 1 and counts.before_recent_window >= 1


def compute(h: History, w: FeatureWriter) -> None:
    if h.ctx.user_id is None:
        w.miss_all(names(w, FeatureCategory.BEHAVIOURAL), NA)
        return
    inside, before = h.recent_network_values
    if not inside and before is None:
        w.miss_all(("country_changed_recently", "asn_changed_recently"), NOT_OBSERVED)
    else:
        countries = {c for c, _ in inside if c is not None}
        asns = {a for _, a in inside if a is not None}
        if before is not None and inside:
            if before.country is not None:
                countries.add(before.country)
            if before.asn is not None:
                asns.add(before.asn)
        w.put_or_miss(
            "country_changed_recently", len(countries) > 1 if countries else None, UNKNOWN
        )
        w.put_or_miss("asn_changed_recently", len(asns) > 1 if asns else None, UNKNOWN)
    device = _changed(h.user_devices)
    address = _changed(h.user_addresses)
    payment = _changed(h.user_payment_methods)
    w.put("device_changed_recently", device)
    w.put("address_changed_recently", address)
    w.put("payment_method_changed_recently", payment)
    changes = [
        security.recent(h, "password_reset"),
        security.recent(h, "email_change"),
        security.recent(h, "phone_change"),
        security.recent(h, "mfa_change"),
        device,
        address,
        payment,
    ]
    w.put("rapid_multi_change_count", sum(changes))
