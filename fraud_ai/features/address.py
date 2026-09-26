"""Shipping-address features (keyed hashes and coarse data only)."""

from __future__ import annotations

from fraud_ai.features._common import NA, NOT_OBSERVED, names
from fraud_ai.features.definitions import EventKind, FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter
from fraud_ai.features.windows import RECENT_WINDOW, elapsed_days, elapsed_hours


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    address = ctx.address
    if ctx.kind is EventKind.LOGIN or address is None:
        w.miss_all(names(w, FeatureCategory.ADDRESS), NA)
        return
    usage = h.address_usage
    w.put("address_age_days", elapsed_days(address.added_at, ctx.as_of))
    w.put("address_seen_before", usage.orders > 0)
    w.put("address_verified", address.verified_at is not None and address.verified_at <= ctx.as_of)
    w.put("orders_to_address", usage.orders)
    w.put("successful_orders_to_address", usage.approved)
    w.put("failed_orders_to_address", usage.declined)
    w.put("new_address", RECENT_WINDOW.contains(address.added_at, ctx.as_of))
    w.put_or_miss(
        "time_since_address_last_used_hours",
        elapsed_hours(usage.last_used, ctx.as_of) if usage.last_used else None,
        NOT_OBSERVED,
    )
    w.put("accounts_sharing_address", h.accounts_sharing_address)
