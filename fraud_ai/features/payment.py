"""Payment-method features (vault token metadata only - never card data)."""

from __future__ import annotations

from fraud_ai.features._common import NA, NOT_OBSERVED, UNKNOWN, names
from fraud_ai.features.definitions import EventKind, FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter
from fraud_ai.features.windows import RECENT_WINDOW, elapsed_days


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    pm = ctx.payment_method
    if ctx.kind is EventKind.LOGIN or pm is None:
        w.miss_all(names(w, FeatureCategory.PAYMENT), NA)
        return
    usage = h.payment_method_usage
    w.put("payment_method_age_days", elapsed_days(pm.added_at, ctx.as_of))
    w.put("payment_method_seen_before", usage.orders > 0)
    w.put("payment_method_verified", pm.verified_at is not None and pm.verified_at <= ctx.as_of)
    w.put("successful_transactions_on_payment_method", usage.approved)
    w.put("failed_transactions_on_payment_method", usage.declined)
    has_previous, previous_had_pm, previous_country = h.previous_transaction_issuer
    if not has_previous or not previous_had_pm:
        w.miss("issuing_country_changed", NOT_OBSERVED)
    elif previous_country is None or pm.issuer_country is None:
        w.miss("issuing_country_changed", UNKNOWN)
    else:
        w.put("issuing_country_changed", previous_country != pm.issuer_country)
    w.put("new_payment_method", RECENT_WINDOW.contains(pm.added_at, ctx.as_of))
    w.put_or_miss("accounts_sharing_payment_fingerprint", h.accounts_sharing_fingerprint, UNKNOWN)
