"""Transaction amount and velocity features.

Amount statistics use only prior transactions in the *same currency* - minor units of
different currencies are not comparable. With no history the statistics are missing
(``not_observed``), never zero; ratios with a zero denominator are ``not_applicable``.
"""

from __future__ import annotations

from fraud_ai.features._common import NA, NOT_OBSERVED, names
from fraud_ai.features.definitions import EventKind, FeatureCategory, get_feature_set
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter
from fraud_ai.features.windows import elapsed_minutes

STATS = (
    "average_previous_transaction_amount",
    "median_previous_transaction_amount",
    "maximum_previous_transaction_amount",
    "transaction_vs_average_ratio",
    "transaction_vs_median_ratio",
    "unusually_high_transaction",
)


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    txn = ctx.transaction
    if ctx.kind is EventKind.LOGIN or txn is None:
        w.miss_all(names(w, FeatureCategory.TRANSACTION), NA)
        return
    min_history = int(get_feature_set(w.feature_version).parameters["unusually_high_min_history"])
    ut = h.user_transactions
    amount = txn.amount_minor
    w.put("transaction_amount_minor_units", amount)
    w.put("transaction_currency", txn.currency)
    n = ut.same_currency_count
    w.put("previous_transactions_same_currency", n)
    if n == 0 or ut.same_currency_max is None:
        w.miss_all(STATS, NOT_OBSERVED)
    else:
        average = ut.same_currency_sum / n
        median = h.median_same_currency(n)
        assert median is not None
        w.put("average_previous_transaction_amount", average)
        w.put("median_previous_transaction_amount", median)
        w.put("maximum_previous_transaction_amount", ut.same_currency_max)
        w.put_or_miss("transaction_vs_average_ratio", amount / average if average else None, NA)
        w.put_or_miss("transaction_vs_median_ratio", amount / median if median else None, NA)
        w.put_or_miss(
            "unusually_high_transaction",
            amount > ut.same_currency_max if n >= min_history else None,
            NOT_OBSERVED,
        )
    for window, count in ut.last.items():
        w.put(f"transactions_last_{window}", count)
    w.put("transaction_value_last_24h", ut.same_currency_value_24h)
    w.put_or_miss(
        "time_since_previous_transaction_minutes",
        elapsed_minutes(ut.last_occurred_at, ctx.as_of) if ut.last_occurred_at else None,
        NOT_OBSERVED,
    )
