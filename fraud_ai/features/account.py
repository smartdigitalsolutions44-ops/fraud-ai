"""Account features: age, verification state, lifetime outcomes and known label history."""

from __future__ import annotations

from datetime import datetime

from fraud_ai.core.enums import SecurityEventType as S
from fraud_ai.features._common import NA, UNKNOWN, names
from fraud_ai.features.definitions import FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter
from fraud_ai.features.windows import elapsed_days


def _verified(last: dict[S, datetime], verified: S, changed: S) -> bool | None:
    """Verified iff the latest verification is strictly after the latest change."""
    v, c = last.get(verified), last.get(changed)
    if v is None and c is None:
        return None  # no lifecycle data at all: unknown, not "unverified"
    if v is None:
        return False
    return c is None or v > c


def _enabled(last: dict[S, datetime]) -> bool | None:
    on, off = last.get(S.MFA_ENABLED), last.get(S.MFA_DISABLED)
    if on is None and off is None:
        return None
    if on is None:
        return False
    return off is None or on > off


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    if ctx.user_id is None or ctx.account_created_at is None:
        w.miss_all(names(w, FeatureCategory.ACCOUNT), NA)
        return
    w.put("account_age_days", elapsed_days(ctx.account_created_at, ctx.as_of))
    last = h.security_last
    w.put_or_miss("email_verified", _verified(last, S.EMAIL_VERIFIED, S.EMAIL_CHANGED), UNKNOWN)
    w.put_or_miss("phone_verified", _verified(last, S.PHONE_VERIFIED, S.PHONE_CHANGED), UNKNOWN)
    w.put_or_miss("mfa_enabled", _enabled(last), UNKNOWN)
    logins = h.user_logins
    w.put("successful_logins_total", logins.success_total)
    w.put("failed_logins_total", logins.failure_total)
    txns = h.user_transactions
    w.put("successful_transactions_total", txns.approved)
    w.put("failed_transactions_total", txns.declined)
    chargebacks, confirmed = h.label_counts
    w.put("historical_chargebacks", chargebacks)
    w.put("historical_confirmed_fraud_events", confirmed)
