"""Device features: application-level device history (no fingerprinting)."""

from __future__ import annotations

from fraud_ai.features._common import NA, NOT_OBSERVED, names
from fraud_ai.features.definitions import FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter
from fraud_ai.features.windows import RECENT_WINDOW, elapsed_days, elapsed_hours

USER_SCOPED = ("device_age_days", "device_seen_before", "device_trusted", "new_device")


def compute(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    if ctx.device_id is None:
        w.miss_all(names(w, FeatureCategory.DEVICE), NOT_OBSERVED)
        return
    d = h.device
    if ctx.user_id is None:
        w.miss_all(USER_SCOPED, NA)
    else:
        # The scored event itself is an observation of the device at event time.
        first = min(d.first_for_user, ctx.event_time) if d.first_for_user else ctx.event_time
        w.put("device_age_days", elapsed_days(first, ctx.as_of))
        w.put("device_seen_before", d.prior_for_user > 0)
        w.put("device_trusted", h.user_logins.mfa_successes_on_device > 0)
        w.put("new_device", RECENT_WINDOW.contains(first, ctx.as_of))
    w.put("device_successful_login_count", d.successful_logins)
    w.put("device_failed_login_count", d.failed_logins)
    w.put("accounts_seen_on_device", d.accounts)
    w.put("accounts_seen_on_device_last_24h", d.accounts_24h)
    w.put_or_miss(
        "time_since_device_last_seen_hours",
        elapsed_hours(d.last_seen, ctx.as_of) if d.last_seen else None,
        NOT_OBSERVED,
    )
