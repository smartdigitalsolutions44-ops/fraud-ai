"""Login-velocity features for the account."""

from __future__ import annotations

from fraud_ai.features._common import NA, names
from fraud_ai.features.definitions import FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter


def compute(h: History, w: FeatureWriter) -> None:
    if h.ctx.user_id is None:
        w.miss_all(names(w, FeatureCategory.LOGIN_VELOCITY), NA)
        return
    logins = h.user_logins
    for window, count in logins.last.items():
        w.put(f"logins_last_{window}", count)
    for window, count in logins.failed_last.items():
        w.put(f"failed_logins_last_{window}", count)
    w.put("successful_logins_last_1h", logins.success_last_1h)
    w.put("distinct_networks_last_1h", logins.distinct_networks_1h)
    w.put("distinct_devices_last_1h", logins.distinct_devices_1h)
