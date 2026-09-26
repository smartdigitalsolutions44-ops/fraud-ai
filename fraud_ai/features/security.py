"""Security-event recency features."""

from __future__ import annotations

from datetime import datetime

from fraud_ai.core.enums import SecurityEventType as S
from fraud_ai.features._common import NA, NOT_OBSERVED, names
from fraud_ai.features.definitions import FeatureCategory
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter
from fraud_ai.features.windows import RECENT_WINDOW, elapsed_minutes


def latest(h: History) -> dict[str, datetime | None]:
    last = h.security_last
    mfa = [t for t in (last.get(S.MFA_ENABLED), last.get(S.MFA_DISABLED)) if t is not None]
    return {
        "password_reset": last.get(S.PASSWORD_RESET),
        "email_change": last.get(S.EMAIL_CHANGED),
        "phone_change": last.get(S.PHONE_CHANGED),
        "mfa_change": max(mfa) if mfa else None,
        "mfa_removed": last.get(S.MFA_DISABLED),
    }


def recent(h: History, kind: str) -> bool:
    ts = latest(h)[kind]
    return ts is not None and RECENT_WINDOW.contains(ts, h.as_of)


def compute(h: History, w: FeatureWriter) -> None:
    if h.ctx.user_id is None:
        w.miss_all(names(w, FeatureCategory.SECURITY), NA)
        return
    last = latest(h)
    for kind in ("password_reset", "email_change", "phone_change", "mfa_change"):
        ts = last[kind]
        w.put_or_miss(
            f"minutes_since_{kind}", elapsed_minutes(ts, h.as_of) if ts else None, NOT_OBSERVED
        )
    for kind in ("password_reset", "email_change", "phone_change", "mfa_removed"):
        w.put(f"recent_{kind}", recent(h, kind))
