"""Reusable point-in-time window utilities.

Every history query in feature engineering is bounded above by ``as_of`` (inclusive):
nothing that happened after the moment being scored may influence a feature. Windows add a
lower bound: a window of length ``d`` covers the half-open interval ``(as_of - d, as_of]``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import BindParameter, ColumnElement, and_, bindparam, case, func

from fraud_ai.database.base import UTCDateTime
from fraud_ai.utils.time import ensure_utc


@dataclass(frozen=True)
class TimeWindow:
    name: str
    duration: timedelta

    def lower_bound(self, as_of: datetime) -> datetime:
        return ensure_utc(as_of) - self.duration

    def contains(self, ts: datetime, as_of: datetime) -> bool:
        ts, as_of = ensure_utc(ts), ensure_utc(as_of)
        return self.lower_bound(as_of) < ts <= as_of

    def clause(self, column: Any, as_of: datetime) -> ColumnElement[bool]:
        """SQL predicate ``lower < column <= as_of``."""
        return and_(column > self.lower_bound(as_of), column <= ensure_utc(as_of))


W5M = TimeWindow("5m", timedelta(minutes=5))
W15M = TimeWindow("15m", timedelta(minutes=15))
W1H = TimeWindow("1h", timedelta(hours=1))
W6H = TimeWindow("6h", timedelta(hours=6))
W24H = TimeWindow("24h", timedelta(hours=24))
W7D = TimeWindow("7d", timedelta(days=7))
W30D = TimeWindow("30d", timedelta(days=30))
WINDOWS: tuple[TimeWindow, ...] = (W5M, W15M, W1H, W6H, W24H, W7D, W30D)
WINDOWS_BY_NAME = {w.name: w for w in WINDOWS}

# "recent" / "new" in feature names means within this window.
RECENT_WINDOW = W24H


# ---- parameterised forms, used by statements that are built once and reused ------------
def as_of_param() -> BindParameter[datetime]:
    return bindparam("as_of", type_=UTCDateTime())


def lower_param(window: TimeWindow) -> BindParameter[datetime]:
    return bindparam(f"lower_{window.name}", type_=UTCDateTime())


def upto_param(column: Any) -> ColumnElement[bool]:
    """``column <= :as_of``."""
    return column <= as_of_param()  # type: ignore[no-any-return]


def in_window_param(column: Any, window: TimeWindow) -> ColumnElement[bool]:
    """``:lower_<w> < column <= :as_of``."""
    return and_(column > lower_param(window), column <= as_of_param())


def window_params(as_of: datetime) -> dict[str, datetime]:
    """Bind values for every window's lower bound (and as_of itself)."""
    as_of = ensure_utc(as_of)
    return {"as_of": as_of, **{f"lower_{w.name}": w.lower_bound(as_of) for w in WINDOWS}}


def upto(column: Any, as_of: datetime) -> ColumnElement[bool]:
    """The universal upper bound: ``column <= as_of``."""
    return column <= ensure_utc(as_of)  # type: ignore[no-any-return]


def count_if(condition: ColumnElement[bool]) -> Any:
    """Portable conditional count (``SUM(CASE WHEN cond THEN 1 ELSE 0 END)``)."""
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def elapsed_days(earlier: datetime, later: datetime) -> float:
    return (ensure_utc(later) - ensure_utc(earlier)).total_seconds() / 86400.0


def elapsed_hours(earlier: datetime, later: datetime) -> float:
    return (ensure_utc(later) - ensure_utc(earlier)).total_seconds() / 3600.0


def elapsed_minutes(earlier: datetime, later: datetime) -> float:
    return (ensure_utc(later) - ensure_utc(earlier)).total_seconds() / 60.0
