"""Rate limiting per API key and route group (never per client IP as an identity).

:class:`RateLimiter` is the interface. :class:`InMemoryRateLimiter` is a thread-safe token
bucket for a single process. A multi-instance deployment would supply a shared
implementation, for example Redis ``INCR``/Lua over the same interface. Nothing else in
the service changes.

A bucket holds ``burst`` tokens and refills at ``count / period`` tokens per second. For
example, ``RATE_LIMIT=120/minute`` with ``RATE_LIMIT_BURST=30`` gives a sustained 2
requests per second with bursts of up to 30.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: int  # seconds; 0 when allowed
    remaining: int


class RateLimiter(Protocol):
    def hit(self, bucket: str) -> RateDecision: ...


class InMemoryRateLimiter:
    MAX_BUCKETS = 100_000

    def __init__(
        self,
        count: int,
        period: float,
        burst: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = count / period
        self.capacity = float(max(1, burst))
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # bucket -> (tokens, updated)

    def hit(self, bucket: str) -> RateDecision:
        now = self._clock()
        with self._lock:
            tokens, updated = self._buckets.get(bucket, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - updated) * self.rate)
            if tokens >= 1.0:
                tokens -= 1.0
                self._store(bucket, tokens, now)
                return RateDecision(True, 0, int(tokens))
            self._store(bucket, tokens, now)
            wait = math.ceil((1.0 - tokens) / self.rate) if self.rate > 0 else 3600
            return RateDecision(False, max(1, wait), 0)

    def _store(self, bucket: str, tokens: float, now: float) -> None:
        if len(self._buckets) >= self.MAX_BUCKETS and bucket not in self._buckets:
            # Drop full (idle) buckets first; they carry no state worth keeping.
            full = [k for k, (t, _) in self._buckets.items() if t >= self.capacity]
            for key in full or list(self._buckets)[: max(1, self.MAX_BUCKETS // 10)]:
                del self._buckets[key]
        self._buckets[bucket] = (tokens, now)
