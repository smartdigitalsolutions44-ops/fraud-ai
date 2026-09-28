"""In-process shared state: correct for one process, NOT shared between workers."""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable

from fraud_ai.state.base import RateDecision, idle_ttl, retry_after


class MemoryState:
    name = "memory"
    distributed = False
    MAX_KEYS = 200_000

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float, float]] = {}  # tokens, updated, expires
        self._claims: dict[str, float] = {}  # key -> expires
        self._locks: dict[str, tuple[str, float]] = {}  # key -> (token, expires)

    def _expire(self, now: float) -> None:
        if len(self._buckets) + len(self._claims) + len(self._locks) < self.MAX_KEYS:
            return
        self._buckets = {k: v for k, v in self._buckets.items() if v[2] > now}
        self._claims = {k: v for k, v in self._claims.items() if v > now}
        self._locks = {k: v for k, v in self._locks.items() if v[1] > now}

    def token_bucket(self, key: str, *, rate: float, capacity: float) -> RateDecision:
        now = self._clock()
        with self._lock:
            self._expire(now)
            tokens, updated, expires = self._buckets.get(key, (capacity, now, 0.0))
            if expires and expires <= now:
                tokens, updated = capacity, now
            tokens = min(capacity, tokens + max(0.0, now - updated) * rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[key] = (tokens, now, now + idle_ttl(rate, capacity))
        if allowed:
            return RateDecision(True, 0, int(tokens))
        return RateDecision(False, retry_after(tokens, rate), 0)

    def claim(self, key: str, ttl_seconds: float) -> bool:
        now = self._clock()
        with self._lock:
            self._expire(now)
            expires = self._claims.get(key)
            if expires is not None and expires > now:
                return False
            self._claims[key] = now + max(ttl_seconds, 0.001)
            return True

    def acquire_lock(self, key: str, ttl_seconds: float) -> str | None:
        now = self._clock()
        with self._lock:
            held = self._locks.get(key)
            if held is not None and held[1] > now:
                return None
            token = secrets.token_hex(16)
            self._locks[key] = (token, now + ttl_seconds)
            return token

    def release_lock(self, key: str, token: str) -> bool:
        with self._lock:
            held = self._locks.get(key)
            if held is None or held[0] != token:
                return False
            del self._locks[key]
            return True

    def ping(self) -> float:
        return 0.0

    def close(self) -> None:
        return None
