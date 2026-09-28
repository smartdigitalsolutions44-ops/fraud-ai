"""The shared-state interface.

Implementations:

* :class:`fraud_ai.state.memory.MemoryState`: one process only (tests, local
  development). Rate limits and claims are *not* shared between uvicorn workers.
* :class:`fraud_ai.state.redis.RedisState`: every process that points at the same
  Redis shares one view. Each operation is a single atomic Redis command or Lua script.

Every operation either answers or raises :class:`StateUnavailableError`. Callers fail
closed on that error: a request is refused with 503, never let through unchecked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fraud_ai.core.exceptions import FraudAIError


class StateUnavailableError(FraudAIError):
    """The shared-state backend did not answer (callers must fail closed)."""


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: int  # seconds; 0 when allowed
    remaining: int


class SharedState(Protocol):
    name: str
    distributed: bool

    def token_bucket(self, key: str, *, rate: float, capacity: float) -> RateDecision:
        """Take one token from ``key`` (refill ``rate``/s, at most ``capacity``)."""
        ...

    def claim(self, key: str, ttl_seconds: float) -> bool:
        """Atomically mark ``key`` as used. True only for the first caller within the TTL."""
        ...

    def acquire_lock(self, key: str, ttl_seconds: float) -> str | None:
        """A short-lived lock; returns its owner token, or None if someone holds it."""
        ...

    def release_lock(self, key: str, token: str) -> bool:
        """Release only if still owned by ``token`` (compare-and-delete)."""
        ...

    def ping(self) -> float:
        """Round-trip latency in seconds."""
        ...

    def close(self) -> None: ...


def retry_after(tokens: float, rate: float) -> int:
    import math

    if rate <= 0:
        return 3600
    return max(1, math.ceil((1.0 - tokens) / rate))


def idle_ttl(rate: float, capacity: float) -> float:
    """How long an untouched bucket must be kept: the time to refill it completely."""
    return (capacity / rate if rate > 0 else 3600.0) + 1.0
