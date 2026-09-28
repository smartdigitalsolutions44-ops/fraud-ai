"""Redis-backed shared state for multi-process / multi-instance deployments.

Every operation is atomic on the Redis server:

* **Token bucket:** one Lua script reads, refills, spends and writes the bucket. It uses
  the Redis server clock (``TIME``), so workers with skewed clocks still agree. An idle
  bucket expires once it would have refilled completely.
* **Claims** (replay tokens): ``SET key 1 NX PX ttl``. Exactly one caller wins within the
  TTL.
* **Locks:** ``SET key token NX PX ttl``, released by a compare-and-delete script, so a
  lock that expired and was taken by someone else is never released by the old owner.

Connection or command errors raise :class:`StateUnavailableError`; the service then fails
closed (503). Keys carry a configurable prefix; values never contain secrets. Replay
claims store a SHA-256 of the signature, not the signature.
"""

from __future__ import annotations

import contextlib
import secrets
import time
from typing import Any

from fraud_ai.state.base import RateDecision, StateUnavailableError, idle_ttl, retry_after

_BUCKET_SCRIPT = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local ttl_ms = tonumber(ARGV[3])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + elapsed * rate)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', key, ttl_ms)
return {allowed, tostring(tokens)}
"""

_RELEASE = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""


class RedisState:
    name = "redis"
    distributed = True

    def __init__(
        self,
        url: str,
        *,
        prefix: str = "fraud-ai:",
        timeout: float = 0.5,
        client: Any = None,
        observe: Any = None,
    ) -> None:
        import redis

        self._redis_errors: tuple[type[BaseException], ...] = (redis.RedisError, OSError)
        self._client = client or redis.Redis.from_url(
            url,
            socket_timeout=timeout,
            socket_connect_timeout=timeout,
            health_check_interval=30,
        )
        self._prefix = prefix
        self._bucket = self._client.register_script(_BUCKET_SCRIPT)
        self._release = self._client.register_script(_RELEASE)
        self._observe = observe  # callable(op, seconds, ok) for metrics

    def _k(self, key: str) -> str:
        return self._prefix + key

    def _call(self, op: str, fn: Any) -> Any:
        started = time.perf_counter()
        try:
            result = fn()
        except self._redis_errors as exc:
            if self._observe:
                self._observe(op, time.perf_counter() - started, False)
            raise StateUnavailableError(f"redis {op} failed: {type(exc).__name__}") from None
        if self._observe:
            self._observe(op, time.perf_counter() - started, True)
        return result

    def token_bucket(self, key: str, *, rate: float, capacity: float) -> RateDecision:
        ttl_ms = int(idle_ttl(rate, capacity) * 1000)
        allowed, tokens = self._call(
            "token_bucket",
            lambda: self._bucket(keys=[self._k("rl:" + key)], args=[rate, capacity, ttl_ms]),
        )
        left = float(tokens)
        if int(allowed) == 1:
            return RateDecision(True, 0, int(left))
        return RateDecision(False, retry_after(left, rate), 0)

    def claim(self, key: str, ttl_seconds: float) -> bool:
        ttl_ms = max(1, int(ttl_seconds * 1000))
        result = self._call(
            "claim", lambda: self._client.set(self._k("claim:" + key), b"1", nx=True, px=ttl_ms)
        )
        return bool(result)

    def acquire_lock(self, key: str, ttl_seconds: float) -> str | None:
        token = secrets.token_hex(16)
        ttl_ms = max(1, int(ttl_seconds * 1000))
        ok = self._call(
            "lock", lambda: self._client.set(self._k("lock:" + key), token, nx=True, px=ttl_ms)
        )
        return token if ok else None

    def release_lock(self, key: str, token: str) -> bool:
        result = self._call(
            "unlock", lambda: self._release(keys=[self._k("lock:" + key)], args=[token])
        )
        return bool(int(result))

    def ping(self) -> float:
        started = time.perf_counter()
        self._call("ping", self._client.ping)
        return time.perf_counter() - started

    def close(self) -> None:
        with contextlib.suppress(*self._redis_errors):
            self._client.close()
