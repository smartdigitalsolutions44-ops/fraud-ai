"""Structured decision logs and in-process metrics for the scoring service.

**Logs.** Each decision is logged as one JSON object on the ``fraud_ai.realtime`` logger
(which also passes through the global redaction filter). A log line carries:

* the event *pseudonym*;
* the policy version, decision, risk level and reason codes;
* the per-stage latencies;
* whether a fallback was used, and the error category.

It never carries raw identifiers, card data, passwords, tokens, addresses or payloads.

**Metrics.** Thread-safe counters and bounded latency reservoirs, which report p50, p95 and
p99 per stage.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections import Counter, deque
from typing import Any

import numpy as np

from fraud_ai.utils.logging import get_logger

log = get_logger("fraud_ai.realtime")
RESERVOIR = 10_000
#: Keys a decision log line may contain; anything else is dropped.
LOG_FIELDS = frozenset(
    {
        "event",
        "event_ref",
        "event_type",
        "status",
        "policy_version",
        "decision",
        "risk_level",
        "reason_codes",
        "latency_ms",
        "fallback_used",
        "error_category",
        "assessment_version",
        "duplicate",
        "lateness_seconds",
    }
)


def event_ref(event_id: uuid.UUID | str) -> str:
    """One-way pseudonym for logs (never the raw event id)."""
    return "rt-" + hashlib.sha256(f"fraud-ai-realtime:{event_id}".encode()).hexdigest()[:16]


def log_decision(**fields: Any) -> str:
    record = {k: v for k, v in fields.items() if k in LOG_FIELDS and v is not None}
    line = json.dumps(record, sort_keys=True, default=str)
    log.info(line)
    return line


def percentiles(values: list[float] | deque[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None, "count": 0}
    arr = np.asarray(list(values), dtype=np.float64)
    p50, p95, p99 = np.percentile(arr, [50, 95, 99])
    return {
        "p50": round(float(p50), 3),
        "p95": round(float(p95), 3),
        "p99": round(float(p99), 3),
        "count": len(arr),
    }


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: Counter[str] = Counter()
        self.decisions: Counter[str] = Counter()
        self.fallbacks: Counter[str] = Counter()
        self.latencies: dict[str, deque[float]] = {}

    def record(
        self,
        *,
        status: str,
        decision: str | None,
        failures: list[str],
        latency_ms: dict[str, float],
        shadow_disagreements: int = 0,
        shadow_comparisons: int = 0,
    ) -> None:
        with self._lock:
            self.counters[f"events_{status}"] += 1
            self.counters["events_processed"] += 1
            if failures:
                self.counters["events_with_failures"] += 1
            if decision:
                self.decisions[decision] += 1
            for failure in failures:
                self.fallbacks[failure] += 1
            self.counters["shadow_comparisons"] += shadow_comparisons
            self.counters["shadow_disagreements"] += shadow_disagreements
            for stage, ms in latency_ms.items():
                self.latencies.setdefault(stage, deque(maxlen=RESERVOIR)).append(ms)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            comparisons = self.counters["shadow_comparisons"]
            return {
                "counters": dict(self.counters),
                "decisions": dict(self.decisions),
                "fallbacks": dict(self.fallbacks),
                "shadow_disagreement_rate": (
                    self.counters["shadow_disagreements"] / comparisons if comparisons else None
                ),
                "latency_ms": {k: percentiles(v) for k, v in sorted(self.latencies.items())},
            }
