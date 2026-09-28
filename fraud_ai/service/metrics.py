"""Prometheus metrics for the service, in their own registry (one per app instance).

Labels are low-cardinality by construction:

* route *templates* (``/v1/assessments/{assessment_id}``), never concrete paths;
* HTTP methods and status codes;
* decisions, results and error codes from closed enums.

Labels never carry an event id, user id, assessment id, key id or IP address.
"""

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    disable_created_metrics,
    generate_latest,
)

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
disable_created_metrics()  # type: ignore[no-untyped-call]  # *_created series are noise
_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class ServiceMetrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        r = self.registry
        self.requests = Counter(
            "fraud_api_requests",
            "HTTP requests by route template, method and status code.",
            ["route", "method", "status"],
            registry=r,
        )
        self.latency = Histogram(
            "fraud_api_request_duration_seconds",
            "Request latency by route template.",
            ["route", "method"],
            buckets=_BUCKETS,
            registry=r,
        )
        self.decisions = Counter(
            "fraud_api_decisions", "Scoring decisions returned.", ["decision"], registry=r
        )
        self.auth_failures = Counter(
            "fraud_api_auth_failures", "Rejected authentication attempts.", ["reason"], registry=r
        )
        self.rate_limited = Counter(
            "fraud_api_rate_limited", "Requests refused by the rate limiter.", ["route"], registry=r
        )
        self.idempotent_replays = Counter(
            "fraud_api_idempotent_replays",
            "Responses served from the idempotency store.",
            registry=r,
        )
        self.stepup = Counter(
            "fraud_api_stepup_results",
            "Recorded step-up attempts.",
            ["method", "result"],
            registry=r,
        )
        self.investigations = Counter(
            "fraud_api_investigations",
            "Analyst-triggered LLM investigations.",
            ["outcome"],
            registry=r,
        )
        self.review_queue = Gauge(
            "fraud_api_review_queue",
            "Review items by status (at scrape time).",
            ["status"],
            registry=r,
        )

        self.signature_failures = Counter(
            "fraud_api_signature_failures",
            "Rejected request signatures by reason.",
            ["code"],
            registry=r,
        )
        self.signatures_verified = Counter(
            "fraud_api_signatures_verified",
            "Accepted request signatures by signing-key version.",
            ["key_version"],
            registry=r,
        )
        self.state_unavailable = Counter(
            "fraud_api_state_unavailable",
            "Requests refused because shared state was unavailable (fail closed).",
            ["what"],
            registry=r,
        )
        self.state_latency = Histogram(
            "fraud_state_operation_seconds",
            "Shared-state (Redis) operation latency.",
            ["op"],
            buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5),
            registry=r,
        )
        self.state_errors = Counter(
            "fraud_state_errors", "Shared-state (Redis) operation errors.", ["op"], registry=r
        )

        self.db_ping = Histogram(
            "fraud_db_ping_seconds",
            "Database round trip measured by readiness probes.",
            buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0),
            registry=r,
        )
        self.model_verification_seconds = Histogram(
            "fraud_model_verification_seconds",
            "Full SHA-256 re-verification time of the primary artefact.",
            buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
            registry=r,
        )
        self.model_verification_failures = Counter(
            "fraud_model_verification_failures",
            "Primary artefact verification failures (missing, changed or corrupted).",
            registry=r,
        )

        self.db_query = Histogram(
            "fraud_db_query_seconds",
            "Database statement latency (all statements issued by this process).",
            buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0),
            registry=r,
        )
        self.db_pool_checked_out = Gauge(
            "fraud_db_pool_checked_out",
            "Connections checked out of the pool (at scrape time).",
            registry=r,
        )
        self.fallbacks = Counter(
            "fraud_api_fallbacks",
            "Decisions that used a conservative fallback, by first failure category.",
            ["category"],
            registry=r,
        )
        self.policy_decisions = Counter(
            "fraud_api_policy_decisions",
            "Decisions by policy version (for unexpected decision-rate changes).",
            ["policy_version", "decision"],
            registry=r,
        )
        self.model_loads = Gauge(
            "fraud_model_cache_loads", "Verified model loads in this process.", registry=r
        )
        self.model_load_failures = Gauge(
            "fraud_model_cache_load_failures",
            "Model loads that failed verification in this process.",
            registry=r,
        )

    def observe_state(self, op: str, seconds: float, ok: bool) -> None:
        self.state_latency.labels(op).observe(seconds)
        if not ok:
            self.state_errors.labels(op).inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)
