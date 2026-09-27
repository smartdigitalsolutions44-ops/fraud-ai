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

    def render(self) -> bytes:
        return generate_latest(self.registry)
