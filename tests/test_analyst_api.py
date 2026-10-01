"""Stage 13 read-only analyst views (``/v1/analyst``) for the Sentinel console.

They read stored records only: nothing is scored, decided or changed by calling them.
They need their own ``analyst:read`` scope, and they never return personal data, keyed
hashes, credentials or signing material."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from fraud_ai.database.models import AuditEvent, RiskAssessment
from fraud_ai.service.analyst import INDICATORS, reason_catalogue
from tests.realtime_world import World, open_world
from tests.service_helpers import Harness, make_harness

NEVER = {
    "external_ref",
    "email",
    "phone",
    "ip_address",
    "ip_hash",
    "address_hash",
    "device_hash",
    "fingerprint_hash",
    "token_reference",
    "token_ref_hash",
    "provider_reference",
    "credential_ref",
    "public_key",
    "secret",
    "signature",
    "evidence_packet",
    "prompt",
}


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


@pytest.fixture
def h(w: World) -> Iterator[Harness]:
    harness = make_harness(w.url, engine=w.engine, local_llm_runtime="reference")
    try:
        yield harness
    finally:
        harness.container.close()


def _keys(body: Any) -> set[str]:
    if isinstance(body, dict):
        return set(body) | {k for v in body.values() for k in _keys(v)}
    if isinstance(body, list):
        return {k for v in body for k in _keys(v)}
    return set()


def _counts(w: World) -> tuple[int, int]:
    with w.session() as s:
        return (
            s.scalar(select(func.count()).select_from(RiskAssessment)) or 0,
            s.scalar(select(func.count()).select_from(AuditEvent)) or 0,
        )


def test_analyst_views_need_their_own_scope(h: Harness) -> None:
    without = h.key("assessment:read", "review:read", "metrics:read")
    for path in ("/v1/analyst/feed", "/v1/analyst/reviews", "/v1/analyst/summary",
                 "/v1/analyst/system", f"/v1/analyst/cases/{uuid.uuid4()}"):  # fmt: skip
        r = h.get(path, without)
        assert r.status_code == 403 and r.json()["error"]["code"] == "INSUFFICIENT_SCOPE", path
        assert h.get(path, None).status_code == 401


def test_feed_queue_case_summary_system_search(w: World, h: Harness) -> None:
    cred = h.key()
    review_body, _ = h.drive(cred, w.events, "MANUAL_REVIEW")
    aid = review_body["assessment_id"]
    reader = h.key("analyst:read")
    before = _counts(w)

    feed = h.get("/v1/analyst/feed?limit=20", reader)
    assert feed.status_code == 200, feed.text
    items = feed.json()["items"]
    assert items and any(i["assessment_id"] == aid for i in items)
    mine = next(i for i in items if i["assessment_id"] == aid)
    assert mine["decision"] == "MANUAL_REVIEW" and mine["review"]["status"] == "open"
    assert mine["event_type"] and mine["policy_version"]
    newest = items[0]["assessed_at"]
    assert h.get(f"/v1/analyst/feed?since={newest}", reader).json()["items"] == []
    only = h.get("/v1/analyst/feed?decision=MANUAL_REVIEW", reader).json()["items"]
    assert only and {i["decision"] for i in only} == {"MANUAL_REVIEW"}

    queue = h.get("/v1/analyst/reviews?status=open", reader).json()["items"]
    row = next(q for q in queue if q["assessment_id"] == aid)
    assert row["decision"] == "MANUAL_REVIEW" and row["authentication"]["attempts"] == 0

    case = h.get(f"/v1/analyst/cases/{aid}", reader)
    assert case.status_code == 200, case.text
    c = case.json()
    assert c["assessment"]["assessment_id"] == aid
    assert c["review"]["review_id"] == row["review_id"] and c["review"]["outcomes"] == []
    assert c["reasons"] and all(r["code"] for r in c["reasons"])
    assert all(r["description"] for r in c["reasons"])  # every code is described by the backend
    entries = c["models"]["entries"]
    assert entries[0]["role"] == "primary" and entries[0]["raw_score"] is not None
    assert c["models"]["rated"] >= 1 and "not certainty" in c["models"]["note"]
    assert "consensus" not in _keys(c["models"])
    rules = c["rules"]
    assert rules and all(r["rule_id"] and r["description"] for r in rules)
    names = {i["name"] for i in c["indicators"]}
    assert names and names <= {n for n, _, _ in INDICATORS}
    timeline = c["timeline"]
    assert sum(1 for t in timeline if t["is_case_event"]) == 1
    assert [t["occurred_at"] for t in timeline] == sorted(t["occurred_at"] for t in timeline)
    kinds = {a["kind"] for a in c["activity"]}
    assert {"assessment.created", "review.created"} <= kinds
    assert c["investigation"] is None
    assert _keys(c).isdisjoint(NEVER), _keys(c) & NEVER

    # An investigation (reference runtime) shows up with its cited evidence and limitations.
    inv = h.post(f"/v1/assessments/{aid}/investigate", cred, {})
    assert inv.status_code == 200, inv.text
    c2 = h.get(f"/v1/analyst/cases/{aid}", reader).json()
    investigation = c2["investigation"]
    assert investigation["runtime"] == "reference" and investigation["explanation"]["summary"]
    cited = {e for f in [investigation["explanation"]["summary"]] for e in f["evidence_ids"]}
    assert {e["id"] for e in investigation["evidence"]} >= {x for x in cited if x.startswith("E")}
    assert investigation["limitations"] and "never scores" in investigation["note"]
    assert "investigation.generated" in {a["kind"] for a in c2["activity"]}

    # Resolution appears with the reviewer, and the outcome view carries it too.
    resolved = h.post(
        f"/v1/reviews/{row['review_id']}/resolve", cred, {"resolution": "fraud", "note": "demo"}
    )
    assert resolved.status_code == 200
    assert resolved.json()["outcomes"][0]["reviewer"].startswith("api_key:")
    c3 = h.get(f"/v1/analyst/cases/{aid}", reader).json()
    assert c3["review"]["status"] == "resolved"
    assert c3["review"]["outcomes"][0]["resolution"] == "fraud"
    assert "review.resolved" in {a["kind"] for a in c3["activity"]}

    summary = h.get("/v1/analyst/summary", reader).json()
    assert summary["assessments"]["total"] >= 1
    assert summary["assessments"]["by_decision"].get("MANUAL_REVIEW", 0) >= 1
    assert summary["latency_ms"]["samples"] >= 1 and summary["latency_ms"]["p50"] is not None
    assert summary["series"] and h.get("/v1/analyst/summary?hours=1", reader).status_code == 200
    assert h.get("/v1/analyst/summary?hours=0", reader).status_code == 422

    system = h.get("/v1/analyst/system", reader)
    assert system.status_code == 200, system.text
    sysj = system.json()
    assert sysj["policy"]["policy_version"] and sysj["policy"]["bands"]
    primary = next(m for m in sysj["models"] if m["role"] == "primary")
    assert primary["registered"] and "artifact_sha256" in primary
    assert sysj["migrations"]["up_to_date"] is True
    assert sysj["audit"]["chain"]["verified"] is True
    assert sysj["llm"]["runtime"] == "reference" and sysj["llm"]["reference_template"] is True
    assert sysj["reason_catalogue"] == reason_catalogue()
    assert _keys(sysj).isdisjoint(NEVER - {"signature"})
    assert "private" not in str(sysj).lower()

    found = h.get(f"/v1/analyst/search?q={aid}", reader).json()["matches"]
    assert any(m["kind"] == "assessment" and m["assessment_id"] == aid for m in found)
    by_prefix = h.get(f"/v1/analyst/search?q={aid.replace('-', '')[:10]}", reader).json()
    assert any(m["assessment_id"] == aid for m in by_prefix["matches"])
    by_review = h.get(f"/v1/analyst/search?q={row['review_id']}", reader).json()["matches"]
    assert any(m["kind"] == "review" for m in by_review)
    assert h.get("/v1/analyst/search?q=abc", reader).status_code == 422  # too short
    assert h.get("/v1/analyst/search?q=not-hex-xyzxyz", reader).status_code == 422

    # Reads changed nothing (the investigation and resolution above are the writes).
    assessments_after, _ = _counts(w)
    assert assessments_after == before[0]


def test_case_not_found_and_reads_do_not_write(w: World, h: Harness) -> None:
    reader = h.key("analyst:read")
    before = _counts(w)
    missing = h.get(f"/v1/analyst/cases/{uuid.uuid4()}", reader)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "NOT_FOUND"
    for path in ("/v1/analyst/feed", "/v1/analyst/reviews?status=all", "/v1/analyst/summary",
                 "/v1/analyst/system"):  # fmt: skip
        assert h.get(path, reader).status_code == 200, path
    assert _counts(w) == before


def test_reason_catalogue_describes_rule_and_engine_codes() -> None:
    from fraud_ai.rules.ruleset import get_rule_set
    from fraud_ai.service.analyst import describe_reason

    catalogue = reason_catalogue()
    for rule in get_rule_set().rules:
        assert catalogue[rule.reason_code] == rule.description
    assert "fallback" in (describe_reason("FALLBACK_DATABASE_UNAVAILABLE", catalogue) or "")
    assert describe_reason("SOMETHING_UNKNOWN", catalogue) is None  # never invented
