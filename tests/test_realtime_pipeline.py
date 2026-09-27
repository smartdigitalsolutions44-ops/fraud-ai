"""Stage 8 hot path on a real synthetic world.

Covers:

* end to end, determinism and idempotency;
* arrival-time semantics, late events and decision immutability;
* shadow isolation, the model cache and every explicit failure mode (never a silent
  ALLOW);
* the review queue, the policy registry, simulation and comparison, monitoring,
  structured logging, concurrency and LLM independence.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import threading
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from fraud_ai.core.enums import Decision, ReviewResolution, ReviewStatus
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import (
    EventRecord,
    FeatureSnapshot,
    ModelCalibration,
    ModelPrediction,
    PolicyDeployment,
    ReviewItem,
    ReviewOutcome,
    RiskAssessment,
    RiskPolicyRecord,
)
from fraud_ai.realtime import monitoring
from fraud_ai.realtime import service as service_module
from fraud_ai.realtime.review import ReviewError, get_review, list_reviews, queue_size, resolve
from fraud_ai.realtime.service import FraudScoringService, idempotency_key
from fraud_ai.risk.engine import PolicyInputs, decide
from fraud_ai.risk.offline import OfflinePolicyError, compare_policies, run_policy, simulate
from fraud_ai.risk.policy import RiskPolicyDefinition
from fraud_ai.risk.registry import (
    PolicyError,
    PolicyIntegrityError,
    activate,
    active_deployment,
    create_policy,
    deployment_history,
    list_policies,
    load_policy,
)
from fraud_ai.utils.time import ensure_utc
from tests.realtime_world import GB, GRU, LR, P1, P2, PSEUDO, World, open_world

UNSAFE = {Decision.ALLOW, Decision.ALLOW_WITH_MONITORING}


@pytest.fixture
def world_dir(realtime_world_dir: Path) -> Path:
    return realtime_world_dir


@pytest.fixture
def w(world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(world_dir, tmp_path)


def _count(w: World, model: Any) -> int:
    with w.session() as s:
        return int(s.scalar(select(func.count()).select_from(model)) or 0)


def _first_decision(w: World, **kwargs: Any) -> tuple[FraudScoringService, Any, int]:
    svc = w.service(**kwargs)
    outcomes, nxt = w.replay_until(svc)
    return svc, outcomes[-1], nxt


# ------------------------------------------------------------------ end to end
def test_one_event_is_scored_end_to_end(w: World) -> None:
    svc, outcome, _ = _first_decision(w)
    assert outcome.status == "decided" and outcome.persisted
    assert outcome.decision is not None and outcome.policy_version == P1
    assert outcome.assessment_version == 1 and outcome.calibrated_score is not None
    for stage in (
        "validation",
        "ingestion",
        "policy_load",
        "features",
        "inference_primary",
        "calibration",
        "rules",
        "policy",
        "shadow",
        "persistence",
        "total",
    ):
        assert stage in outcome.latency_ms, stage
    with w.session() as s:
        row = s.scalar(select(RiskAssessment).where(RiskAssessment.event_id == outcome.event_id))
        assert row is not None
        assert row.idempotency_key == idempotency_key(outcome.event_id, P1, 1)
        assert row.primary_model == GB and row.rules_version == "fraud-rules-1.0.0"
        assert row.deployment_id == active_deployment(s).deployment_id  # type: ignore[union-attr]
        assert row.event_time is not None and row.arrival_time is not None
        assert row.model_scores["primary"]["model"] == GB and "sequence" in row.model_scores
        assert {r["rule_id"] for r in row.triggered_rules["results"]} >= {"R001", "R006"}
        assert row.shadow["models"][0]["model"] == LR
        assert row.shadow["policies"][0]["policy_version"] == P2
        assert set(row.latency_ms) >= {"features", "policy", "persistence", "total"}
        assert row.latency_ms["total"] <= outcome.latency_ms["total"]
        refs = {
            f"{p.model_name}-{p.model_version}"
            for p in s.scalars(
                select(ModelPrediction).where(ModelPrediction.event_id == outcome.event_id)
            )
        }
        assert refs == {GB, GRU, LR}  # active + shadow predictions are persisted
        # The stored decision is exactly what the pure policy engine gives for the stored inputs.
        policy = load_policy(s, P1)
        again = decide(
            policy,
            PolicyInputs(
                primary_score=row.calibrated_score,
                rule_results=[_rule(r) for r in row.triggered_rules["results"]],
                secondary_flags={"sequence": row.model_scores["sequence"]["flagged"]},
                lateness_seconds=row.lateness_seconds,
            ),
        )
        assert again.decision is row.decision and list(again.reason_codes) == row.reason_codes
    assert svc.metrics.snapshot()["counters"]["events_decided"] == 1


def _rule(d: dict[str, Any]) -> Any:
    from fraud_ai.core.enums import RuleSeverity
    from fraud_ai.rules.engine import RuleResult

    return RuleResult(
        d["rule_id"],
        d["version"],
        d["matched"],
        d["evaluated"],
        RuleSeverity(d["severity"]),
        d["reason_code"],
        d["evidence"],
    )


def test_decisions_are_deterministic(world_dir: Path, tmp_path: Path) -> None:
    runs = []
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        for w in open_world(world_dir, tmp_path / name):
            outcomes, _ = w.replay_until(w.service(), decisions=8)
            runs.append(
                [(o.decision, o.risk_level, o.reason_codes, o.calibrated_score) for o in outcomes]
            )
    assert runs[0] == runs[1]


def test_repeated_processing_is_idempotent(w: World) -> None:
    svc = w.service()
    outcomes, nxt = w.replay_until(svc, decisions=3)
    tables = (EventRecord, FeatureSnapshot, ModelPrediction, RiskAssessment, ReviewItem)
    before = [_count(w, t) for t in tables]
    again = [svc.score_event(e) for e in w.events[:nxt]]
    assert all(o.status == "duplicate" for o in again)
    assert [_count(w, t) for t in tables] == before
    decided = [o for o in outcomes if o.status == "decided"]
    replayed = [o for o in again if o.decision is not None]
    assert [(o.decision, o.assessment_id) for o in decided] == [
        (o.decision, o.assessment_id) for o in replayed
    ]
    fresh = w.service()  # a new process gives the same answer
    assert fresh.score_event(w.events[nxt - 1]).assessment_id == decided[-1].assessment_id


def test_conflicting_duplicate_is_rejected(w: World) -> None:
    svc, _outcome, nxt = _first_decision(w)
    event = dict(w.events[nxt - 1])
    event["timestamp"] = (
        datetime.fromisoformat(event["timestamp"]) - timedelta(days=1)
    ).isoformat()
    conflict = svc.score_event(event)
    assert conflict.status == "rejected" and conflict.decision is Decision.MANUAL_REVIEW
    assert "conflicting duplicate" in (conflict.error or "")


def test_non_decision_events_are_ingested_only(w: World) -> None:
    svc = w.service()
    login = next(e for e in w.events if e["event_type"] == "LOGIN_SUCCESS")
    idx = w.events.index(login)
    for e in w.events[:idx]:
        svc.score_event(e)
    outcome = svc.score_event(login)
    assert outcome.status == "ingested" and outcome.decision is None
    assert outcome.reason_codes == ["NOT_A_DECISION_POINT"]  # policy decides on transactions
    with w.session() as s:
        assert s.get(EventRecord, uuid.UUID(login["event_id"])) is not None
        assert (
            s.scalar(
                select(func.count())
                .select_from(RiskAssessment)
                .where(RiskAssessment.event_id == uuid.UUID(login["event_id"]))
            )
            == 0
        )
    assert svc.score_event(login).status == "duplicate"


def test_malformed_and_unprocessable_events_never_allow(w: World) -> None:
    svc = w.service(replay=False)
    bad = svc.score_event({"event_type": "TRANSACTION_CREATED"})
    assert bad.status == "rejected" and bad.decision is Decision.MANUAL_REVIEW and not bad.persisted
    live = dict(w.transactions()[0])
    rejected = svc.score_event(live)  # live scoring refuses a client arrival_time
    assert rejected.status == "rejected" and "arrival_time" in (rejected.error or "")
    unknown_user = {k: v for k, v in live.items() if k != "arrival_time"}
    unknown_user["user_id"] = str(uuid.uuid4())
    unknown_user["event_id"] = str(uuid.uuid4())
    orphan = svc.score_event(unknown_user)
    assert orphan.status == "rejected" and orphan.decision is Decision.MANUAL_REVIEW
    assert _count(w, RiskAssessment) == 0
    snap = svc.metrics.snapshot()
    assert snap["counters"]["events_rejected"] == 3 and snap["fallbacks"]["event_rejected"] == 3


def test_future_events_are_refused(w: World) -> None:
    svc = w.service()
    event = dict(w.transactions()[0])
    event["arrival_time"] = (
        datetime.fromisoformat(event["timestamp"]) - timedelta(hours=2)
    ).isoformat()
    outcome = svc.score_event(event)
    assert outcome.status == "rejected" and "future" in (outcome.error or "")


# ------------------------------------------------------------------ arrival time
def _prefix_before(w: World, svc: FraudScoringService, target: dict[str, Any]) -> None:
    for e in w.events[: w.events.index(target)]:
        svc.score_event(e)


def test_late_event_is_flagged_and_recorded(w: World) -> None:
    svc = w.service()
    target = w.transactions()[0]
    _prefix_before(w, svc, target)
    late = dict(target)
    late["arrival_time"] = (
        datetime.fromisoformat(target["timestamp"]) + timedelta(hours=2)
    ).isoformat()
    outcome = svc.score_event(late)
    assert outcome.status == "decided" and "LATE_EVENT" in outcome.reason_codes
    assert outcome.decision is not None and outcome.decision.severity >= 1
    assert outcome.lateness_seconds == pytest.approx(7200)
    with w.session() as s:
        row = s.get(RiskAssessment, outcome.assessment_id)
        assert row is not None and ensure_utc(row.arrival_time) - ensure_utc(row.event_time) == (
            timedelta(hours=2)
        )
        record = s.get(EventRecord, outcome.event_id)
        assert record is not None and record.arrival_time is not None


def test_late_event_cannot_rewrite_an_issued_decision(w: World) -> None:
    svc, first, nxt = _first_decision(w)
    with w.session() as s:
        before = s.get(RiskAssessment, first.assessment_id)
        assert before is not None
        snapshot = {c.key: getattr(before, c.key) for c in RiskAssessment.__table__.columns}
        user_id = before.user_id
        event_time = ensure_utc(before.event_time)
    # A login for the same user, one hour BEFORE the decided event, arrives now.
    template = next(e for e in w.events if e["event_type"] == "LOGIN_SUCCESS")
    late = dict(template)
    late.update(
        event_id=str(uuid.uuid4()),
        user_id=str(user_id),
        timestamp=(event_time - timedelta(hours=1)).isoformat(),
        arrival_time=(event_time + timedelta(hours=3)).isoformat(),
    )
    assert svc.score_event(late).status == "ingested"
    with w.session() as s:
        after = s.get(RiskAssessment, first.assessment_id)
        assert {c.key: getattr(after, c.key) for c in RiskAssessment.__table__.columns} == snapshot
        # New evidence -> a NEW version; the original is preserved.
    new = svc.reassess(first.event_id)
    assert new.assessment_version == 2 and new.status == "decided"
    with w.session() as s:
        rows = list(
            s.scalars(
                select(RiskAssessment)
                .where(RiskAssessment.event_id == first.event_id)
                .order_by(RiskAssessment.assessment_version)
            )
        )
        assert [r.assessment_version for r in rows] == [1, 2]
        assert rows[1].supersedes_assessment_id == rows[0].assessment_id
        assert rows[1].mode == "reassessment" and "LATE_EVENT" not in rows[1].reason_codes
        assert {
            c.key: getattr(rows[0], c.key) for c in RiskAssessment.__table__.columns
        } == snapshot
    assert svc.score_event(w.events[nxt - 1]).assessment_version == 2  # latest is returned


def test_reassess_needs_an_existing_assessment(w: World) -> None:
    svc = w.service()
    with pytest.raises(FraudAIError, match="unknown event"):
        svc.reassess(uuid.uuid4())
    with w.session() as s:
        event_id = s.scalar(select(EventRecord.event_id).limit(1))
    with pytest.raises(FraudAIError, match="no assessment"):
        svc.reassess(event_id)  # type: ignore[arg-type]


def test_out_of_arrival_order_decision_is_refused(w: World) -> None:
    """Only information available by arrival time may influence a decision."""
    svc = w.service()
    target = w.transactions()[0]
    _prefix_before(w, svc, target)
    event_time = datetime.fromisoformat(target["timestamp"])
    template = next(e for e in w.events if e["event_type"] == "LOGIN_SUCCESS")
    later = dict(template)
    later.update(
        event_id=str(uuid.uuid4()),
        user_id=target["user_id"],
        timestamp=(event_time - timedelta(minutes=30)).isoformat(),
        arrival_time=(event_time + timedelta(hours=5)).isoformat(),
    )
    svc.score_event(later)  # stored with an arrival AFTER the target's arrival
    outcome = svc.score_event(target)
    assert outcome.decision is Decision.MANUAL_REVIEW
    assert "FALLBACK_INFORMATION_CUTOFF_VIOLATED" in outcome.reason_codes
    assert outcome.review_id is not None


# ------------------------------------------------------------------ shadow isolation
def test_shadow_models_and_policies_never_change_decisions(world_dir: Path, tmp_path: Path) -> None:
    results = {}
    for name, shadows in (("with", True), ("without", False), ("broken", True)):
        (tmp_path / name).mkdir()
        for w in open_world(world_dir, tmp_path / name):
            if not shadows:
                with session_scope(w.factory) as s:
                    activate(s, P1)  # same policy, no shadows
            if name == "broken":
                for f in (w.root / "models" / LR).iterdir():
                    if f.is_file() and f.suffix not in (".json",):
                        f.write_bytes(b"corrupted")
            outcomes, _ = w.replay_until(w.service(), decisions=6)
            decided = [o for o in outcomes if o.status == "decided"]
            results[name] = [(o.decision, o.reason_codes, o.calibrated_score) for o in decided]
            if name == "with":
                assert all(o.shadow["models"][0].get("agrees") is not None for o in decided)
            if name == "broken":
                assert all("error" in o.shadow["models"][0] for o in decided)
            if name == "without":
                assert all(o.shadow == {} for o in decided)
    assert results["with"] == results["without"] == results["broken"]


# ------------------------------------------------------------------ model cache
def test_models_are_cached_and_invalidated_on_deployment_change(w: World) -> None:
    svc = w.service()
    w.replay_until(svc, decisions=5)
    stats = svc.cache.stats.to_dict()
    assert stats["loads"] == 3 and stats["hits"] >= 12 and stats["invalidations"] == 0
    with session_scope(w.factory) as s:
        activate(s, P1)
    _outcomes, _ = w.replay_until(svc, decisions=6)
    assert svc.cache.stats.invalidations == 1
    assert svc.cache.stats.loads == 3 + 2  # GB and GRU reloaded; no shadow any more


# ------------------------------------------------------------------ explicit failures
def _decide_first(w: World) -> Any:
    _, outcome, _ = _first_decision(w)
    assert outcome.status == "decided"
    assert outcome.decision not in UNSAFE, outcome
    return outcome


def _categories(outcome: Any) -> set[str]:
    return {f["category"] for f in outcome.failures}


def test_feature_extraction_failure(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("history query failed")

    monkeypatch.setattr(service_module, "point_in_time_snapshot", boom)
    outcome = _decide_first(w)
    assert outcome.decision is Decision.MANUAL_REVIEW and outcome.risk_level == "unknown"
    assert _categories(outcome) == {"feature_extraction_failed"} and outcome.review_id is not None


def test_sequence_extraction_failure(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("sequence query failed")

    monkeypatch.setattr(service_module, "build_sequence", boom)
    outcome = _decide_first(w)
    assert "sequence_extraction_failed" in _categories(outcome)
    assert outcome.calibrated_score is not None  # the primary still scored


def test_corrupt_primary_artifact(w: World) -> None:
    for f in (w.root / "models" / GB).iterdir():
        if f.is_file() and f.suffix != ".json":
            f.write_bytes(b"not a model")
    outcome = _decide_first(w)
    assert outcome.decision is Decision.MANUAL_REVIEW
    assert "primary_artifact_invalid" in _categories(outcome)


def test_missing_primary_model(w: World) -> None:
    shutil.rmtree(w.root / "models" / GB)
    outcome = _decide_first(w)
    assert outcome.decision is Decision.MANUAL_REVIEW
    assert _categories(outcome) & {"primary_model_unavailable", "primary_artifact_invalid"}


def test_corrupt_optional_sequence_model(w: World) -> None:
    for f in (w.root / "models" / GRU).iterdir():
        if f.is_file() and f.suffix != ".json":
            f.write_bytes(b"not a model")
    outcome = _decide_first(w)
    assert "sequence_model_failed" in _categories(outcome)
    assert outcome.decision.severity >= Decision.STEP_UP_AUTHENTICATION.severity


def test_invalid_calibration(w: World) -> None:
    with session_scope(w.factory) as s:
        for row in s.scalars(select(ModelCalibration)):
            row.parameters = {"a": 99.0, "b": 1.0}
    outcome = _decide_first(w)
    assert outcome.decision is Decision.MANUAL_REVIEW
    assert "calibration_unavailable" in _categories(outcome)


def test_no_active_policy(w: World) -> None:
    w.sql("DELETE FROM policy_deployments")
    outcome = _decide_first(w)
    assert outcome.decision is Decision.MANUAL_REVIEW and outcome.policy_version == "unavailable"
    assert _categories(outcome) == {"policy_unavailable"}


def test_tampered_policy_is_not_used(w: World) -> None:
    with session_scope(w.factory) as s:
        row = s.scalar(select(RiskPolicyRecord).where(RiskPolicyRecord.policy_version == P1))
        assert row is not None
        definition = dict(row.definition)
        definition["late_event_seconds"] = 1.0e9
        row.definition = definition
    outcome = _decide_first(w)
    assert outcome.decision is Decision.MANUAL_REVIEW
    assert _categories(outcome) == {"policy_unavailable"}
    with w.session() as s, pytest.raises(PolicyIntegrityError):
        load_policy(s, P1)


def test_tampered_deployment_is_not_used(w: World) -> None:
    w.sql("UPDATE policy_deployments SET shadow_models = '[]'")
    outcome = _decide_first(w)
    assert _categories(outcome) == {"policy_unavailable"}


def test_rule_engine_failure(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        def evaluate(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("rule bug")

    monkeypatch.setattr(service_module, "get_rule_set", lambda version: Broken())
    outcome = _decide_first(w)
    assert "rules_failed" in _categories(outcome) and outcome.decision is Decision.MANUAL_REVIEW


def test_invalid_model_output(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    original = service_module.FraudScoringService._matrix

    def nan_matrix(self: Any, state: Any, record: Any, model: Any) -> Any:
        matrix = original(self, state, record, model)
        model.predict_proba = lambda m: [float("nan")]
        return matrix

    monkeypatch.setattr(service_module.FraudScoringService, "_matrix", nan_matrix)
    outcome = _decide_first(w)
    assert "primary_model_unavailable" in _categories(outcome)


def test_database_failure_never_allows(world_dir: Path, tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'empty.db'}")  # no schema at all
    svc = FraudScoringService(make_session_factory(engine), PSEUDO, replay=True)
    event = json.loads((world_dir / "live.jsonl").read_text().splitlines()[0])
    outcome = svc.score_event(event)
    assert outcome.status == "not_persisted" and outcome.decision is Decision.MANUAL_REVIEW
    assert outcome.failures[0]["category"] == "database_unavailable" and not outcome.persisted
    engine.dispose()


def test_commit_failure_never_allows(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = w.service()
    target = w.transactions()[0]
    _prefix_before(w, svc, target)
    from sqlalchemy.orm import Session

    def failing_commit(self: Any) -> None:
        raise OperationalError("COMMIT", {}, Exception("disk I/O error"))

    monkeypatch.setattr(Session, "commit", failing_commit)
    outcome = svc.score_event(target)
    assert outcome.status == "not_persisted" and outcome.decision is Decision.MANUAL_REVIEW


# ------------------------------------------------------------------ concurrency
def test_concurrent_duplicates_create_one_assessment(w: World) -> None:
    svc = w.service()
    target = w.transactions()[0]
    _prefix_before(w, svc, target)
    barrier = threading.Barrier(6)
    outcomes: list[Any] = []

    def worker() -> None:
        barrier.wait()
        outcomes.append(svc.score_event(target))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(o.status for o in outcomes).count("decided") == 1
    assert {o.assessment_id for o in outcomes} == {outcomes[0].assessment_id}
    with w.session() as s:
        assert s.scalar(select(func.count()).select_from(RiskAssessment)) == 1


def test_concurrent_distinct_events(w: World) -> None:
    svc = w.service()
    _outcomes, nxt = w.replay_until(svc, decisions=1)
    rest = w.events[nxt : nxt + 40]
    results: list[Any] = []
    lock = threading.Lock()

    def worker(chunk: list[dict[str, Any]]) -> None:
        for e in chunk:
            outcome = svc.score_event(e)
            with lock:
                results.append(outcome)

    # Each user's events stay in order within one thread.
    by_user: dict[str, list[dict[str, Any]]] = {}
    for e in rest:
        by_user.setdefault(str(e.get("user_id")), []).append(e)
    chunks: list[list[dict[str, Any]]] = [[], [], [], []]
    for i, events in enumerate(by_user.values()):
        chunks[i % 4].extend(events)
    threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == len(rest)
    assert not [o for o in results if o.status == "not_persisted"]
    assert svc.cache.stats.loads == 3  # no duplicate loads under concurrency


# ------------------------------------------------------------------ review queue
def test_review_queue_and_resolution(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        service_module,
        "point_in_time_snapshot",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
    )
    outcome = _decide_first(w)
    with session_scope(w.factory) as s:
        items = list_reviews(s)
        assert [i.review_id for i in items] == [outcome.review_id]
        assert items[0].priority == 2 and items[0].status is ReviewStatus.OPEN
        assert queue_size(s) == {"open": 1, "needs_more_information": 0, "resolved": 0}
        with pytest.raises(ReviewError, match="personal data"):
            resolve(s, items[0].review_id, ReviewResolution.FRAUD, note="call +44 7700 900123")
        with pytest.raises(ReviewError, match="500"):
            resolve(s, items[0].review_id, ReviewResolution.FRAUD, note="x" * 501)
        resolve(s, items[0].review_id, ReviewResolution.NEEDS_MORE_INFORMATION, note="check device")
        assert list_reviews(s) == [] and queue_size(s)["needs_more_information"] == 1
        resolve(s, items[0].review_id, ReviewResolution.FRAUD)
        with pytest.raises(ReviewError, match="already resolved"):
            resolve(s, items[0].review_id, ReviewResolution.LEGITIMATE)
        detail = get_review(s, items[0].review_id)
        assert [o.resolution for o in detail.outcomes] == [
            ReviewResolution.NEEDS_MORE_INFORMATION,
            ReviewResolution.FRAUD,
        ]
        assert detail.item.status is ReviewStatus.RESOLVED and detail.item.reviewed_at is not None
        # The original assessment is untouched.
        assert detail.assessment.decision is Decision.MANUAL_REVIEW
        assert list_reviews(s, status=None)
        with pytest.raises(ReviewError):
            get_review(s, uuid.uuid4())
        with pytest.raises(ReviewError):
            resolve(s, uuid.uuid4(), ReviewResolution.FRAUD)
    assert _count(w, ReviewOutcome) == 2


# ------------------------------------------------------------------ policy registry
def test_policies_are_immutable_and_activation_is_validated(w: World) -> None:
    with session_scope(w.factory) as s:
        policy = load_policy(s, P1)
        with pytest.raises(PolicyError, match="immutable"):
            create_policy(s, policy)
        assert [r.policy_version for r in list_policies(s)] == [P1, P2]
        with pytest.raises(PolicyError, match="unknown policy"):
            activate(s, "risk-policy-9.9.9")
        with pytest.raises(PolicyError, match="already in the active model set"):
            activate(s, P1, shadow_models=[GB])
        with pytest.raises(PolicyError, match="cannot also be a shadow"):
            activate(s, P1, shadow_policies=[P1])
        with pytest.raises(PolicyError):
            activate(s, P1, shadow_models=["gradient-boosting-9.9.9"])
        bad = policy.model_copy(
            update={
                "policy_version": "risk-policy-3.0.0",
                "primary": policy.primary.model_copy(update={"artifact_sha256": "b" * 64}),
            }
        )
        with pytest.raises(PolicyError, match="digest"):
            create_policy(s, RiskPolicyDefinition.model_validate(bad.model_dump(mode="json")))
        wrong_role = policy.model_copy(
            update={
                "policy_version": "risk-policy-3.0.1",
                "sequence": policy.primary.model_copy(update={"calibration": None}),
            }
        )
        with pytest.raises(PolicyError, match="not a sequence model"):
            create_policy(
                s, RiskPolicyDefinition.model_validate(wrong_role.model_dump(mode="json"))
            )
        stale_rules = policy.model_copy(
            update={"policy_version": "risk-policy-3.0.2", "rules_fingerprint": "c" * 64}
        )
        with pytest.raises(PolicyError, match="rule set"):
            create_policy(
                s, RiskPolicyDefinition.model_validate(stale_rules.model_dump(mode="json"))
            )
        history = deployment_history(s)
        assert [d.sequence for d in history] == [1]
        second = activate(s, P2, note="switch")
        assert second.sequence == 2 and active_deployment(s).policy.policy_version == P2  # type: ignore[union-attr]
        assert [d.policy_version for d in deployment_history(s)] == [P2, P1]


# ------------------------------------------------------------------ simulation + comparison
def test_simulation_changes_nothing_and_is_consistent(w: World) -> None:
    _first_decision(w)
    before = _count(w, RiskAssessment)
    with w.session() as s:
        report = simulate(s, load_policy(s, P1))
        s.rollback()
    assert _count(w, RiskAssessment) == before
    assert report["stored_decisions_changed"] is False and "SYNTHETIC" in report["data_note"]
    assert sum(report["decision_distribution"].values()) == report["events"]
    assert (
        report["fraud_caught"] + report["fraud_challenged_step_up"] + report["fraud_missed"]
        == (report["fraud_events"])
    )
    assert report["estimated_cost"] > 0 and report["split"] == "test"


def test_policy_comparison_uses_identical_events(w: World) -> None:
    with w.session() as s:
        a, b = load_policy(s, P1), load_policy(s, P2)
        report = compare_policies(s, a, b, iterations=50)
        assert report["a"]["events"] == report["b"]["events"] == report["same_events"]
        assert sum(report["decision_crosstab"].values()) == report["same_events"]
        diff = report["cost_difference_a_minus_b"]
        assert diff["lower_95"] <= diff["estimate"] <= diff["upper_95"]
        assert "never a reason to activate" in report["note"]
        same = compare_policies(s, a, a, iterations=20)
        assert same["decisions_differ"] == 0 and same["cost_difference_a_minus_b"]["estimate"] == 0
        login_only = a.model_copy(update={"decision_event_kinds": ("login",)})
        from fraud_ai.risk.offline import _context

        ctx = _context(s, [GB, GRU])
        with pytest.raises(OfflinePolicyError, match="no \\('login',\\) events"):
            run_policy(ctx, login_only, "test")
        s.rollback()


# ------------------------------------------------------------------ monitoring
def test_monitoring_summary_drift_and_shadow(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = w.service()
    w.replay_until(svc, decisions=35)
    with w.session() as s:
        summary = monitoring.summary(s)
        assert summary["assessments"] == 35 and summary["policies_seen"] == [P1]
        assert sum(summary["decisions"].values()) == 35
        assert summary["latency_ms"]["total"]["count"] == 35
        assert summary["shadow_comparisons"] == 70
        drift = monitoring.drift(s)
        assert set(drift["signals"]) >= {
            "prediction",
            "decision_rates",
            "fraud_prevalence",
            "features",
        }
        assert drift["signals"]["prediction"]["rows"] == 35
        assert "retrained" in drift["action"]
        assert isinstance(drift["warnings"], list)
        shadow = monitoring.shadow_report(s)
        assert shadow["assessments_with_shadow"] == 35
        model = shadow["models"][LR]
        assert model["compared"] == 35 and 0 <= model["agreement_rate"] <= 1
        policy = shadow["policies"][P2]
        assert sum(policy["crosstab"].values()) == 35
        future = datetime.now().astimezone() + timedelta(days=1)
        assert monitoring.summary(s, since=future)["assessments"] == 0
        assert monitoring.drift(s, since=future)["signals"]["prediction"]["status"] == (
            "insufficient_data"
        )
    monkeypatch.setattr(monitoring, "active_deployment", lambda session: None)
    with w.session() as s:
        assert monitoring.drift(s)["status"] == "no_active_policy"


def test_prevalence_status() -> None:
    assert monitoring._prevalence_status(5, 1.0) == "insufficient_data"
    assert monitoring._prevalence_status(50, 3.0) == "shifted"
    assert monitoring._prevalence_status(50, 0.1) == "labels_pending_or_lower"
    assert monitoring._prevalence_status(50, 1.1) == "stable"


# ------------------------------------------------------------------ logging + LLM independence
def test_structured_logs_carry_no_identifiers(w: World, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="fraud_ai.realtime"):
        _, _outcome, nxt = _first_decision(w)
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.name == "fraud_ai.realtime"]
    decision = next(line for line in lines if line.get("status") == "decided")
    assert decision["policy_version"] == P1 and decision["event_ref"].startswith("rt-")
    assert "total" in decision["latency_ms"]
    raw = w.events[nxt - 1]
    assert raw["event_id"] not in caplog.text and raw["user_id"] not in caplog.text
    ip = (raw["metadata"].get("network") or {}).get("ip")
    if ip:
        assert ip not in caplog.text


def test_hot_path_does_not_depend_on_the_llm(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    code = (
        "import sys, fraud_ai.realtime.service, fraud_ai.realtime.monitoring, "
        "fraud_ai.realtime.review, fraud_ai.risk.offline, fraud_ai.risk.registry; "
        "print(sorted(m for m in sys.modules if m.startswith('fraud_ai.llm')))"
    )
    out = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    loaded = json.loads(out.stdout.replace("'", '"'))
    assert loaded == []  # no LLM module at all: no Ollama, llama.cpp or reference runtime
    monkeypatch.setenv("LOCAL_LLM_RUNTIME", "ollama")
    monkeypatch.setenv("LOCAL_LLM_ENDPOINT", "http://127.0.0.1:9")
    _, outcome, _ = _first_decision(w)
    assert outcome.status == "decided" and not outcome.failures


# ------------------------------------------------------------------ direct regression tests
def _row_state(w: World, assessment_id: Any) -> dict[str, Any]:
    with w.session() as s:
        row = s.get(RiskAssessment, assessment_id)
        assert row is not None
        return {c.key: getattr(row, c.key) for c in RiskAssessment.__table__.columns}


def test_t1_event_arriving_at_t3_does_not_alter_the_t2_decision(w: World) -> None:
    """T1 < T2 < T3: the T2 transaction arrives on time and is decided. A T1 transaction
    for the same user arrives late, at T3. The T2 decision, its snapshot and its
    predictions are unchanged, and the T1 event gets its own late-flagged assessment."""
    svc, t2_outcome, nxt = _first_decision(w)
    t2_event = w.events[nxt - 1]
    t2_state = _row_state(w, t2_outcome.assessment_id)
    t2 = datetime.fromisoformat(t2_event["timestamp"])
    with w.session() as s:
        t2_id = uuid.UUID(t2_event["event_id"])
        snapshots = [
            (x.snapshot_id, x.feature_hash)
            for x in s.scalars(select(FeatureSnapshot).where(FeatureSnapshot.event_id == t2_id))
        ]
        predictions = [
            (p.prediction_id, p.fraud_probability)
            for p in s.scalars(select(ModelPrediction).where(ModelPrediction.event_id == t2_id))
        ]
    t1_event = json.loads(json.dumps(t2_event))
    t1_event["event_id"] = str(uuid.uuid4())
    t1_event["timestamp"] = (t2 - timedelta(hours=1)).isoformat()  # T1
    t1_event["arrival_time"] = (t2 + timedelta(hours=2)).isoformat()  # T3
    t1_event["metadata"]["transaction_id"] = str(uuid.uuid4())
    t1_outcome = svc.score_event(t1_event)
    assert t1_outcome.status == "decided" and "LATE_EVENT" in t1_outcome.reason_codes
    assert t1_outcome.assessment_id != t2_outcome.assessment_id
    assert _row_state(w, t2_outcome.assessment_id) == t2_state
    with w.session() as s:
        assert [
            (x.snapshot_id, x.feature_hash)
            for x in s.scalars(select(FeatureSnapshot).where(FeatureSnapshot.event_id == t2_id))
        ] == snapshots
        assert [
            (p.prediction_id, p.fraud_probability)
            for p in s.scalars(select(ModelPrediction).where(ModelPrediction.event_id == t2_id))
        ] == predictions
    again = svc.score_event(t2_event)
    assert again.status == "duplicate" and again.assessment_id == t2_outcome.assessment_id


def test_idempotency_covers_review_entries(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        service_module,
        "point_in_time_snapshot",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
    )
    svc, first, nxt = _first_decision(w)
    assert first.decision is Decision.MANUAL_REVIEW and first.review_id is not None
    tables = (EventRecord, FeatureSnapshot, ModelPrediction, RiskAssessment, ReviewItem)
    before = [_count(w, t) for t in tables]
    again = svc.score_event(w.events[nxt - 1])
    assert again.status == "duplicate"
    assert (again.assessment_id, again.review_id) == (first.assessment_id, first.review_id)
    assert [_count(w, t) for t in tables] == before
    assert _count(w, ReviewItem) == 1


def test_later_evidence_and_new_policy_never_overwrite_the_original(w: World) -> None:
    svc, first, nxt = _first_decision(w)
    original = _row_state(w, first.assessment_id)
    with session_scope(w.factory) as s:
        activate(s, P2)
    # A redelivery under the new policy returns the ORIGINAL decision; it is not re-decided.
    redelivered = svc.score_event(w.events[nxt - 1])
    assert redelivered.status == "duplicate" and redelivered.policy_version == P1
    new = svc.reassess(first.event_id)
    assert new.assessment_version == 2 and new.policy_version == P2
    assert _row_state(w, first.assessment_id) == original
    with w.session() as s:
        v2 = s.get(RiskAssessment, new.assessment_id)
        assert v2 is not None and v2.supersedes_assessment_id == first.assessment_id
        assert original["policy_version"] == P1 and original["primary_model"] == GB
        assert set(original["model_scores"]) == {"primary", "sequence"}  # P1's model set
        assert set(v2.model_scores) == {"primary"}  # P2's model set
    assert svc.score_event(w.events[nxt - 1]).assessment_version == 2


def test_shadow_policy_cannot_trigger_review_or_change_scores(
    world_dir: Path, tmp_path: Path
) -> None:
    """Direct regression: a shadow policy that would send EVERYTHING to manual review
    must not change any decision, score, reason, action or review entry."""
    from fraud_ai.risk.policy import Band

    results: dict[str, Any] = {}
    for name in ("shadowed", "plain"):
        (tmp_path / name).mkdir()
        for w in open_world(world_dir, tmp_path / name):
            with session_scope(w.factory) as s:
                if name == "shadowed":
                    base = load_policy(s, P1)
                    review_all = RiskPolicyDefinition.model_validate(
                        base.model_copy(
                            update={
                                "policy_version": "risk-policy-9.0.0",
                                "bands": (
                                    Band(
                                        lower=0.0,
                                        risk_level="high",
                                        decision=Decision.MANUAL_REVIEW,
                                    ),
                                ),
                            }
                        ).model_dump(mode="json")
                    )
                    create_policy(s, review_all)
                    activate(s, P1, shadow_models=[LR], shadow_policies=["risk-policy-9.0.0"])
                else:
                    activate(s, P1)
            outcomes, _ = w.replay_until(w.service(), decisions=10)
            decided = [o for o in outcomes if o.status == "decided"]
            with w.session() as s:
                rows = [s.get(RiskAssessment, o.assessment_id) for o in decided]
                results[name] = {
                    "decisions": [
                        (
                            r.decision,
                            r.final_risk_score,
                            r.calibrated_score,
                            r.risk_level,
                            r.reason_codes,
                            r.action,
                        )
                        for r in rows
                        if r is not None
                    ],
                    "reviews": int(s.scalar(select(func.count()).select_from(ReviewItem)) or 0),
                }
                if name == "shadowed":
                    shadow_decisions = {
                        p["decision"] for r in rows if r is not None for p in r.shadow["policies"]
                    }
                    assert shadow_decisions == {"MANUAL_REVIEW"}
    assert results["shadowed"] == results["plain"]
    assert any(d[0] is not Decision.MANUAL_REVIEW for d in results["plain"]["decisions"])


def test_review_resolution_creates_no_label(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    from fraud_ai.database.models import FraudLabel

    monkeypatch.setattr(
        service_module,
        "point_in_time_snapshot",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
    )
    _, outcome, _ = _first_decision(w)
    original = _row_state(w, outcome.assessment_id)
    labels = _count(w, FraudLabel)
    assert _count(w, ReviewItem) == 1
    with session_scope(w.factory) as s:
        resolve(s, outcome.review_id, ReviewResolution.FRAUD)  # type: ignore[arg-type]
    assert _count(w, FraudLabel) == labels and _count(w, ReviewOutcome) == 1
    assert _row_state(w, outcome.assessment_id) == original


def test_simulation_and_comparison_are_read_only(w: World) -> None:
    from fraud_ai.database.models import FraudLabel

    _first_decision(w)
    tables = (
        RiskAssessment, ReviewItem, PolicyDeployment, FraudLabel, ModelPrediction,
        ModelCalibration, RiskPolicyRecord, FeatureSnapshot,
    )  # fmt: skip
    before = [_count(w, t) for t in tables]
    with session_scope(w.factory) as s:  # committed on purpose: nothing may be written
        simulate(s, load_policy(s, P1))
        compare_policies(s, load_policy(s, P1), load_policy(s, P2), iterations=20)
    assert [_count(w, t) for t in tables] == before


def test_comparison_uses_exactly_the_same_examples(w: World) -> None:
    from fraud_ai.risk.offline import _context

    with w.session() as s:
        a, b = load_policy(s, P1), load_policy(s, P2)
        ctx = _context(s, [GB, GRU])
        run_a, run_b = run_policy(ctx, a, "test"), run_policy(ctx, b, "test")
        assert run_a.event_refs == run_b.event_refs and len(set(run_a.event_refs)) == len(
            run_a.event_refs
        )
        assert (run_a.labels == run_b.labels).all()
        report = compare_policies(s, a, b, iterations=10)
        assert report["same_events"] == len(run_a.event_refs)
        s.rollback()


def test_logs_never_contain_ips_addresses_card_or_token_data(
    w: World, caplog: pytest.LogCaptureFixture
) -> None:
    svc = w.service()
    with caplog.at_level(logging.DEBUG):
        _, nxt = w.replay_until(svc, decisions=5)
        w.replay_until(svc, decisions=5)  # redelivery is logged too
    sensitive: set[str] = set()
    for e in w.events[:nxt]:
        md = e.get("metadata") or {}
        for key in ("full_address", "token_reference", "fingerprint", "card_last4"):
            if md.get(key):
                sensitive.add(str(md[key]))
        ip = (md.get("network") or {}).get("ip")
        if ip:
            sensitive.add(ip)
        sensitive.add(e["event_id"])
        if e.get("user_id"):
            sensitive.add(e["user_id"])
        if e.get("device_id"):
            sensitive.add(e["device_id"])
    assert sensitive
    leaked = sorted(v for v in sensitive if v in caplog.text)
    assert leaked == []
    for record in caplog.records:
        if record.name == "fraud_ai.realtime":
            assert set(json.loads(record.getMessage())) <= set(
                service_module.__dict__["log_decision"].__globals__["LOG_FIELDS"]
            )
