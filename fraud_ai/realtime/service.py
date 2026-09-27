"""``FraudScoringService``: the real-time hot path.

::

    incoming event -> validate (contract) -> ingest (idempotent, with arrival time)
      -> active deployment (verified policy) -> information-cutoff check
      -> point-in-time feature snapshot -> sequence (if a sequence model needs it)
      -> active model set (cached, verified) -> score + persist predictions
      -> calibrate -> rules -> policy -> shadow models / policies (recorded only)
      -> persist the immutable risk assessment (+ review item) -> return the decision

The LLM is **not** in this path. Explanations (Stage 7) are requested afterwards for a
stored assessment, and scoring works whether or not a local LLM exists.

**Arrival-time semantics.** An event is decided when it is ingested, so the database
holds only what had arrived by then.

* Features are computed as of the *event time*, the same semantics as training, from the
  events already received.
* The snapshot and the decision are then stored and never recomputed.
* A late event is decided on arrival and flagged as late. It cannot change an earlier
  decision, because stored assessments are immutable. Recomputing history later may give
  a different vector, which is expected and documented.
* If an event is decided *after* later-arriving information for the same user is
  already stored (a replay out of arrival order), the information-cutoff check refuses a
  normal decision and falls back to manual review.

**Idempotency.** A redelivered event returns its stored assessment. The key is
SHA-256(event id, policy version, assessment version), and it is unique in the database,
together with (event, version), so concurrent duplicates cannot create two decisions.

**Failures** are explicit (:class:`FailureCategory`) and map to the policy's conservative
fallbacks. Nothing fails open: no path returns ALLOW because something broke.
"""

from __future__ import annotations

import contextlib
import hashlib
import math
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai.core.enums import Decision
from fraud_ai.core.exceptions import EventProcessingError, FraudAIError
from fraud_ai.database.models import (
    EventRecord,
    ModelVersion,
    ReviewItem,
    RiskAssessment,
)
from fraud_ai.evaluation.calibration import Calibrator
from fraud_ai.features.context import load_contexts
from fraud_ai.features.extractor import compute_vector
from fraud_ai.features.vector import FraudFeatureVector
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.models.base import FraudModel
from fraud_ai.models.estimators import ArtifactIntegrityError
from fraud_ai.models.factory import is_anomaly_model
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import point_in_time_snapshot, store_prediction, trained_kinds
from fraud_ai.realtime.cache import ModelCache
from fraud_ai.realtime.contract import (
    DEFAULT_MAX_CLOCK_SKEW,
    EventContractError,
    IncomingEvent,
    check_clock,
    parse_incoming,
)
from fraud_ai.realtime.telemetry import Metrics, event_ref, log_decision
from fraud_ai.risk.engine import PolicyDecision, PolicyInputs, decide, review_priority
from fraud_ai.risk.policy import FailureCategory, ModelSlot, RiskPolicyDefinition
from fraud_ai.risk.registry import ActiveDeployment, active_deployment, validate_references
from fraud_ai.rules.engine import RuleResult
from fraud_ai.rules.ruleset import get_rule_set
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.sequences.definition import SequenceDefinition
from fraud_ai.sequences.extraction import build_sequence
from fraud_ai.utils.time import ensure_utc

UNAVAILABLE_POLICY = "unavailable"


def idempotency_key(event_id: uuid.UUID, policy_version: str, version: int) -> str:
    return hashlib.sha256(f"{event_id}:{policy_version}:{version}".encode()).hexdigest()


@dataclass
class ScoringOutcome:
    status: str  # decided | duplicate | ingested | rejected | not_persisted
    event_id: uuid.UUID | None
    decision: Decision | None = None
    risk_level: str | None = None
    reason_codes: list[str] = field(default_factory=list)
    action: dict[str, Any] = field(default_factory=dict)
    fallback_used: bool = False
    failures: list[dict[str, str]] = field(default_factory=list)
    latency_ms: dict[str, float] = field(default_factory=dict)
    policy_version: str | None = None
    assessment_id: uuid.UUID | None = None
    assessment_version: int | None = None
    review_id: uuid.UUID | None = None
    persisted: bool = False
    lateness_seconds: float | None = None
    calibrated_score: float | None = None
    error: str | None = None
    shadow: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "event_ref": event_ref(self.event_id) if self.event_id else None,
            "decision": self.decision.value if self.decision else None,
            "risk_level": self.risk_level,
            "reason_codes": self.reason_codes,
            "action": self.action,
            "fallback_used": self.fallback_used,
            "failures": self.failures,
            "latency_ms": self.latency_ms,
            "policy_version": self.policy_version,
            "assessment_id": str(self.assessment_id) if self.assessment_id else None,
            "assessment_version": self.assessment_version,
            "review_id": str(self.review_id) if self.review_id else None,
            "persisted": self.persisted,
            "lateness_seconds": self.lateness_seconds,
            "calibrated_score": self.calibrated_score,
            "error": self.error,
        }


class _Timer:
    def __init__(self) -> None:
        self.ms: dict[str, float] = {}

    @contextlib.contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.ms[name] = round(self.ms.get(name, 0.0) + (time.perf_counter() - started) * 1e3, 3)


@dataclass
class _EventState:
    """Per-event working state (never shared between events)."""

    session: Session
    record: EventRecord
    kind: str
    timer: _Timer
    started: float = field(default_factory=time.perf_counter)
    assessment: RiskAssessment | None = None
    vector: FraudFeatureVector | None = None
    snapshot: Any = None
    persist_predictions: bool = True
    sequences: dict[str, Any] = field(default_factory=dict)
    raw_scores: dict[str, float] = field(default_factory=dict)
    failures: list[tuple[FailureCategory, str]] = field(default_factory=list)
    prediction_ids: dict[str, uuid.UUID] = field(default_factory=dict)

    def fail(self, category: FailureCategory, exc: BaseException | str) -> None:
        message = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
        self.failures.append((category, message[:300]))


class FraudScoringService:
    """Callable directly from Python (and from the CLI). Thread-safe."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        pseudonymiser: Pseudonymiser,
        *,
        store_raw_ip: bool = False,
        clock: Callable[[], datetime] | None = None,
        cache: ModelCache | None = None,
        max_clock_skew: Any = DEFAULT_MAX_CLOCK_SKEW,
        replay: bool = False,
    ) -> None:
        self._factory = session_factory
        self._pseudo = pseudonymiser
        self._store_raw_ip = store_raw_ip
        self._clock = clock or (lambda: datetime.now(UTC))
        self.cache = cache or ModelCache()
        self._skew = max_clock_skew
        self._replay = replay
        self.metrics = Metrics()
        bind = session_factory.kw.get("bind")
        dialect = getattr(getattr(bind, "dialect", None), "name", "")
        # SQLite has a single writer: serialise scoring there. PostgreSQL runs concurrently
        # and relies on the unique constraints for idempotency.
        self._write_lock: Any = (
            threading.Lock() if dialect == "sqlite" else contextlib.nullcontext()
        )
        # Model/calibration/rule references are verified once per deployment per process
        # (the policy hash itself is re-verified on every event).
        self._verified: dict[Any, str | None] = {}  # deployment id -> reference error

    # ------------------------------------------------------------------ public API
    def score_event(
        self, data: dict[str, Any], *, arrival_time: datetime | None = None
    ) -> ScoringOutcome:
        timer = _Timer()
        started = time.perf_counter()
        with timer.stage("validation"):
            try:
                incoming = parse_incoming(data, allow_arrival_time=self._replay)
                arrival = ensure_utc(arrival_time or incoming.arrival_time or self._clock())
                check_clock(incoming.event, arrival, self._skew)
            except EventContractError as exc:
                return self._rejected(None, str(exc), timer, started, data)
        with self._write_lock:
            for attempt in range(2):
                try:
                    return self._score(incoming, arrival, timer, started)
                except IntegrityError:
                    # A concurrent request stored the same event/assessment first.
                    existing = self._stored_outcome(incoming.event.event_id, timer, started)
                    if existing is not None:
                        return existing
                    if attempt == 1:
                        return self._db_failure(incoming, "integrity conflict", timer, started)
                except SQLAlchemyError as exc:
                    return self._db_failure(incoming, type(exc).__name__, timer, started)
        raise AssertionError("unreachable")  # pragma: no cover

    def reassess(self, event_id: uuid.UUID, *, note: str | None = None) -> ScoringOutcome:
        """A new assessment version with the evidence available *now* (fresh features, the
        current deployment). The earlier assessment is preserved, never changed."""
        timer = _Timer()
        started = time.perf_counter()
        with self._write_lock, self._factory() as session:
            record = session.get(EventRecord, event_id)
            if record is None:
                raise FraudAIError(f"unknown event {event_id}")
            previous = _latest_assessment(session, event_id)
            if previous is None:
                raise FraudAIError("the event has no assessment to supersede; score it first")
            kind = _kind(record)
            if kind is None:  # pragma: no cover - only decision points are assessed
                raise FraudAIError("the event is not a decision point")
            state = _EventState(
                session, record, kind, timer, started=started, persist_predictions=False
            )
            outcome = self._decide(
                state,
                arrival=ensure_utc(record.arrival_time or record.occurred_at),
                version=previous.assessment_version + 1,
                supersedes=previous.assessment_id,
                mode="reassessment",
                fresh_features=True,
            )
            session.commit()
        return self._finish(outcome, timer, started)

    # ------------------------------------------------------------------ pipeline
    def _score(
        self, incoming: IncomingEvent, arrival: datetime, timer: _Timer, started: float
    ) -> ScoringOutcome:
        event = incoming.event
        with self._factory() as session:
            record = session.get(EventRecord, event.event_id)
            redelivered = record is not None
            if record is not None:
                if (
                    record.event_type != event.event_type
                    or ensure_utc(record.occurred_at) != event.timestamp
                    or record.user_id != event.user_id
                ):
                    return self._rejected(
                        event.event_id,
                        "event_id already used by a different event (conflicting duplicate)",
                        timer,
                        started,
                    )
                stored = _latest_assessment(session, event.event_id)
                if stored is not None or incoming.decision_kind is None:
                    outcome = _outcome_from(stored, event.event_id, duplicate=True)
                    return self._finish(outcome, timer, started)
                arrival = ensure_utc(record.arrival_time or record.occurred_at)
            else:
                with timer.stage("ingestion"):
                    try:
                        EventProcessor(
                            session, self._pseudo, store_raw_ip=self._store_raw_ip
                        ).process(event, arrival_time=arrival)
                    except EventProcessingError as exc:
                        session.rollback()
                        return self._rejected(event.event_id, str(exc), timer, started)
                    record = session.get(EventRecord, event.event_id)
                    assert record is not None
            if incoming.decision_kind is None:
                session.commit()
                return self._finish(
                    ScoringOutcome("ingested", event.event_id, persisted=True), timer, started
                )
            state = _EventState(session, record, incoming.decision_kind, timer, started=started)
            outcome = self._decide(state, arrival=arrival, version=1, supersedes=None, mode="live")
            if redelivered and outcome.status == "ingested":
                outcome.status = "duplicate"
            with timer.stage("commit"):
                session.commit()
        return self._finish(outcome, timer, started)

    def _deployment(self, state: _EventState) -> ActiveDeployment | None:
        with state.timer.stage("policy_load"):
            try:
                deployment = active_deployment(state.session)
            except FraudAIError as exc:
                state.fail(FailureCategory.POLICY_UNAVAILABLE, exc)
                return None
            if deployment is None:
                state.fail(FailureCategory.POLICY_UNAVAILABLE, "no active deployment")
                return None
            key = deployment.deployment_id
            if key not in self._verified:
                try:
                    validate_references(state.session, deployment.policy, load_artifacts=False)
                    self._verified[key] = None
                except FraudAIError as exc:
                    self._verified[key] = str(exc)
            self.cache.bind(key)
            problem = self._verified[key]
            if problem is not None:
                category = (
                    FailureCategory.CALIBRATION_UNAVAILABLE
                    if "calibration" in problem
                    else FailureCategory.POLICY_UNAVAILABLE
                )
                state.fail(category, problem)
            return deployment

    def _decide(
        self,
        state: _EventState,
        *,
        arrival: datetime,
        version: int,
        supersedes: uuid.UUID | None,
        mode: str,
        fresh_features: bool = False,
    ) -> ScoringOutcome:
        record, timer = state.record, state.timer
        event_time = ensure_utc(record.occurred_at)
        lateness = max(0.0, (arrival - event_time).total_seconds())
        deployment = self._deployment(state)
        policy = deployment.policy if deployment else None
        if policy is not None and state.kind not in policy.decision_event_kinds:
            return ScoringOutcome(
                "ingested",
                record.event_id,
                policy_version=policy.policy_version,
                persisted=True,
                reason_codes=["NOT_A_DECISION_POINT"],
            )
        if mode == "live":
            with timer.stage("cutoff_check"):
                self._check_cutoff(state, event_time, arrival)
        if policy is not None and not _blocked(state):
            self._features(state, policy, fresh=fresh_features)
        scores: dict[str, dict[str, Any]] = {}
        rule_results: list[RuleResult] = []
        inputs_primary: float | None = None
        secondary_flags: dict[str, bool] = {}
        anomaly_flag: bool | None = None
        if policy is not None and state.vector is not None and not _blocked(state):
            scores = self._score_models(state, policy)
            primary = scores.get("primary")
            if primary is not None and primary.get("calibrated") is not None:
                inputs_primary = primary["calibrated"]
            for role in ("secondary", "sequence"):
                if role in scores and "flagged" in scores[role]:
                    secondary_flags[role] = bool(scores[role]["flagged"])
            if "anomaly" in scores and "flagged" in scores["anomaly"]:
                anomaly_flag = bool(scores["anomaly"]["flagged"])
            with timer.stage("rules"):
                try:
                    rule_results = get_rule_set(policy.rules_version).evaluate(
                        state.vector.values,
                        state.kind,
                        f"feature_snapshots/{state.snapshot.snapshot_id}"
                        if state.snapshot is not None
                        else None,
                    )
                except Exception as exc:  # a broken rule must not fail open
                    state.fail(FailureCategory.RULES_FAILED, exc)
        failures = [f for f, _ in state.failures]
        with timer.stage("policy"):
            decision = decide(
                policy,
                PolicyInputs(
                    primary_score=inputs_primary,
                    rule_results=rule_results,
                    secondary_flags=secondary_flags,
                    anomaly_flag=anomaly_flag,
                    failures=failures,
                    # Lateness describes the original delivery; a reassessment is not late.
                    lateness_seconds=lateness if mode == "live" else None,
                ),
            )
        shadow: dict[str, Any] = {}
        if deployment is not None and state.vector is not None and not _blocked(state):
            with timer.stage("shadow"):
                shadow = self._shadow(state, deployment, decision, scores)
        with timer.stage("persistence"):
            outcome = self._persist(
                state,
                policy,
                deployment,
                decision,
                scores,
                rule_results,
                shadow,
                event_time=event_time,
                arrival=arrival,
                lateness=lateness,
                version=version,
                supersedes=supersedes,
                mode=mode,
            )
        if state.assessment is not None:
            # The stored breakdown includes everything up to (not including) the commit.
            state.assessment.latency_ms = {
                **timer.ms,
                "total": round((time.perf_counter() - state.started) * 1e3, 3),
            }
            state.session.flush()
        return outcome

    def _check_cutoff(self, state: _EventState, event_time: datetime, arrival: datetime) -> None:
        """Only information available by arrival time may influence the decision."""
        record = state.record
        if record.user_id is None:
            return
        later = state.session.scalar(
            select(func.count())
            .select_from(EventRecord)
            .where(
                EventRecord.user_id == record.user_id,
                EventRecord.event_id != record.event_id,
                EventRecord.occurred_at <= event_time,
                func.coalesce(EventRecord.arrival_time, EventRecord.occurred_at) > arrival,
            )
        )
        if later:
            state.fail(
                FailureCategory.INFORMATION_CUTOFF_VIOLATED,
                f"{later} event(s) for this user arrived after this event; a live decision "
                "would use information that was not available at its arrival",
            )

    def _features(self, state: _EventState, policy: RiskPolicyDefinition, *, fresh: bool) -> None:
        try:
            with state.timer.stage("model_resolution"):
                primary = resolve_model(state.session, policy.primary.ref)
            policy_feature_version = primary.feature_version
        except FraudAIError as exc:
            state.fail(FailureCategory.PRIMARY_MODEL_UNAVAILABLE, exc)
            return
        with state.timer.stage("features"):
            savepoint = state.session.begin_nested()
            try:
                if fresh:
                    ctx = load_contexts(state.session, [state.record.event_id])[
                        state.record.event_id
                    ]
                    state.vector = compute_vector(state.session, ctx, policy_feature_version)
                else:
                    state.snapshot, state.vector = point_in_time_snapshot(
                        state.session, state.record.event_id, policy_feature_version
                    )
                savepoint.commit()
            except Exception as exc:
                savepoint.rollback()
                state.fail(FailureCategory.FEATURE_EXTRACTION_FAILED, exc)
                state.vector = None

    # ------------------------------------------------------------------ models
    def _load(
        self, state: _EventState, slot_ref: str, pinned: str | None
    ) -> tuple[ModelVersion, FraudModel]:
        with state.timer.stage("model_resolution"):
            record = resolve_model(state.session, slot_ref)
        if pinned is not None and record.artifact_sha256 != pinned:
            raise FraudAIError(f"{slot_ref}: registered artefact differs from the pinned digest")
        with state.timer.stage("model_loading"):
            model, _ = self.cache.get(record)
        return record, model

    def _matrix(self, state: _EventState, record: ModelVersion, model: FraudModel) -> ModelMatrix:
        assert state.vector is not None
        matrix = ModelMatrix.from_vectors([state.vector], record.feature_version)
        if model.input_kind != "sequence":
            return matrix
        from fraud_ai.sequences.inputs import SequenceMatrix

        definition: SequenceDefinition | None = getattr(model, "definition", None)
        if definition is None:  # pragma: no cover - a trained sequence model has one
            raise FraudAIError("sequence model has no sequence definition")
        key = definition.fingerprint()
        if key not in state.sequences:
            with state.timer.stage("sequence"):
                try:
                    state.sequences[key] = build_sequence(
                        state.session, state.record.event_id, definition
                    )
                except Exception as exc:
                    state.fail(FailureCategory.SEQUENCE_EXTRACTION_FAILED, exc)
                    state.sequences[key] = None
        batch = state.sequences[key]
        if batch is None:
            raise _SequenceUnavailable()
        return SequenceMatrix.attach(matrix, batch)

    def _raw_score(
        self, state: _EventState, ref: str, pinned: str | None, stage: str, *, persist: bool
    ) -> tuple[ModelVersion, float]:
        if ref in state.raw_scores:
            with state.timer.stage("model_resolution"):
                return resolve_model(state.session, ref), state.raw_scores[ref]
        record, model = self._load(state, ref, pinned)
        assert state.vector is not None
        kinds = trained_kinds(record)
        if kinds and state.vector.event_kind.value not in kinds:
            raise FraudAIError(f"{ref} was not trained on {state.vector.event_kind.value} events")
        matrix = self._matrix(state, record, model)
        with state.timer.stage(stage):
            value = float(model.predict_proba(matrix)[0])
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise FraudAIError(f"{ref} produced an invalid score")
        state.raw_scores[ref] = value
        if persist and state.persist_predictions and not is_anomaly_model(record.model_name):
            threshold = record.default_threshold if record.default_threshold is not None else 0.5
            assert state.snapshot is not None
            with state.timer.stage("prediction_persistence"):
                prediction, _ = store_prediction(
                    state.session,
                    state.record.event_id,
                    record,
                    value,
                    threshold,
                    state.snapshot,
                    state.vector,
                )
            state.prediction_ids[ref] = prediction.prediction_id
        return record, value

    def _score_models(
        self, state: _EventState, policy: RiskPolicyDefinition
    ) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        categories = {
            "primary": FailureCategory.PRIMARY_MODEL_UNAVAILABLE,
            "secondary": FailureCategory.SECONDARY_MODEL_FAILED,
            "sequence": FailureCategory.SEQUENCE_MODEL_FAILED,
            "anomaly": FailureCategory.ANOMALY_MODEL_FAILED,
        }
        for role, slot in policy.slots().items():
            try:
                _, raw = self._raw_score(
                    state, slot.ref, slot.artifact_sha256, f"inference_{role}", persist=True
                )
            except _SequenceUnavailable:
                if role == "primary":  # pragma: no cover - primary models are tabular
                    state.fail(categories[role], "sequence unavailable")
                out[role] = {"model": slot.ref, "error": "sequence_unavailable"}
                continue
            except Exception as exc:
                category = categories[role]
                if role == "primary" and (
                    isinstance(exc, ArtifactIntegrityError) or "digest" in str(exc).lower()
                ):
                    category = FailureCategory.PRIMARY_ARTIFACT_INVALID
                state.fail(category, exc)
                out[role] = {"model": slot.ref, "error": type(exc).__name__}
                continue
            entry: dict[str, Any] = {
                "model": slot.ref,
                "raw": round(raw, 6),
                "threshold": slot.threshold,
                "prediction_id": str(state.prediction_ids[slot.ref])
                if slot.ref in state.prediction_ids
                else None,
            }
            if role == "primary":
                with state.timer.stage("calibration"):
                    calibrated = _calibrated(slot, raw)
                if calibrated is None:
                    state.fail(FailureCategory.CALIBRATION_UNAVAILABLE, "calibration failed")
                else:
                    entry["calibrated"] = round(calibrated, 6)
            else:
                entry["flagged"] = raw >= slot.threshold
            out[role] = entry
        return out

    def _shadow(
        self,
        state: _EventState,
        deployment: ActiveDeployment,
        decision: PolicyDecision,
        scores: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Shadow models and policies: scored and recorded, never used for the decision."""
        active_flag = decision.decision.severity >= Decision.STEP_UP_AUTHENTICATION.severity
        models = []
        for ref in deployment.shadow_models:
            started = time.perf_counter()
            try:
                record, raw = self._raw_score(state, ref, None, "inference_shadow", persist=True)
                threshold = (
                    record.default_threshold if record.default_threshold is not None else 0.5
                )
                flagged = raw >= threshold
                models.append(
                    {
                        "model": ref,
                        "raw": round(raw, 6),
                        "threshold": threshold,
                        "flagged": flagged,
                        "active_flagged": active_flag,
                        "agrees": flagged == active_flag,
                        "latency_ms": round((time.perf_counter() - started) * 1e3, 3),
                    }
                )
            except Exception as exc:
                models.append({"model": ref, "error": type(exc).__name__})
        policies = []
        for shadow_policy in deployment.shadow_policies:
            started = time.perf_counter()
            try:
                result = self._shadow_policy(state, shadow_policy)
                policies.append(
                    {
                        "policy_version": shadow_policy.policy_version,
                        "decision": result.decision.value,
                        "risk_level": result.risk_level,
                        "reason_codes": list(result.reason_codes),
                        "agrees": result.decision is decision.decision,
                        "latency_ms": round((time.perf_counter() - started) * 1e3, 3),
                    }
                )
            except Exception as exc:
                policies.append(
                    {"policy_version": shadow_policy.policy_version, "error": type(exc).__name__}
                )
        return {"models": models, "policies": policies} if models or policies else {}

    def _shadow_policy(self, state: _EventState, policy: RiskPolicyDefinition) -> PolicyDecision:
        assert state.vector is not None
        _, raw = self._raw_score(
            state,
            policy.primary.ref,
            policy.primary.artifact_sha256,
            "inference_shadow",
            persist=True,
        )
        calibrated = _calibrated(policy.primary, raw)
        flags = {}
        for role in ("secondary", "sequence"):
            slot = getattr(policy, role)
            if slot is not None:
                _, value = self._raw_score(
                    state, slot.ref, slot.artifact_sha256, "inference_shadow", persist=True
                )
                flags[role] = value >= slot.threshold
        anomaly = None
        if policy.anomaly is not None:
            _, value = self._raw_score(
                state,
                policy.anomaly.ref,
                policy.anomaly.artifact_sha256,
                "inference_shadow",
                persist=False,
            )
            anomaly = value >= policy.anomaly.threshold
        rules = get_rule_set(policy.rules_version).evaluate(state.vector.values, state.kind)
        return decide(
            policy,
            PolicyInputs(
                primary_score=calibrated,
                rule_results=rules,
                secondary_flags=flags,
                anomaly_flag=anomaly,
                failures=[]
                if calibrated is not None
                else [FailureCategory.CALIBRATION_UNAVAILABLE],
            ),
        )

    # ------------------------------------------------------------------ persistence
    def _persist(
        self,
        state: _EventState,
        policy: RiskPolicyDefinition | None,
        deployment: ActiveDeployment | None,
        decision: PolicyDecision,
        scores: dict[str, dict[str, Any]],
        rule_results: list[RuleResult],
        shadow: dict[str, Any],
        *,
        event_time: datetime,
        arrival: datetime,
        lateness: float,
        version: int,
        supersedes: uuid.UUID | None,
        mode: str,
    ) -> ScoringOutcome:
        record = state.record
        policy_version = policy.policy_version if policy else UNAVAILABLE_POLICY
        primary = scores.get("primary", {})
        failures = [{"category": c.value, "message": m} for c, m in state.failures]
        row = RiskAssessment(
            event_id=record.event_id,
            assessment_version=version,
            supersedes_assessment_id=supersedes,
            idempotency_key=idempotency_key(record.event_id, policy_version, version),
            mode=mode,
            user_id=record.user_id,
            transaction_id=state.vector.transaction_id if state.vector else None,
            prediction_id=state.prediction_ids.get(policy.primary.ref) if policy else None,
            deployment_id=deployment.deployment_id if deployment else None,
            event_time=event_time,
            arrival_time=arrival,
            lateness_seconds=round(lateness, 3),
            policy_version=policy_version,
            rules_version=policy.rules_version if policy else None,
            primary_model=policy.primary.ref if policy else None,
            ml_probability=primary.get("raw"),
            calibrated_score=primary.get("calibrated"),
            final_risk_score=decision.final_risk_score,
            risk_level=decision.risk_level,
            decision=decision.decision,
            reason_codes=list(decision.reason_codes),
            model_scores=scores,
            triggered_rules={
                "rules_version": policy.rules_version if policy else None,
                "results": [r.to_dict() for r in rule_results],
            },
            shadow=shadow,
            action=decision.action,
            latency_ms=dict(state.timer.ms),
            fallback_used=decision.fallback_used,
            failures=failures,
        )
        state.session.add(row)
        state.session.flush()
        state.assessment = row
        review_id = None
        priority = review_priority(decision)
        if priority is not None:
            item = ReviewItem(
                assessment_id=row.assessment_id,
                event_id=record.event_id,
                priority=priority,
                reason_codes=list(decision.reason_codes),
            )
            state.session.add(item)
            state.session.flush()
            review_id = item.review_id
        return ScoringOutcome(
            "decided",
            record.event_id,
            decision.decision,
            decision.risk_level,
            list(decision.reason_codes),
            decision.action,
            decision.fallback_used,
            failures,
            policy_version=policy_version,
            assessment_id=row.assessment_id,
            assessment_version=version,
            review_id=review_id,
            persisted=True,
            lateness_seconds=round(lateness, 3),
            calibrated_score=decision.final_risk_score,
            shadow=shadow,
        )

    # ------------------------------------------------------------------ outcomes
    def _finish(self, outcome: ScoringOutcome, timer: _Timer, started: float) -> ScoringOutcome:
        timer.ms["total"] = round((time.perf_counter() - started) * 1e3, 3)
        outcome.latency_ms = dict(timer.ms)
        compared = [
            item
            for group in ("models", "policies")
            for item in outcome.shadow.get(group, [])
            if "agrees" in item
        ]
        shadow_cmp = len(compared) if outcome.status == "decided" else 0
        shadow_dis = sum(1 for item in compared if not item["agrees"]) if shadow_cmp else 0
        self.metrics.record(
            status=outcome.status,
            decision=outcome.decision.value if outcome.decision else None,
            failures=[f["category"] for f in outcome.failures],
            latency_ms=outcome.latency_ms,
            shadow_disagreements=shadow_dis,
            shadow_comparisons=shadow_cmp,
        )
        log_decision(
            event="realtime_decision",
            event_ref=event_ref(outcome.event_id) if outcome.event_id else None,
            status=outcome.status,
            policy_version=outcome.policy_version,
            decision=outcome.decision.value if outcome.decision else None,
            risk_level=outcome.risk_level,
            reason_codes=outcome.reason_codes,
            latency_ms=outcome.latency_ms,
            fallback_used=outcome.fallback_used,
            error_category=",".join(f["category"] for f in outcome.failures) or None,
            assessment_version=outcome.assessment_version,
            duplicate=outcome.status == "duplicate",
            lateness_seconds=outcome.lateness_seconds,
        )
        return outcome

    def _stored_outcome(
        self, event_id: uuid.UUID, timer: _Timer, started: float
    ) -> ScoringOutcome | None:
        try:
            with self._factory() as session:
                stored = _latest_assessment(session, event_id)
                if stored is None:
                    return None
                outcome = _outcome_from(stored, event_id, duplicate=True)
        except SQLAlchemyError:  # pragma: no cover - the database went away mid-retry
            return None
        return self._finish(outcome, timer, started)

    def _rejected(
        self,
        event_id: uuid.UUID | None,
        message: str,
        timer: _Timer,
        started: float,
        data: Any = None,
    ) -> ScoringOutcome:
        """A rejected event is never allowed: it is returned for manual review and is not
        persisted (an invalid event cannot be stored)."""
        if event_id is None and isinstance(data, dict):
            with contextlib.suppress(ValueError, TypeError, AttributeError):
                event_id = uuid.UUID(str(data.get("event_id")))
        outcome = ScoringOutcome(
            "rejected",
            event_id,
            Decision.MANUAL_REVIEW,
            "unknown",
            ["EVENT_REJECTED"],
            {"type": "MANUAL_REVIEW", "reason_codes": ["EVENT_REJECTED"]},
            True,
            [{"category": FailureCategory.EVENT_REJECTED.value, "message": message[:300]}],
            error=message[:300],
        )
        return self._finish(outcome, timer, started)

    def _db_failure(
        self, incoming: IncomingEvent, message: str, timer: _Timer, started: float
    ) -> ScoringOutcome:
        outcome = ScoringOutcome(
            "not_persisted",
            incoming.event.event_id,
            Decision.MANUAL_REVIEW,
            "unknown",
            ["FALLBACK_DATABASE_UNAVAILABLE"],
            {"type": "MANUAL_REVIEW", "reason_codes": ["FALLBACK_DATABASE_UNAVAILABLE"]},
            True,
            [{"category": FailureCategory.DATABASE_UNAVAILABLE.value, "message": message[:300]}],
            error=message[:300],
        )
        return self._finish(outcome, timer, started)


class _SequenceUnavailable(Exception):
    pass


def _blocked(state: _EventState) -> bool:
    from fraud_ai.risk.policy import BLOCKING_FAILURES

    return any(f in BLOCKING_FAILURES for f, _ in state.failures)


def _calibrated(slot: ModelSlot, raw: float) -> float | None:
    if slot.calibration is None:
        return raw
    try:
        value = float(
            Calibrator.from_dict(
                {"method": slot.calibration.method, "parameters": slot.calibration.parameters}
            ).transform(np.asarray([raw]))[0]
        )
    except Exception:
        return None
    return value if math.isfinite(value) and 0.0 <= value <= 1.0 else None


def _kind(record: EventRecord) -> str | None:
    from fraud_ai.realtime.contract import DECISION_KINDS

    return DECISION_KINDS.get(record.event_type)


def _latest_assessment(session: Session, event_id: uuid.UUID) -> RiskAssessment | None:
    return session.scalar(
        select(RiskAssessment)
        .where(RiskAssessment.event_id == event_id)
        .order_by(RiskAssessment.assessment_version.desc())
    )


def _outcome_from(
    row: RiskAssessment | None, event_id: uuid.UUID, *, duplicate: bool
) -> ScoringOutcome:
    if row is None:
        return ScoringOutcome("duplicate", event_id, persisted=True)
    review = None
    session = Session.object_session(row)
    if session is not None:
        review = session.scalar(
            select(ReviewItem.review_id).where(ReviewItem.assessment_id == row.assessment_id)
        )
    return ScoringOutcome(
        "duplicate" if duplicate else "decided",
        event_id,
        row.decision,
        row.risk_level,
        list(row.reason_codes),
        dict(row.action),
        row.fallback_used,
        list(row.failures),
        policy_version=row.policy_version,
        assessment_id=row.assessment_id,
        assessment_version=row.assessment_version,
        review_id=review,
        persisted=True,
        lateness_seconds=row.lateness_seconds,
        calibrated_score=row.calibrated_score,
    )
