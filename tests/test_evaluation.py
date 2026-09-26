"""Stage 4 evaluation on a trained synthetic world: context, scenarios, cohorts, errors,
walk-forward, drift, calibration persistence, report reproducibility and shortcut checks."""

from __future__ import annotations

import json
import shutil
import uuid
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fraud_ai.core.enums import FraudType, LabelSource, LabelValue
from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import FraudLabel, ModelCalibration
from fraud_ai.datasets.labels import LabelDecision, LabelProvenance, LabelStatus
from fraud_ai.evaluation import reports
from fraud_ai.evaluation.context import (
    EvaluationContext,
    EvaluationError,
    build_context,
    pseudonym,
)
from fraud_ai.evaluation.drift import TRACKED_FEATURES, build_baseline, compare_to_baseline
from fraud_ai.evaluation.reports import CalibrationConflictError, EvaluationSettings
from fraud_ai.evaluation.segments import (
    COHORTS,
    MIN_CLASS,
    SEGMENTS,
    cohort_report,
    error_report,
    scenario_report,
    segment_metrics,
)
from fraud_ai.evaluation.shortcuts import univariate_separability
from fraud_ai.evaluation.walk_forward import WalkForwardConfig, label_as_of, walk_forward
from fraud_ai.models.training import run_training
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import TEST_KEY, fast_training_config

REFS = ["logistic-regression-1.0.0", "random-forest-1.0.0", "gradient-boosting-1.0.0"]
FAST = EvaluationSettings(
    iterations=60,
    walk_forward=WalkForwardConfig(
        period_days=15, initial_train_periods=3, max_folds=4, bootstrap_iterations=30
    ),
)


@pytest.fixture(scope="module")
def eval_world(seeded_model_world: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("evaluation")
    shutil.copy(seeded_model_world, root / "world.db")
    engine = create_db_engine(f"sqlite:///{root / 'world.db'}")
    with session_scope(make_session_factory(engine)) as s:
        run_training(
            s,
            ["logistic", "random-forest", "gradient-boosting"],
            fast_training_config(),
            root / "models",
        )
    engine.dispose()
    return root


@pytest.fixture(scope="module")
def ctx_session(eval_world: Path) -> Iterator[tuple[EvaluationContext, Session]]:
    engine = create_db_engine(f"sqlite:///{eval_world / 'world.db'}")
    with make_session_factory(engine)() as session:
        yield build_context(session, REFS), session
        session.rollback()
    engine.dispose()


@pytest.fixture
def ctx(ctx_session: tuple[EvaluationContext, Session]) -> EvaluationContext:
    return ctx_session[0]


# ------------------------------------------------------------------ context
def test_context_scores_every_split_on_identical_examples(ctx: EvaluationContext) -> None:
    assert [m.model_id for m in ctx.models] == REFS
    sizes = ctx.prepared.split.sizes()
    for m in ctx.models:
        for split in ("train", "validation", "test"):
            p = m.scores[split]
            assert len(p) == sizes[split] and np.all((p >= 0) & (p <= 1))
    assert len(ctx.scenarios) == len(ctx.fraud_types) == len(ctx.prepared.y)
    assert "unknown" not in ctx.scenarios
    known = {t for t, y in zip(ctx.fraud_types, ctx.prepared.y, strict=True) if y == 1}
    assert known <= {
        "account_takeover",
        "stolen_payment_method",
        "friendly_fraud",
        "credential_stuffing",
        "other",
    }
    assert np.all(ctx.amounts("test") >= 0)
    header = ctx.header("x", extra=1)
    assert header["dataset_fingerprint"] == ctx.fingerprint and "SYNTHETIC" in header["data_note"]
    with pytest.raises(EvaluationError, match="not part"):
        ctx.model("nope-1.0.0")


def test_context_refuses_mixed_datasets_and_changed_data(eval_world: Path, tmp_path: Path) -> None:
    shutil.copy(eval_world / "world.db", tmp_path / "w.db")
    engine = create_db_engine(f"sqlite:///{tmp_path / 'w.db'}")
    factory = make_session_factory(engine)
    with factory() as s:
        with pytest.raises(EvaluationError, match="no models"):
            build_context(s, [])
        run_training(
            s,
            ["logistic"],
            fast_training_config(version="2.0.0", maturity=timedelta(days=20)),
            tmp_path / "models",
        )
        s.commit()
        with pytest.raises(EvaluationError, match="different datasets"):
            build_context(s, ["logistic-regression-1.0.0", "logistic-regression-2.0.0"])
        # A new label changes the recorded dataset: evaluation must refuse, not drift.
        event = s.scalars(
            select(FraudLabel).where(FraudLabel.label == LabelValue.LEGITIMATE).limit(1)
        ).one()
        event.label = LabelValue.FRAUD
        event.fraud_type = FraudType.OTHER
        s.flush()
        with pytest.raises(EvaluationError, match="no longer be reproduced"):
            build_context(s, ["logistic-regression-1.0.0"])
        s.rollback()
    engine.dispose()


def test_pseudonyms_are_stable_and_one_way() -> None:
    event = uuid.UUID(int=5)
    assert pseudonym(event) == pseudonym(uuid.UUID(int=5)) != pseudonym(uuid.UUID(int=6))
    assert pseudonym(event).startswith("ex-") and str(event) not in pseudonym(event)


# ------------------------------------------------------------------ scenarios / cohorts
def test_scenario_report(ctx: EvaluationContext) -> None:
    model = ctx.model("gradient-boosting-1.0.0")
    report = scenario_report(ctx, model)
    names = [s["segment"] for s in report["segments"]]
    assert names == [s.name for s in SEGMENTS]
    for seg in report["segments"]:
        if seg["n"] == 0:
            assert seg["notes"] == ["no examples in this split"]
            continue
        if seg["population"] == "fraud_only":
            assert seg["legitimate"] == 0 and seg["fpr"] is None and seg["precision"] is None
            assert seg["fraud"] == seg["n"]
            if seg["fraud"] < MIN_CLASS:
                assert any("indicative only" in n for n in seg["notes"])
        if seg["population"] == "legitimate_only":
            assert seg["fraud"] == 0 and seg["recall"] is None
        if seg["pr_auc"] is not None:
            assert seg["fraud"] >= MIN_CLASS and seg["legitimate"] >= MIN_CLASS
    by = {s["segment"]: s for s in report["segments"]}
    ato, stealthy = by["account_takeover"], by["stealthy_account_takeover"]
    assert stealthy.get("n", 0) <= ato.get("n", 0)
    lowered = scenario_report(ctx, model, threshold=0.0)
    assert all(s.get("recall") in (None, 1.0) for s in lowered["segments"])


def test_segment_metrics_small_sample_notes() -> None:
    y = np.array([1, 0, 0])
    m = segment_metrics(y, np.array([0.9, 0.8, 0.1]), 0.5, "mixed")
    assert m["recall"] == 1.0 and m["fpr"] == 0.5 and m["precision"] == 0.5
    assert m["pr_auc"] is None and len(m["notes"]) == 3
    assert m["recall_interval_95"] is not None and m["fpr_interval_95"] is not None


def test_cohort_report_flags_only_clearly_higher_fpr(ctx: EvaluationContext) -> None:
    model = ctx.model("logistic-regression-1.0.0")
    report = cohort_report(ctx, model)
    assert [c["cohort"] for c in report["cohorts"]] == [c.name for c in COHORTS]
    assert "no demographic inference" in report["method"]
    for c in report["cohorts"]:
        if c["legitimate_events"] < 30:
            assert not c["flagged_higher_fpr"] and c["notes"]
        if c["flagged_higher_fpr"]:
            assert c["fpr_interval_95"][0] > report["global_fpr"]
    # Flag everything: every cohort's FPR equals the global FPR, so nothing is flagged.
    everything = cohort_report(ctx, model, threshold=0.0)
    assert everything["global_fpr"] == 1.0
    assert not any(c["flagged_higher_fpr"] for c in everything["cohorts"])


def test_cohort_flag_fires_for_a_targeted_cohort(ctx: EvaluationContext) -> None:
    """Scores that flag every VPN event (and few others) must be caught by the cohort check."""
    base = ctx.model("logistic-regression-1.0.0")
    vectors = ctx.vectors("test")
    vpn = np.asarray([v.values.get("vpn_detected") is True for v in vectors])
    assert vpn.sum() >= 10
    biased = replace(base, scores={**base.scores, "test": np.where(vpn, 0.99, 0.0)})
    report = cohort_report(ctx, biased, min_legitimate=10)
    flags = {c["cohort"]: c["flagged_higher_fpr"] for c in report["cohorts"]}
    assert flags["vpn_users"] is True
    assert flags["new_account_users"] is False


def test_error_report_is_pseudonymised_with_context(ctx: EvaluationContext) -> None:
    model = ctx.model("gradient-boosting-1.0.0")
    report = error_report(ctx, model, threshold=0.3, limit=5)
    fps, fns = report["false_positives"], report["false_negatives"]
    y, p = ctx.labels("test"), model.scores["test"]
    assert fps["count"] == int(np.sum((y == 0) & (p >= 0.3)))
    assert fns["count"] == int(np.sum((y == 1) & (p < 0.3)))
    assert len(fps["examples"]) <= 5 and len(fns["examples"]) <= 5
    assert sum(fps["by_scenario"].values()) == fps["count"]
    assert sum(fns["by_fraud_type"].values()) == fns["count"]
    probs = [e["probability"] for e in fps["examples"]]
    assert probs == sorted(probs, reverse=True)
    text = json.dumps(report, default=str)
    for example in ctx.prepared.dataset.examples[:200]:
        assert str(example.event_id) not in text
        assert str(example.vector.user_id) not in text
    for e in fps["examples"]:
        assert e["ref"].startswith("ex-") and "vpn_detected" in e["context"]
    for e in fns["examples"]:
        assert "device_seen_before" in e["context"] and e["fraud_type"] is not None
    assert set(fps["traits"]) >= {"vpn", "new_device", "large_purchase"}
    everything = error_report(ctx, model, threshold=0.0, limit=0)
    assert everything["false_negatives"]["count"] == 0
    assert everything["false_positives"]["examples"] == []
    for t in everything["false_positives"]["traits"].values():
        assert t["lift"] is None or t["lift"] == pytest.approx(1.0)


# ------------------------------------------------------------------ walk-forward
def _provenance(label: LabelValue, at: datetime) -> LabelProvenance:
    return LabelProvenance(
        uuid.uuid4(),
        label,
        LabelSource.CHARGEBACK,
        at,
        FraudType.ACCOUNT_TAKEOVER if label is LabelValue.FRAUD else None,
        True,
    )


def test_label_as_of_uses_only_labels_known_at_the_cutoff() -> None:
    event = datetime(2026, 1, 1, tzinfo=UTC)
    cutoff = datetime(2026, 2, 1, tzinfo=UTC)
    maturity = timedelta(days=14)
    late_chargeback = LabelDecision(
        uuid.uuid4(),
        LabelStatus.POSITIVE,
        1,
        (_provenance(LabelValue.FRAUD, cutoff + timedelta(days=1)),),
    )
    assert label_as_of(late_chargeback, event, cutoff, maturity) == 0
    assert label_as_of(late_chargeback, event, cutoff + timedelta(days=2), maturity) == 1
    early = LabelDecision(
        uuid.uuid4(),
        LabelStatus.POSITIVE,
        1,
        (_provenance(LabelValue.FRAUD, event + timedelta(days=3)),),
    )
    assert label_as_of(early, event, cutoff, maturity) == 1
    # Not matured by the cutoff: unusable for training, however it is labelled.
    assert label_as_of(early, cutoff - timedelta(days=5), cutoff, maturity) is None
    unlabelled = LabelDecision(uuid.uuid4(), LabelStatus.NEGATIVE_IMPLICIT, 0, ())
    assert label_as_of(unlabelled, event, cutoff, maturity) == 0


def test_walk_forward_temporal_boundaries(ctx: EvaluationContext) -> None:
    model = ctx.model("logistic-regression-1.0.0")
    result = walk_forward(ctx, model, FAST.walk_forward)
    folds = result["folds"]
    assert folds and result["maturity_days"] == 14
    evaluated = [f for f in folds if "test_metrics" in f]
    assert evaluated, [(f["train"], f.get("skipped")) for f in folds]
    times = [e.event_time for e in ctx.prepared.dataset.examples]
    for f in folds:
        train, val, test = f["train"], f["validation"], f["test"]
        assert train["end"] == val["start"] and val["end"] == test["start"]
        assert train["start"] < train["end"] < val["end"] < test["end"]
        train_end = datetime.fromisoformat(train["end"])
        assert train["rows"] <= sum(t < train_end for t in times)
        for part in (train, val, test):
            assert part["prevalence"] is None or 0 <= part["prevalence"] <= 1
    for f in evaluated:
        assert f["model"]["registered"] is False and "+fold" in f["model"]["retrained_as"]
        assert f["threshold"] == model.threshold
        assert set(f["test_metrics"]) >= {"pr_auc", "recall", "fpr"}
    # Expanding window: training sets grow fold by fold.
    rows = [f["train"]["rows"] for f in folds]
    assert rows == sorted(rows)
    assert result["stability"]["pr_auc"]["folds"] <= len(evaluated)
    again = walk_forward(ctx, model, FAST.walk_forward)
    assert json.dumps(again, default=str) == json.dumps(result, default=str)


def test_walk_forward_training_labels_ignore_future_chargebacks(ctx: EvaluationContext) -> None:
    """Fold training fraud counts use as-of labels, so they can only be <= eventual counts."""
    result = walk_forward(ctx, ctx.model("logistic-regression-1.0.0"), FAST.walk_forward)
    examples = ctx.prepared.dataset.examples
    for f in result["folds"]:
        end = datetime.fromisoformat(f["train"]["end"])
        eventual = sum(int(ctx.prepared.y[i]) for i, e in enumerate(examples) if e.event_time < end)
        assert f["train"]["fraud"] <= eventual


# ------------------------------------------------------------------ drift
def test_drift_baseline_and_comparison(ctx: EvaluationContext) -> None:
    train = ctx.prepared.part("train")[0]
    baseline = build_baseline(train, TRACKED_FEATURES)
    assert set(baseline["features"]) == set(TRACKED_FEATURES)
    for spec in baseline["features"].values():
        assert sum(spec["reference"].values()) == pytest.approx(1.0)
        assert any(b.startswith("missing:") for b in spec["buckets"])
    assert baseline["features"]["transaction_amount_minor_units"]["kind"] == "numeric"
    assert baseline["features"]["network_type"]["kind"] == "categorical"
    same = compare_to_baseline(baseline, train)
    assert all(
        r["psi"] == pytest.approx(0, abs=1e-9) and r["status"] == "stable"
        for r in same["features"].values()
    )
    later = compare_to_baseline(baseline, ctx.prepared.part("test")[0])
    for r in later["features"].values():
        assert r["psi"] >= 0 and 0 <= r["js_distance"] <= 1
        assert r["status"] in ("stable", "moderate", "significant")
    with pytest.raises(ValueError, match="feature version"):
        compare_to_baseline({**baseline, "feature_version": "other"}, train)


# ------------------------------------------------------------------ reports
def test_full_report_is_reproducible(
    ctx_session: tuple[EvaluationContext, Session], tmp_path: Path
) -> None:
    ctx, _ = ctx_session
    model = ctx.model("gradient-boosting-1.0.0")
    first = reports.full_model_report(ctx, model, FAST, tmp_path / "a")
    second = reports.full_model_report(ctx, model, FAST, tmp_path / "b")
    expected = {
        "summary",
        "confidence",
        "thresholds",
        "calibration",
        "scenarios",
        "errors",
        "costs",
        "walk_forward",
        "drift_baseline",
    }
    assert set(first) == expected
    for name in expected:
        a, b = (json.loads(p.read_text()) for p in (first[name], second[name]))
        assert a.pop("generated_at") and b.pop("generated_at")
        assert a == b, name
        assert a["dataset_fingerprint"] == ctx.fingerprint and a["model"] == model.model_id
        assert a["settings"]["seed"] == 0 and a["evaluation_version"] == "evaluation-1.0.0"
    summary = json.loads(first["summary"].read_text())
    assert set(summary["reports"]) == expected - {"summary"}
    assert summary["lowest_test_brier_calibration"] in ("uncalibrated", "sigmoid", "isotonic")
    costs = json.loads(first["costs"].read_text())
    assert "NOT applied" in costs["manual_review"]["note"]
    compared = reports.compare(ctx, FAST)
    assert len(compared["pairwise"]) == 3 and set(compared["confidence"]) == set(REFS)
    text = json.dumps(compared)
    assert "winner" not in text and "universally" not in text


def test_calibration_persistence(ctx_session: tuple[EvaluationContext, Session]) -> None:
    ctx, session = ctx_session
    model = ctx.model("random-forest-1.0.0")
    report = reports.calibration(ctx, model, FAST)
    try:
        rows = reports.persist_calibrations(session, ctx, model, report)
        assert rows, {k: sorted(v) for k, v in report["methods"].items()}
        assert {r.method for r in rows} == {"sigmoid", "isotonic"}
        assert all(
            r.fitted_on == "validation" and r.dataset_fingerprint == ctx.fingerprint for r in rows
        )
        again = reports.persist_calibrations(session, ctx, model, report)  # idempotent
        assert [r.calibration_id for r in again] == [r.calibration_id for r in rows]
        stored = session.scalars(
            select(ModelCalibration).where(
                ModelCalibration.model_version_id == model.record.model_version_id
            )
        ).all()
        assert len(stored) == 2
        tampered: dict[str, Any] = json.loads(json.dumps(report))
        tampered["methods"]["sigmoid"]["calibrator"]["parameters"]["a"] += 1.0
        with pytest.raises(CalibrationConflictError, match="different sigmoid"):
            reports.persist_calibrations(session, ctx, model, tampered)
    finally:
        session.rollback()


def test_calibration_can_never_be_stored_as_fitted_on_test(
    ctx_session: tuple[EvaluationContext, Session],
) -> None:
    ctx, session = ctx_session
    model = ctx.model("random-forest-1.0.0")
    session.add(
        ModelCalibration(
            model_version_id=model.record.model_version_id,
            method="sigmoid",
            fitted_on="test",
            dataset_fingerprint=ctx.fingerprint,
            parameters={},
            metrics={},
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


# ------------------------------------------------------------------ generator realism
def test_no_single_feature_separates_synthetic_fraud(ctx: EvaluationContext) -> None:
    """Guard against generator giveaways: no single feature may (nearly) perfectly separate
    fraud from legitimate transactions on the training split."""
    matrix, y = ctx.prepared.part("train")
    ranked = univariate_separability(matrix, y)
    assert ranked and ranked[0]["auc"] < 0.92, ranked[:3]
    assert all(r["auc"] >= 0.5 for r in ranked)
    assert univariate_separability(matrix, np.zeros(len(y), dtype=int)) == []


# ------------------------------------------------------------------ PostgreSQL and SQLite
def test_evaluation_end_to_end_on_each_backend(any_engine: Engine, tmp_path: Path) -> None:
    factory = make_session_factory(any_engine)
    with session_scope(factory) as s:
        seed_synthetic_data(
            s,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=40,
            seed=5,
            reference_time=datetime(2026, 6, 1, tzinfo=UTC),
            activity_days=90,
            fraud_multiplier=2.0,
        )
        run_training(s, ["logistic"], fast_training_config(), tmp_path / "models")
    with session_scope(factory) as s:
        ctx = build_context(s, ["logistic-regression-1.0.0"])
        model = ctx.models[0]
        paths = reports.full_model_report(ctx, model, FAST, tmp_path / "eval", s)
        assert (tmp_path / "eval" / "summary.json").exists() and len(paths) == 9
    with session_scope(factory) as s:
        stored = s.scalars(select(ModelCalibration)).all()
        assert {r.method for r in stored} <= {"sigmoid", "isotonic"}
        assert all(r.fitted_on == "validation" for r in stored)
