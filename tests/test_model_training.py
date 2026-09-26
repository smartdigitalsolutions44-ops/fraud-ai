"""Training pipeline: split, train, evaluate, save, load, register, reproduce."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import ModelVersion
from fraud_ai.features.definitions import get_feature_set
from fraud_ai.models.estimators import (
    MANIFEST_FILE,
    SPECS,
    ArtifactIntegrityError,
    BaselineModel,
    ModelError,
)
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.models.preprocessing import PREPROCESSING_VERSION
from fraud_ai.models.registry import parse_model_ref, resolve_model
from fraud_ai.models.report import comparison_table, model_details, threshold_table
from fraud_ai.models.training import (
    TrainingError,
    dataset_fingerprint,
    overfitting_warnings,
    prepare_data,
    reevaluate,
    run_training,
)
from tests.conftest import fast_training_config
from tests.model_helpers import make_vectors

KINDS = ["logistic", "random-forest", "gradient-boosting"]


@dataclass
class Trained:
    db: Path
    models: Path
    run: object


@pytest.fixture(scope="module")
def trained(seeded_model_world: Path, tmp_path_factory: pytest.TempPathFactory) -> Trained:
    root = tmp_path_factory.mktemp("trained")
    db = root / "world.db"
    shutil.copy(seeded_model_world, db)
    engine = create_db_engine(f"sqlite:///{db}")
    with session_scope(make_session_factory(engine)) as s:
        run = run_training(s, KINDS, fast_training_config(), root / "models")
    engine.dispose()
    return Trained(db, root / "models", run)


@pytest.fixture
def db_session(trained: Trained) -> Iterator[Session]:
    engine = create_db_engine(f"sqlite:///{trained.db}")
    with make_session_factory(engine)() as s:
        yield s
        s.rollback()
    engine.dispose()


def test_all_models_trained_on_the_same_time_ordered_split(trained: Trained) -> None:
    run = trained.run
    prepared = run.prepared  # type: ignore[attr-defined]
    sizes = prepared.split.sizes()
    assert sum(sizes.values()) == len(prepared.y) and all(sizes.values())
    times = [e.event_time for e in prepared.dataset.examples]
    tr, va, te = (
        [times[i] for i in getattr(prepared.split, n)] for n in ("train", "validation", "test")
    )
    assert max(tr) < min(va) and max(va) < min(te)
    assert [r.model_id for r in run.results] == [  # type: ignore[attr-defined]
        "logistic-regression-1.0.0",
        "random-forest-1.0.0",
        "gradient-boosting-1.0.0",
    ]
    fps = {r.registered.dataset_fingerprint for r in run.results}  # type: ignore[attr-defined]
    assert fps == {prepared.fingerprint}


def test_registry_records_everything_needed_to_reproduce(db_session: Session) -> None:
    rows = db_session.scalars(select(ModelVersion).order_by(ModelVersion.model_name)).all()
    assert len(rows) == 3
    fs = get_feature_set()
    for m in rows:
        assert (
            m.feature_version == fs.version and m.feature_catalogue_fingerprint == fs.fingerprint()
        )
        assert m.preprocessing_version == PREPROCESSING_VERSION and m.random_seed == 42
        assert m.train_rows and m.validation_rows and m.test_rows and m.hyperparameters
        assert m.artifact_sha256 and len(m.artifact_sha256) == 64 and not m.active
        assert Path(m.model_path).name == f"{m.model_name}-{m.model_version}"
        manifest = m.training_manifest or {}
        env = manifest["environment"]
        assert {"python", "scikit-learn", "numpy", "scipy", "joblib"} <= set(env)
        assert manifest["seed"] == 42 and manifest["split"]["strategy"] == "fraction"
        assert manifest["dataset"]["dataset_fingerprint"] == m.dataset_fingerprint
        for split in ("train", "validation", "test"):
            metrics = m.metrics[split]
            assert {
                "precision",
                "recall",
                "f1",
                "roc_auc",
                "pr_auc",
                "fpr",
                "fnr",
                "tpr",
                "tnr",
                "confusion_matrix",
                "tp",
                "fp",
                "tn",
                "fn",
            } <= set(metrics)
            assert "accuracy" not in metrics
        assert len(m.metrics["threshold_analysis"]["test"]) >= 7
        assert {"train_seconds", "single_event_p50_ms", "batch_rows_per_second"} <= set(
            m.metrics["timings"]
        )
        assert m.metrics["explanation"]["method"]


def test_matrix_contains_only_features(trained: Trained) -> None:
    prepared = trained.run.prepared  # type: ignore[attr-defined]
    assert prepared.matrix.feature_names == get_feature_set().names
    model = trained.run.results[0].model  # type: ignore[attr-defined]
    bases = {model.preprocessor.base_feature(c) for c in model.preprocessor.output_columns}
    assert bases <= set(get_feature_set().names)
    for forbidden in (
        "event_id",
        "user_id",
        "occurred_at",
        "labelled_at",
        "feature_hash",
        "label",
        "transaction_id",
    ):
        assert all(forbidden != b for b in bases)


def test_artifacts_load_verified_and_predict_identically(trained: Trained) -> None:
    for result in trained.run.results:  # type: ignore[attr-defined]
        loaded = BaselineModel.load(result.artifact_path, result.artifact_sha256)
        matrix = trained.run.prepared.part("test")[0]  # type: ignore[attr-defined]
        assert np.array_equal(loaded.predict_proba(matrix), result.model.predict_proba(matrix))
        assert loaded.preprocessor.output_columns == result.model.preprocessor.output_columns
        assert json.loads((result.artifact_path / MANIFEST_FILE).read_text())["seed"] == 42


def test_tampered_or_incomplete_artifacts_are_never_loaded(
    trained: Trained, tmp_path: Path
) -> None:
    result = trained.run.results[0]  # type: ignore[attr-defined]
    copy = tmp_path / "copy"
    shutil.copytree(result.artifact_path, copy)
    with (copy / "estimator.joblib").open("ab") as fh:
        fh.write(b"\0")
    with pytest.raises(ArtifactIntegrityError, match="digest"):
        BaselineModel.load(copy, result.artifact_sha256)
    (copy / "preprocessor.json").unlink()
    with pytest.raises(ArtifactIntegrityError, match="missing"):
        BaselineModel.load(copy, result.artifact_sha256)
    with pytest.raises(ModelError, match="refusing to overwrite"):
        result.model.save(result.artifact_path)


def test_reproducible_training(trained: Trained, tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{trained.db}")
    with make_session_factory(engine)() as s:
        again = run_training(
            s, KINDS, fast_training_config(version="9.9.9"), tmp_path, register=False
        )
        s.rollback()
    engine.dispose()
    matrix = trained.run.prepared.part("test")[0]  # type: ignore[attr-defined]
    assert again.prepared.fingerprint == trained.run.prepared.fingerprint  # type: ignore[attr-defined]
    for first, second in zip(trained.run.results, again.results, strict=True):  # type: ignore[attr-defined]
        assert np.array_equal(first.model.predict_proba(matrix), second.model.predict_proba(matrix))
        assert first.metrics["test"] == second.metrics["test"]


def test_existing_version_is_never_overwritten(db_session: Session, trained: Trained) -> None:
    with pytest.raises(TrainingError, match="already registered"):
        run_training(db_session, ["logistic"], fast_training_config(), trained.models)
    with pytest.raises(TrainingError, match="unknown model kinds"):
        run_training(db_session, ["neural-net"], fast_training_config(), trained.models)


def test_reevaluation_reproduces_stored_metrics(db_session: Session) -> None:
    for name in ("logistic-regression-1.0.0", "gradient-boosting-1.0.0"):
        result = reevaluate(db_session, resolve_model(db_session, name))
        assert result.dataset_matches and result.reproduced


def test_reports_and_references(db_session: Session) -> None:
    rows = db_session.scalars(select(ModelVersion)).all()
    table = comparison_table(rows)
    assert "PR-AUC" in table and "SYNTHETIC" in table and "DIFFERENT" not in table
    details = model_details(rows[0])
    assert "sha256" in details and "not used by any decision" in details
    assert "FPR" in threshold_table(rows[0].metrics["threshold_analysis"]["test"])
    assert parse_model_ref("random-forest-1.0.0") == ("random-forest", "1.0.0")
    assert parse_model_ref("random-forest:1.0.0") == ("random-forest", "1.0.0")
    for bad in ("nodash", "-1.0.0"):
        with pytest.raises(Exception):  # noqa: B017
            parse_model_ref(bad)


def test_explanations(trained: Trained) -> None:
    by_kind = {r.model.spec.kind: r.explanation for r in trained.run.results}  # type: ignore[attr-defined]
    assert by_kind["logistic"]["top_positive"] and by_kind["logistic"]["top_negative"]
    assert by_kind["random-forest"]["top_features"][0]["importance"] > 0
    assert "permutation" in by_kind["gradient-boosting"]["method"]
    names = set(get_feature_set().names)
    for kind in ("random-forest", "gradient-boosting"):
        assert {f["feature"] for f in by_kind[kind]["top_features"]} <= names


def test_dataset_fingerprint_changes_with_labels(db_session: Session) -> None:
    prepared = prepare_data(db_session, fast_training_config())
    before = prepared.fingerprint
    prepared.dataset.labels[0] = type(prepared.dataset.labels[0])(
        prepared.dataset.labels[0].event_id,
        prepared.dataset.labels[0].status,
        1 - (prepared.dataset.labels[0].label or 0),
    )
    assert dataset_fingerprint(prepared.dataset, prepared.kinds) != before


def test_overfitting_warnings_are_not_hidden() -> None:
    def m(pr: float | None, pos: int = 50) -> dict[str, object]:
        return {"pr_auc": pr, "positives": pos}

    warnings = overfitting_warnings({"train": m(1.0), "validation": m(0.9), "test": m(0.6)})
    assert any("overfitting" in w for w in warnings)
    assert any("memorising" in w for w in warnings)
    assert any("unstable" in w for w in warnings)
    small = overfitting_warnings({"train": m(0.8), "validation": m(0.8), "test": m(None, 0)})
    assert any("no fraud" in w for w in small) and any("uncertainty" in w for w in small)
    assert overfitting_warnings({"train": m(0.8), "validation": m(0.78), "test": m(0.77)}) == []


def test_imbalance_strategies_and_input_checks() -> None:
    vectors, labels = make_vectors(60)
    matrix = ModelMatrix.from_vectors(vectors)
    for imbalance in ("class_weight", "oversample", "none"):
        model = BaselineModel(SPECS["logistic"], imbalance=imbalance)
        model.train(matrix, labels)
        proba = model.predict_proba(matrix)
        assert proba.shape == (60,) and np.all((proba >= 0) & (proba <= 1))
        assert set(model.predict(matrix, 0.5)) <= {0, 1}
        assert model.evaluate(matrix, labels).metrics["n"] == 60
    with pytest.raises(ModelError):
        BaselineModel(SPECS["logistic"], imbalance="smote")
    model = BaselineModel(SPECS["random-forest"])
    with pytest.raises(ModelError, match="both classes"):
        model.train(matrix, [0] * 60)
    with pytest.raises(ModelError, match="length"):
        model.train(matrix, [0, 1])
    for call in (
        lambda: model.predict_proba(matrix),
        model.explain,
        lambda: model.save(Path("/nonexistent")),
    ):
        with pytest.raises(ModelError, match="not trained"):
            call()
    with pytest.raises(ValueError):
        BaselineModel(SPECS["logistic"]).predict(matrix, threshold=2)
    hgb = BaselineModel(SPECS["gradient-boosting"], hyperparameters={"max_iter": 10})
    hgb.train(matrix, labels)
    assert hgb.explain()["top_features"] == []  # permutation needs labelled data
