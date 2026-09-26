"""Training pipeline: dataset -> time split -> train -> evaluate -> explain -> save -> register.

Every model in one run is trained on the *same* dataset and the *same* split, so their
results are comparable. Nothing here makes a decision: thresholds are evaluated, not
applied, and no transaction is blocked.
"""

from __future__ import annotations

import hashlib
import json
import platform
import statistics
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai import __version__
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import EventRecord, FraudLabel, ModelVersion
from fraud_ai.datasets.builder import TrainingDataset, TrainingDatasetBuilder
from fraud_ai.datasets.labels import LabelAvailabilityPolicy
from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION, EventKind, get_feature_set
from fraud_ai.models.estimators import SPECS, BaselineModel
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.models.metrics import (
    DEFAULT_THRESHOLDS,
    evaluate_scores,
    select_threshold,
    threshold_analysis,
)
from fraud_ai.models.preprocessing import PREPROCESSING_VERSION
from fraud_ai.models.registry import get_model_version, register_model_version
from fraud_ai.models.splits import DatasetSplit, SplitConfig, time_ordered_split
from fraud_ai.utils.logging import get_logger
from fraud_ai.utils.time import ensure_utc, utcnow

log = get_logger(__name__)
PIPELINE_VERSION = "training-pipeline-1.0.0"
MIN_TEST_POSITIVES = 30


class TrainingError(FraudAIError):
    pass


@dataclass(frozen=True)
class TrainingConfig:
    start: datetime | None = None
    end: datetime | None = None
    label_cutoff: datetime | None = None
    maturity: timedelta = timedelta(days=30)
    implicit_negatives: bool = False
    kinds: tuple[EventKind, ...] = (EventKind.TRANSACTION,)
    split: SplitConfig = field(default_factory=SplitConfig)
    seed: int = 42
    imbalance: str = "class_weight"
    threshold: float = 0.5
    version: str = "1.0.0"
    feature_version: str = DEFAULT_FEATURE_VERSION
    use_snapshots: bool = False
    persist_snapshots: bool = False
    # Per model kind, e.g. {"random-forest": {"n_estimators": 100}}; recorded with the model.
    hyperparameters: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolvedWindow:
    start: datetime
    end: datetime
    label_cutoff: datetime


def resolve_window(session: Session, config: TrainingConfig) -> ResolvedWindow:
    """Defaults: cutoff = the latest moment the database knows about (last event or label);
    end = cutoff - maturity (so *every* example, fraud or not, has had the same time for its
    label to arrive); start = earliest event."""
    first, last = session.execute(
        select(func.min(EventRecord.occurred_at), func.max(EventRecord.occurred_at))
    ).one()
    if first is None:
        raise TrainingError("no events in the database")
    last_label = session.scalar(select(func.max(FraudLabel.labelled_at)))
    known = max(ensure_utc(last), ensure_utc(last_label)) if last_label else ensure_utc(last)
    cutoff = ensure_utc(config.label_cutoff or known)
    end = ensure_utc(config.end or cutoff - config.maturity)
    start = ensure_utc(config.start or first)
    if end <= start:
        raise TrainingError(
            "training window is empty (end <= start); seed more history or lower --maturity-days"
        )
    return ResolvedWindow(start, end, cutoff)


def dataset_fingerprint(ds: TrainingDataset, kinds: Sequence[EventKind]) -> str:
    payload = {
        "feature_version": ds.feature_version,
        "catalogue_fingerprint": get_feature_set(ds.feature_version).fingerprint(),
        "label_policy": ds.policy.describe(),
        "kinds": sorted(k.value for k in kinds),
        "range": [ds.start.isoformat(), ds.end.isoformat()],
        "rows": sorted(
            [str(e.event_id), e.feature_hash, d.label]
            for e, d in zip(ds.examples, ds.labels, strict=True)
        ),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def environment() -> dict[str, str]:
    versions = {}
    for dist in ("scikit-learn", "numpy", "scipy", "joblib", "sqlalchemy", "pydantic"):
        try:
            versions[dist] = metadata.version(dist)
        except metadata.PackageNotFoundError:  # pragma: no cover
            versions[dist] = "not installed"
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "fraud_ai": __version__,
        **versions,
    }


@dataclass
class PreparedData:
    dataset: TrainingDataset
    fingerprint: str
    matrix: ModelMatrix
    y: npt.NDArray[np.int_]
    split: DatasetSplit
    window: ResolvedWindow
    kinds: tuple[EventKind, ...]

    def part(self, name: str) -> tuple[ModelMatrix, npt.NDArray[np.int_]]:
        idx = list(getattr(self.split, name))
        return self.matrix.take(idx), self.y[idx]

    def summary(self) -> dict[str, Any]:
        parts = {}
        for name in ("train", "validation", "test"):
            idx = list(getattr(self.split, name))
            positives = int(self.y[idx].sum())
            parts[name] = {
                "rows": len(idx),
                "positives": positives,
                "prevalence": positives / len(idx),
                "start": self.split.boundaries[f"{name}_start"],
                "end": self.split.boundaries[f"{name}_end"],
            }
        return {
            "dataset_fingerprint": self.fingerprint,
            "examples": len(self.y),
            "positives": int(self.y.sum()),
            "prevalence": float(self.y.mean()),
            "kinds": [k.value for k in self.kinds],
            "window": {
                "start": self.window.start.isoformat(),
                "end": self.window.end.isoformat(),
                "label_cutoff": self.window.label_cutoff.isoformat(),
            },
            "label_policy": self.dataset.policy.describe(),
            "excluded": len(self.dataset.excluded),
            "splits": parts,
        }


def prepare_data(session: Session, config: TrainingConfig) -> PreparedData:
    window = resolve_window(session, config)
    policy = LabelAvailabilityPolicy(
        label_cutoff=window.label_cutoff,
        maturity=config.maturity,
        implicit_negatives=config.implicit_negatives,
    )
    ds = TrainingDatasetBuilder(session, policy, config.feature_version).build(
        window.start,
        window.end,
        kinds=config.kinds,
        use_snapshots=config.use_snapshots,
        persist_snapshots=config.persist_snapshots,
    )
    if not ds.examples:
        raise TrainingError("the dataset builder returned no labelled examples")
    # X comes from feature values only; ids, timestamps and labels stay on the examples.
    matrix = ModelMatrix.from_vectors([e.vector for e in ds.examples], config.feature_version)
    y = np.asarray(ds.y(), dtype=int)
    split = time_ordered_split(
        [e.event_time for e in ds.examples], [e.event_id for e in ds.examples], config.split
    )
    if len(np.unique(y[list(split.train)])) < 2:
        raise TrainingError("the training split must contain both fraud and legitimate examples")
    return PreparedData(
        ds, dataset_fingerprint(ds, config.kinds), matrix, y, split, window, config.kinds
    )


def overfitting_warnings(metrics: dict[str, dict[str, Any]]) -> list[str]:
    warnings = []
    train, val, test = (metrics[s].get("pr_auc") for s in ("train", "validation", "test"))
    for name in ("train", "validation", "test"):
        if metrics[name]["positives"] == 0:
            warnings.append(f"{name} split has no fraud examples: PR-AUC is undefined")
    if train is not None and test is not None:
        if train - test > 0.10:
            warnings.append(
                f"possible overfitting: train PR-AUC {train:.3f} vs test "
                f"{test:.3f} (gap {train - test:.3f})"
            )
        if train >= 0.99 and test < 0.95:
            warnings.append("train PR-AUC >= 0.99: the model may be memorising training data")
    if val is not None and test is not None and abs(val - test) > 0.15:
        warnings.append(
            f"validation PR-AUC {val:.3f} and test {test:.3f} differ by more than "
            "0.15: performance is unstable across time periods"
        )
    if metrics["test"]["positives"] < MIN_TEST_POSITIVES:
        warnings.append(
            f"only {metrics['test']['positives']} fraud examples in test: "
            "metrics have wide uncertainty"
        )
    return warnings


def measure_inference(
    model: BaselineModel, matrix: ModelMatrix, repeats: int = 100
) -> dict[str, float]:
    """Model-only latency (preprocessing + estimator); database time is excluded."""
    n = len(matrix)
    singles = []
    for i in range(min(repeats, n)):
        row = matrix.take([i])
        started = time.perf_counter()
        model.predict_proba(row)
        singles.append(time.perf_counter() - started)
    started = time.perf_counter()
    model.predict_proba(matrix)
    batch = time.perf_counter() - started
    singles.sort()
    return {
        "single_event_p50_ms": 1000 * statistics.median(singles),
        "single_event_p95_ms": 1000 * singles[int(0.95 * (len(singles) - 1))],
        "batch_rows": n,
        "batch_seconds": batch,
        "batch_rows_per_second": n / batch if batch > 0 else float("inf"),
    }


@dataclass
class ModelResult:
    model: BaselineModel
    metrics: dict[str, Any]
    warnings: list[str]
    explanation: dict[str, Any]
    timings: dict[str, float]
    artifact_path: Path | None = None
    artifact_sha256: str | None = None
    registered: ModelVersion | None = None

    @property
    def model_id(self) -> str:
        return self.model.model_id


def train_and_evaluate(prepared: PreparedData, kind: str, config: TrainingConfig) -> ModelResult:
    model = BaselineModel(
        SPECS[kind],
        config.version,
        seed=config.seed,
        imbalance=config.imbalance,
        feature_version=config.feature_version,
        hyperparameters=config.hyperparameters.get(kind),
    )
    train_m, train_y = prepared.part("train")
    started = time.perf_counter()
    model.train(train_m, train_y)
    wall = time.perf_counter() - started
    scores = {
        name: model.predict_proba(prepared.part(name)[0])
        for name in ("train", "validation", "test")
    }
    labels = {name: prepared.part(name)[1] for name in scores}
    by_split = {
        name: evaluate_scores(labels[name], scores[name], config.threshold) for name in scores
    }
    selected = select_threshold(labels["validation"], scores["validation"])
    metrics: dict[str, Any] = {
        **by_split,
        "evaluation_threshold": config.threshold,
        "threshold_analysis": {
            name: threshold_analysis(labels[name], scores[name], DEFAULT_THRESHOLDS).to_list()
            for name in ("validation", "test")
        },
        "validation_selected_threshold": selected,
        "test_at_validation_selected_threshold": (
            evaluate_scores(labels["test"], scores["test"], selected) if selected else None
        ),
    }
    warnings = overfitting_warnings(by_split)
    val_m, val_y = prepared.part("validation")
    explanation = model.explain(val_m, val_y)
    timings = {
        "train_seconds": model.train_seconds or wall,
        "train_wall_seconds": wall,
        **measure_inference(model, prepared.part("test")[0]),
    }
    return ModelResult(model, metrics, warnings, explanation, timings)


def training_manifest(
    prepared: PreparedData, result: ModelResult, config: TrainingConfig
) -> dict[str, Any]:
    return {
        "pipeline_version": PIPELINE_VERSION,
        "created_at": utcnow().isoformat(),
        "environment": environment(),
        "seed": config.seed,
        "model": result.model.manifest(),
        "dataset": prepared.summary(),
        "split": config.split.describe(),
        "evaluation_threshold": config.threshold,
        "imbalance": config.imbalance,
        "timings": result.timings,
        "warnings": result.warnings,
        "explanation": result.explanation,
        "note": "Metrics computed on the configured dataset. If that dataset is synthetic, "
        "the results describe synthetic data only.",
    }


def check_version_free(session: Session, kind: str, version: str, model_directory: Path) -> None:
    name = SPECS[kind].model_name
    if get_model_version(session, name, version) is not None:
        raise TrainingError(f"{name}-{version} is already registered; choose a new --version")
    if (model_directory / f"{name}-{version}").exists():
        raise TrainingError(f"{model_directory / f'{name}-{version}'} already exists")


@dataclass
class TrainingRun:
    prepared: PreparedData
    results: list[ModelResult]
    config: TrainingConfig


def run_training(
    session: Session,
    kinds: Sequence[str],
    config: TrainingConfig,
    model_directory: Path,
    *,
    register: bool = True,
) -> TrainingRun:
    unknown = set(kinds) - set(SPECS)
    if unknown:
        raise TrainingError(f"unknown model kinds {sorted(unknown)}")
    for kind in kinds:  # fail before any expensive work
        check_version_free(session, kind, config.version, model_directory)
    prepared = prepare_data(session, config)
    log.info(
        "training %s on %d examples (%d fraud)",
        ",".join(kinds),
        len(prepared.y),
        int(prepared.y.sum()),
    )
    fs = get_feature_set(config.feature_version)
    results = []
    for kind in kinds:
        result = train_and_evaluate(prepared, kind, config)
        path = model_directory / result.model_id
        result.artifact_sha256 = result.model.save(path)
        result.artifact_path = path
        if register:
            sizes = prepared.split.sizes()
            result.registered = register_model_version(
                session,
                model_name=result.model.model_name,
                model_version=result.model.version,
                training_timestamp=utcnow(),
                training_dataset_version=f"dataset-{prepared.fingerprint[:16]}",
                feature_version=config.feature_version,
                model_path=str(path),
                metrics={
                    **result.metrics,
                    "timings": result.timings,
                    "warnings": result.warnings,
                    "explanation": result.explanation,
                },
                algorithm=result.model.spec.algorithm,
                notes="baseline; metrics describe the configured (possibly synthetic) dataset",
                dataset_fingerprint=prepared.fingerprint,
                feature_catalogue_fingerprint=fs.fingerprint(),
                preprocessing_version=PREPROCESSING_VERSION,
                train_rows=sizes["train"],
                validation_rows=sizes["validation"],
                test_rows=sizes["test"],
                random_seed=config.seed,
                hyperparameters=result.model.hyperparameters,
                training_manifest=training_manifest(prepared, result, config),
                artifact_sha256=result.artifact_sha256,
                default_threshold=config.threshold,
            )
        results.append(result)
    return TrainingRun(prepared, results, config)


def config_from_manifest(manifest: dict[str, Any]) -> TrainingConfig:
    """Rebuild the exact dataset/split configuration a model was trained with."""
    ds = manifest["dataset"]
    split = manifest["split"]
    split_config = (
        SplitConfig(
            train_end=datetime.fromisoformat(split["train_end"]),
            validation_end=datetime.fromisoformat(split["validation_end"]),
        )
        if split["strategy"] == "date"
        else SplitConfig(split["train_fraction"], split["validation_fraction"])
    )
    policy = ds["label_policy"]
    return TrainingConfig(
        start=datetime.fromisoformat(ds["window"]["start"]),
        end=datetime.fromisoformat(ds["window"]["end"]),
        label_cutoff=datetime.fromisoformat(ds["window"]["label_cutoff"]),
        maturity=timedelta(days=policy["maturity_days"]),
        implicit_negatives=policy["implicit_negatives"],
        kinds=tuple(EventKind(k) for k in ds["kinds"]),
        split=split_config,
        seed=manifest["seed"],
        imbalance=manifest["imbalance"],
        threshold=manifest["evaluation_threshold"],
        feature_version=manifest["model"]["feature_version"],
    )


@dataclass
class Reevaluation:
    model: ModelVersion
    prepared: PreparedData
    metrics: dict[str, Any]
    dataset_matches: bool
    reproduced: bool


def reevaluate(session: Session, model: ModelVersion) -> Reevaluation:
    """Rebuild the model's recorded dataset and split, reload the verified artefact and
    recompute its metrics. Reports whether data and metrics still match training."""
    from fraud_ai.models.scoring import load_registered_model

    if not model.training_manifest:
        raise TrainingError(f"{model.model_name}-{model.model_version} has no training manifest")
    config = config_from_manifest(model.training_manifest)
    prepared = prepare_data(session, config)
    loaded = load_registered_model(model)
    threshold = model.default_threshold if model.default_threshold is not None else 0.5
    metrics: dict[str, Any] = {}
    for name in ("train", "validation", "test"):
        matrix, y = prepared.part(name)
        metrics[name] = evaluate_scores(y, loaded.predict_proba(matrix), threshold)
    test_m, test_y = prepared.part("test")
    metrics["threshold_analysis"] = {
        "test": threshold_analysis(test_y, loaded.predict_proba(test_m)).to_list()
    }
    stored = (model.metrics or {}).get("test", {})
    reproduced = all(
        stored.get(k) == metrics["test"].get(k)
        for k in ("pr_auc", "roc_auc", "tp", "fp", "tn", "fn")
    )
    return Reevaluation(
        model, prepared, metrics, prepared.fingerprint == model.dataset_fingerprint, reproduced
    )
