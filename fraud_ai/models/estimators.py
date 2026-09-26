"""Baseline fraud models: logistic regression, random forest, gradient boosting.

All three share one implementation (:class:`BaselineModel`) that owns a fitted
:class:`Preprocessor` and a scikit-learn estimator. Gradient boosting uses
scikit-learn's ``HistGradientBoostingClassifier`` - no extra dependency.

Class imbalance: the default is **class weighting** (``balanced``), which reweights the
loss so rare fraud counts as much in total as the legitimate majority, without inventing
duplicate rows. Random oversampling of positives is available for controlled experiments
only (``imbalance="oversample"``) and is applied to the training split alone.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import numpy.typing as npt
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from threadpoolctl import ThreadpoolController

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION
from fraud_ai.models.base import EvaluationResult, FraudModel, Labels, Validation
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.models.metrics import evaluate_scores
from fraud_ai.models.preprocessing import PreprocessingConfig, Preprocessor

IMBALANCE_STRATEGIES = ("class_weight", "oversample", "none")
ESTIMATOR_FILE, PREPROCESSOR_FILE, MANIFEST_FILE = (
    "estimator.joblib",
    "preprocessor.json",
    "manifest.json",
)


class ModelError(FraudAIError):
    pass


class ArtifactIntegrityError(ModelError):
    """An artefact on disk does not match the digest recorded when it was trained."""


@dataclass(frozen=True)
class ModelSpec:
    kind: str
    model_name: str
    algorithm: str
    hyperparameters: dict[str, Any]
    preprocessing: PreprocessingConfig = field(default_factory=PreprocessingConfig)


SPECS: dict[str, ModelSpec] = {
    "logistic": ModelSpec(
        "logistic",
        "logistic-regression",
        "sklearn.LogisticRegression",
        {"C": 0.5, "max_iter": 5000, "solver": "lbfgs"},
        # Linear models need comparable scales: signed-log heavy tails, then standardise.
        PreprocessingConfig(log_transform=True, standardize=True),
    ),
    "random-forest": ModelSpec(
        "random-forest",
        "random-forest",
        "sklearn.RandomForestClassifier",
        {"n_estimators": 300, "min_samples_leaf": 3, "max_features": "sqrt", "n_jobs": 1},
    ),
    "gradient-boosting": ModelSpec(
        "gradient-boosting",
        "gradient-boosting",
        "sklearn.HistGradientBoostingClassifier",
        # early_stopping off: it would carve an unseeded random validation split out of the
        # (time-ordered) training data.
        {
            "learning_rate": 0.05,
            "max_iter": 300,
            "max_leaf_nodes": 15,
            "min_samples_leaf": 20,
            "l2_regularization": 1.0,
            "early_stopping": False,
        },
    ),
}
MODEL_KINDS = tuple(SPECS)

# Native thread pools (OpenMP/BLAS) are pinned to one thread for training *and* inference:
# it makes training bit-for-bit reproducible and avoids pathological oversubscription when
# several processes score concurrently (measured: HistGradientBoosting p95 latency went
# from ~8 ms to >3 s without it). The controller inspects the loaded libraries once, so
# applying the limit per call is cheap.
_THREADPOOLS = ThreadpoolController()


def single_threaded() -> Any:
    return _THREADPOOLS.limit(limits=1)


KIND_BY_NAME = {s.model_name: s.kind for s in SPECS.values()}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_digest(directory: Path) -> str:
    """Digest over the files that determine predictions."""
    lines = "".join(
        f"{name}:{_sha256(directory / name)}\n" for name in (ESTIMATOR_FILE, PREPROCESSOR_FILE)
    )
    return hashlib.sha256(lines.encode()).hexdigest()


class BaselineModel(FraudModel):
    def __init__(
        self,
        spec: ModelSpec,
        version: str = "1.0.0",
        *,
        seed: int = 42,
        imbalance: str = "class_weight",
        hyperparameters: dict[str, Any] | None = None,
        feature_version: str = DEFAULT_FEATURE_VERSION,
        oversample_ratio: float = 0.25,
    ) -> None:
        if imbalance not in IMBALANCE_STRATEGIES:
            raise ModelError(f"imbalance must be one of {IMBALANCE_STRATEGIES}")
        self.spec = spec
        self.model_name = spec.model_name
        self.version = version
        self.seed = seed
        self.imbalance = imbalance
        self.oversample_ratio = oversample_ratio
        self.feature_version = feature_version
        self.hyperparameters = {**spec.hyperparameters, **(hyperparameters or {})}
        self.preprocessor = Preprocessor(spec.preprocessing, feature_version)
        self.estimator: Any = None
        self.train_seconds: float | None = None

    @property
    def algorithm(self) -> str:
        return self.spec.algorithm

    # ------------------------------------------------------------------ estimator
    def _build(self) -> Any:
        weight = self.imbalance == "class_weight"
        hp = self.hyperparameters
        if self.spec.kind == "logistic":
            return LogisticRegression(
                **hp, class_weight="balanced" if weight else None, random_state=self.seed
            )
        if self.spec.kind == "random-forest":
            return RandomForestClassifier(
                **hp, class_weight="balanced_subsample" if weight else None, random_state=self.seed
            )
        return HistGradientBoostingClassifier(
            **hp, class_weight="balanced" if weight else None, random_state=self.seed
        )

    def _oversample(
        self, X: npt.NDArray[np.float64], y: npt.NDArray[np.int_]
    ) -> tuple[npt.NDArray[np.float64], npt.NDArray[np.int_]]:
        pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
        target = int(len(neg) * self.oversample_ratio)
        if len(pos) == 0 or target <= len(pos):
            return X, y
        rng = np.random.default_rng(self.seed)
        extra = rng.choice(pos, size=target - len(pos), replace=True)
        idx = np.concatenate([np.arange(len(y)), extra])
        return X[idx], y[idx]

    # ------------------------------------------------------------------ FraudModel
    def train(
        self, matrix: ModelMatrix, labels: Labels, validation: Validation | None = None
    ) -> None:
        # The scikit-learn baselines do not early-stop, so ``validation`` is not used.
        y = np.asarray(labels, dtype=int)
        if len(y) != len(matrix):
            raise ModelError("labels and matrix differ in length")
        if len(np.unique(y)) < 2:
            raise ModelError("training data must contain both classes")
        X = self.preprocessor.fit(matrix).transform(matrix)
        if self.imbalance == "oversample":
            X, y = self._oversample(X, y)
        self.estimator = self._build()
        started = time.perf_counter()
        with single_threaded():  # deterministic, and comparable timings
            self.estimator.fit(X, y)
        self.train_seconds = time.perf_counter() - started

    def transform(self, matrix: ModelMatrix) -> npt.NDArray[np.float64]:
        return self.preprocessor.transform(matrix)

    def predict_proba(self, matrix: ModelMatrix) -> npt.NDArray[np.float64]:
        if self.estimator is None:
            raise ModelError("model is not trained")
        X = self.transform(matrix)
        with single_threaded():
            proba = self.estimator.predict_proba(X)
        return np.asarray(proba[:, 1], dtype=np.float64)

    def evaluate(
        self, matrix: ModelMatrix, labels: Labels, threshold: float = 0.5
    ) -> EvaluationResult:
        metrics = evaluate_scores(labels, self.predict_proba(matrix), threshold)
        return EvaluationResult(metrics, len(matrix), threshold)

    # ------------------------------------------------------------------ explainability
    def explain(
        self, matrix: ModelMatrix | None = None, labels: Labels | None = None, top_k: int = 12
    ) -> dict[str, Any]:
        """Transparent inspection only - never used by any decision."""
        if self.estimator is None:
            raise ModelError("model is not trained")
        columns = self.preprocessor.output_columns
        if self.spec.kind == "logistic":
            coefs = [(c, float(w)) for c, w in zip(columns, self.estimator.coef_[0], strict=True)]
            coefs.sort(key=lambda cw: (cw[1], cw[0]))
            return {
                "method": "standardised logistic coefficients (log-odds per unit)",
                "top_positive": [
                    {"column": c, "coefficient": w} for c, w in reversed(coefs[-top_k:])
                ],
                "top_negative": [{"column": c, "coefficient": w} for c, w in coefs[:top_k]],
            }
        if self.spec.kind == "random-forest":
            scores = [float(v) for v in self.estimator.feature_importances_]
            method = "impurity (mean decrease in Gini); biased toward high-cardinality columns"
        else:
            if matrix is None or labels is None or len(np.unique(np.asarray(labels))) < 2:
                return {
                    "method": "permutation importance",
                    "note": "needs labelled data with both classes",
                    "top_features": [],
                }
            with single_threaded():
                result = permutation_importance(
                    self.estimator,
                    self.transform(matrix),
                    np.asarray(labels),
                    scoring="average_precision",
                    n_repeats=5,
                    random_state=self.seed,
                )
            scores = [float(v) for v in result.importances_mean]
            method = "permutation importance (drop in validation PR-AUC)"
        by_feature: dict[str, float] = {}
        for column, score in zip(columns, scores, strict=True):
            base = self.preprocessor.base_feature(column)
            by_feature[base] = by_feature.get(base, 0.0) + score
        ranked = sorted(by_feature.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
        return {
            "method": method,
            "top_features": [{"feature": f, "importance": s} for f, s in ranked],
        }

    # ------------------------------------------------------------------ persistence
    def manifest(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.version,
            "kind": self.spec.kind,
            "algorithm": self.spec.algorithm,
            "feature_version": self.feature_version,
            "catalogue_fingerprint": self.preprocessor.catalogue_fingerprint,
            "preprocessing": asdict(self.spec.preprocessing),
            "preprocessing_version": self.spec.preprocessing.version,
            "output_columns": len(self.preprocessor.output_columns),
            "hyperparameters": self.hyperparameters,
            "seed": self.seed,
            "imbalance": self.imbalance,
            "oversample_ratio": self.oversample_ratio,
        }

    def save(self, directory: Path) -> str:
        if self.estimator is None:
            raise ModelError("model is not trained")
        if directory.exists():
            raise ModelError(
                f"artefact directory {directory} already exists; refusing to overwrite"
            )
        directory.mkdir(parents=True)
        joblib.dump(self.estimator, directory / ESTIMATOR_FILE)
        (directory / PREPROCESSOR_FILE).write_text(self.preprocessor.to_json())
        digest = artifact_digest(directory)
        (directory / MANIFEST_FILE).write_text(
            json.dumps({**self.manifest(), "artifact_sha256": digest}, indent=2, sort_keys=True)
        )
        return digest

    @classmethod
    def load(cls, directory: Path, expected_sha256: str) -> BaselineModel:
        for name in (ESTIMATOR_FILE, PREPROCESSOR_FILE, MANIFEST_FILE):
            if not (directory / name).exists():
                raise ArtifactIntegrityError(f"{directory / name} is missing")
        actual = artifact_digest(directory)
        if actual != expected_sha256:
            # Never unpickle an artefact whose bytes differ from what was trained.
            raise ArtifactIntegrityError(
                f"{directory}: digest {actual[:12]} != recorded {expected_sha256[:12]}"
            )
        manifest = json.loads((directory / MANIFEST_FILE).read_text())
        spec = SPECS[manifest["kind"]]
        preprocessor = Preprocessor.from_dict(
            json.loads((directory / PREPROCESSOR_FILE).read_text())
        )
        if preprocessor.config != spec.preprocessing:
            raise ModelError("stored preprocessing configuration differs from the model spec")
        model = cls(
            spec,
            manifest["model_version"],
            seed=manifest["seed"],
            imbalance=manifest["imbalance"],
            hyperparameters=manifest["hyperparameters"],
            feature_version=manifest["feature_version"],
            oversample_ratio=manifest["oversample_ratio"],
        )
        model.preprocessor = preprocessor
        model.estimator = joblib.load(directory / ESTIMATOR_FILE)
        return model
