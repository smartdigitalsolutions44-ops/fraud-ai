"""Deterministic, serialisable preprocessing from raw feature values to a numeric matrix.

The three missing reasons from Stage 2 are preserved rather than collapsed:

* **numeric** features become a value column (optionally signed-log transformed, imputed
  with the *training* median, optionally standardised) plus one 0/1 indicator column per
  missing reason (``<name>__unknown``, ``<name>__not_observed``, ``<name>__not_applicable``);
* **boolean** features become one-hot columns ``true``/``false``/``unknown``/
  ``not_observed``/``not_applicable``;
* **categorical** features become one-hot columns over the declared categories (or the
  training categories for open vocabularies), an ``__other__`` bucket for unseen values,
  and the three missing reasons.

Columns that are constant on the training data are dropped (recorded, deterministic). The
fitted state is plain JSON and is saved next to the model, so exactly the same
transformation is applied after loading. Column order follows the feature-set order.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import numpy.typing as npt

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.features.definitions import FeatureType, get_feature_set
from fraud_ai.features.vector import MissingReason
from fraud_ai.models.matrix import FeatureVersionMismatchError, ModelMatrix

PREPROCESSING_VERSION = "preprocessing-1.0.0"
SUPPORTED_PREPROCESSING_VERSIONS = frozenset({PREPROCESSING_VERSION})
REASONS = tuple(r.value for r in MissingReason)
OTHER = "__other__"
# Heavy-tailed units that benefit from sign(x)*log1p(|x|) for linear models.
LOG_UNITS = frozenset({"count", "days", "hours", "minutes", "minor currency units", "ratio"})


class PreprocessingError(FraudAIError):
    pass


@dataclass(frozen=True)
class PreprocessingConfig:
    missing_indicators: bool = True
    log_transform: bool = False
    standardize: bool = False
    drop_constant_columns: bool = True
    version: str = PREPROCESSING_VERSION


def _slog(x: float) -> float:
    return math.copysign(math.log1p(abs(x)), x)


class Preprocessor:
    def __init__(self, config: PreprocessingConfig, feature_version: str) -> None:
        if config.version not in SUPPORTED_PREPROCESSING_VERSIONS:
            raise PreprocessingError(f"unsupported preprocessing version {config.version!r}")
        self.config = config
        self.feature_version = feature_version
        self.catalogue_fingerprint = get_feature_set(feature_version).fingerprint()
        self.state: dict[str, Any] | None = None

    # ------------------------------------------------------------------ fitting
    def fit(self, matrix: ModelMatrix) -> Preprocessor:
        self._check(matrix)
        fs = get_feature_set(self.feature_version)
        specs: list[dict[str, Any]] = []
        for j, d in enumerate(fs.definitions):
            column = [row[j] for row in matrix.values]
            if d.dtype in (FeatureType.FLOAT, FeatureType.INTEGER):
                log = self.config.log_transform and d.units in LOG_UNITS
                observed = [self._num(v, log) for v in column if v is not None]
                median = float(np.median(observed)) if observed else 0.0
                filled = [self._num(v, log) if v is not None else median for v in column]
                mean = float(np.mean(filled)) if filled else 0.0
                std = float(np.std(filled)) if filled else 0.0
                specs.append(
                    {
                        "name": d.name,
                        "kind": "numeric",
                        "log": log,
                        "median": median,
                        "mean": mean,
                        "std": std if std > 0 else 1.0,
                        "no_observed_values": not observed,
                    }
                )
            elif d.dtype is FeatureType.BOOLEAN:
                specs.append({"name": d.name, "kind": "boolean"})
            else:
                categories = (
                    list(d.allowed_values)
                    if d.allowed_values is not None
                    else sorted({str(v) for v in column if v is not None})
                )
                specs.append({"name": d.name, "kind": "categorical", "categories": categories})
        self.state = {"specs": specs, "columns": [], "dropped": []}
        full = self._columns_for(specs)
        raw = self._raw_transform(matrix, specs)
        keep = list(range(len(full)))
        dropped: list[str] = []
        if self.config.drop_constant_columns and len(matrix) > 0:
            keep = [i for i in range(len(full)) if not np.all(raw[:, i] == raw[0, i])]
            dropped = [full[i] for i in range(len(full)) if i not in set(keep)]
        self.state = {
            "specs": specs,
            "columns": [full[i] for i in keep],
            "dropped": dropped,
            "keep_indices": keep,
        }
        return self

    @staticmethod
    def _num(value: Any, log: bool) -> float:
        x = float(value)
        return _slog(x) if log else x

    def _columns_for(self, specs: list[dict[str, Any]]) -> list[str]:
        cols: list[str] = []
        for spec in specs:
            name = spec["name"]
            if spec["kind"] == "numeric":
                cols.append(name)
                if self.config.missing_indicators:
                    cols += [f"{name}__{r}" for r in REASONS]
            elif spec["kind"] == "boolean":
                cols += [f"{name}={v}" for v in ("true", "false", *REASONS)]
            else:
                cols += [f"{name}={c}" for c in (*spec["categories"], OTHER, *REASONS)]
        return cols

    # ------------------------------------------------------------------ transform
    def transform(self, matrix: ModelMatrix) -> npt.NDArray[np.float64]:
        if self.state is None:
            raise PreprocessingError("preprocessor is not fitted")
        self._check(matrix)
        raw = self._raw_transform(matrix, self.state["specs"])
        return raw[:, self.state["keep_indices"]]

    def _raw_transform(
        self, matrix: ModelMatrix, specs: list[dict[str, Any]]
    ) -> npt.NDArray[np.float64]:
        rows: list[list[float]] = []
        for values, missing in zip(matrix.values, matrix.missing, strict=True):
            out: list[float] = []
            for j, spec in enumerate(specs):
                value, reason = values[j], missing[j]
                reason_value = reason.value if reason is not None else None
                if spec["kind"] == "numeric":
                    x = self._num(value, spec["log"]) if value is not None else spec["median"]
                    if self.config.standardize:
                        x = (x - spec["mean"]) / spec["std"]
                    out.append(x)
                    if self.config.missing_indicators:
                        out += [1.0 if reason_value == r else 0.0 for r in REASONS]
                elif spec["kind"] == "boolean":
                    token = reason_value if value is None else ("true" if value else "false")
                    out += [1.0 if token == v else 0.0 for v in ("true", "false", *REASONS)]
                else:
                    cats = spec["categories"]
                    if value is None:
                        token = reason_value
                    else:
                        token = str(value) if str(value) in cats else OTHER
                    out += [1.0 if token == c else 0.0 for c in (*cats, OTHER, *REASONS)]
            rows.append(out)
        width = len(self._columns_for(specs))
        return np.asarray(rows, dtype=np.float64).reshape(len(rows), width)

    def _check(self, matrix: ModelMatrix) -> None:
        if matrix.feature_version != self.feature_version:
            raise FeatureVersionMismatchError(
                f"matrix is {matrix.feature_version}, preprocessor expects {self.feature_version}"
            )
        if matrix.catalogue_fingerprint != self.catalogue_fingerprint:
            raise FeatureVersionMismatchError("feature catalogue fingerprint changed")

    # ------------------------------------------------------------------ introspection
    @property
    def output_columns(self) -> list[str]:
        if self.state is None:
            raise PreprocessingError("preprocessor is not fitted")
        return list(self.state["columns"])

    def base_feature(self, column: str) -> str:
        return column.split("__")[0].split("=")[0]

    # ------------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        if self.state is None:
            raise PreprocessingError("preprocessor is not fitted")
        return {
            "config": asdict(self.config),
            "feature_version": self.feature_version,
            "catalogue_fingerprint": self.catalogue_fingerprint,
            "feature_names": list(get_feature_set(self.feature_version).names),
            "state": self.state,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Preprocessor:
        config = PreprocessingConfig(**data["config"])
        if config.version not in SUPPORTED_PREPROCESSING_VERSIONS:
            raise PreprocessingError(
                f"model uses preprocessing {config.version!r}; this build supports "
                f"{sorted(SUPPORTED_PREPROCESSING_VERSIONS)}"
            )
        version = data["feature_version"]
        fs = get_feature_set(version)
        if data["catalogue_fingerprint"] != fs.fingerprint():
            raise FeatureVersionMismatchError(
                f"model was trained on a different {version} catalogue "
                f"({data['catalogue_fingerprint'][:12]} != {fs.fingerprint()[:12]})"
            )
        if tuple(data["feature_names"]) != fs.names:
            raise FeatureVersionMismatchError("feature order differs from the feature set")
        pre = cls(config, version)
        pre.state = data["state"]
        return pre
