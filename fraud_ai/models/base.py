"""The contract every fraud model implements.

A model consumes a :class:`~fraud_ai.models.matrix.ModelMatrix` (point-in-time feature
values only - never identifiers, timestamps or labels) and outputs P(fraud). It never
makes a decision: thresholds are an evaluation setting and the risk engine owns decisions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt

from fraud_ai.models.matrix import ModelMatrix

Labels = Sequence[int] | npt.NDArray[np.int_]


@dataclass(frozen=True)
class EvaluationResult:
    """Metrics are stored verbatim in ``model_versions.metrics``."""

    metrics: dict[str, Any]
    n_samples: int
    threshold: float
    notes: dict[str, str] = field(default_factory=dict)


class FraudModel(ABC):
    """Abstract fraud model.

    Implementations must be deterministic given the same data, preprocessing,
    hyperparameters and random seed, and declare the feature version they were trained on.
    """

    model_name: str
    version: str
    feature_version: str

    @abstractmethod
    def train(self, matrix: ModelMatrix, labels: Labels) -> None: ...

    @abstractmethod
    def predict_proba(self, matrix: ModelMatrix) -> npt.NDArray[np.float64]:
        """Return P(fraud) in [0, 1] for each row."""

    def predict(self, matrix: ModelMatrix, threshold: float = 0.5) -> npt.NDArray[np.int_]:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be within [0, 1]")
        return (self.predict_proba(matrix) >= threshold).astype(int)

    @abstractmethod
    def evaluate(
        self, matrix: ModelMatrix, labels: Labels, threshold: float = 0.5
    ) -> EvaluationResult: ...

    @abstractmethod
    def save(self, directory: Path) -> str:
        """Write the artefact directory; return its integrity digest (SHA-256)."""

    @classmethod
    @abstractmethod
    def load(cls, directory: Path, expected_sha256: str) -> FraudModel:
        """Verify the digest *before* deserialising, then load."""
