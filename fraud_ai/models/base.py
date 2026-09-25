"""The contract every fraud model implements.

A model consumes numerical feature vectors (rows of ``feature_names``) produced by the
feature-engineering layer and outputs a fraud probability. It never makes the final
decision - that is the risk engine's job.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

FeatureMatrix = Sequence[Sequence[float]]
Labels = Sequence[int]


@dataclass(frozen=True)
class EvaluationResult:
    """Metrics are stored verbatim in ``model_versions.metrics``."""

    metrics: dict[str, float]
    n_samples: int
    threshold: float
    notes: dict[str, str] = field(default_factory=dict)


class FraudModel(ABC):
    """Abstract fraud model.

    Implementations must be deterministic given the same data and random seed, and must
    declare the exact ``feature_names``/``feature_version`` they were trained on so
    predictions can be reproduced and compared across versions.
    """

    name: str
    version: str
    feature_version: str
    feature_names: tuple[str, ...]

    @abstractmethod
    def train(self, features: FeatureMatrix, labels: Labels) -> None: ...

    @abstractmethod
    def predict_proba(self, features: FeatureMatrix) -> list[float]:
        """Return P(fraud) in [0, 1] for each row."""

    def predict(self, features: FeatureMatrix, threshold: float = 0.5) -> list[int]:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be within [0, 1]")
        return [int(p >= threshold) for p in self.predict_proba(features)]

    @abstractmethod
    def evaluate(
        self, features: FeatureMatrix, labels: Labels, threshold: float = 0.5
    ) -> EvaluationResult: ...

    @abstractmethod
    def save(self, path: Path) -> None: ...

    @classmethod
    @abstractmethod
    def load(cls, path: Path) -> FraudModel: ...
