"""Training-dataset construction: point-in-time features (X) and separately resolved,
availability-checked labels (y). No model is trained here."""

from fraud_ai.datasets.builder import DatasetExample, TrainingDataset, TrainingDatasetBuilder
from fraud_ai.datasets.labels import (
    LabelAvailabilityPolicy,
    LabelDecision,
    LabelProvenance,
    LabelStatus,
    resolve_labels,
)

__all__ = [
    "DatasetExample",
    "LabelAvailabilityPolicy",
    "LabelDecision",
    "LabelProvenance",
    "LabelStatus",
    "TrainingDataset",
    "TrainingDatasetBuilder",
    "resolve_labels",
]
