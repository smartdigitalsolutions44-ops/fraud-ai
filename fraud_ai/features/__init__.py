"""Feature engineering: deterministic, versioned, point-in-time feature vectors.

Public API::

    extract_features(session, event_id, as_of_timestamp=None, feature_version=None)
    extract_training_features(session, start_time, end_time, feature_version=None)
    persist_snapshot(session, vector) / snapshot_features(session, event_id, ...)

See FEATURES.md for every feature and the point-in-time rules.
"""

from fraud_ai.features.batch import FeatureBatch, extract_training_features
from fraud_ai.features.definitions import (
    DEFAULT_FEATURE_VERSION,
    FEATURE_SETS,
    EventKind,
    FeatureCategory,
    FeatureDefinition,
    FeatureSet,
    FeatureType,
    get_feature_set,
)
from fraud_ai.features.extractor import extract_features, extract_many
from fraud_ai.features.snapshot import persist_snapshot, snapshot_features
from fraud_ai.features.vector import FraudFeatureVector, MissingReason

__all__ = [
    "DEFAULT_FEATURE_VERSION",
    "FEATURE_SETS",
    "EventKind",
    "FeatureBatch",
    "FeatureCategory",
    "FeatureDefinition",
    "FeatureSet",
    "FeatureType",
    "FraudFeatureVector",
    "MissingReason",
    "extract_features",
    "extract_many",
    "extract_training_features",
    "get_feature_set",
    "persist_snapshot",
    "snapshot_features",
]
