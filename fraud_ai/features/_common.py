"""Helpers shared by the feature-category modules."""

from __future__ import annotations

from fraud_ai.features.definitions import FeatureCategory, get_feature_set
from fraud_ai.features.vector import FeatureWriter, MissingReason

NA = MissingReason.NOT_APPLICABLE
NOT_OBSERVED = MissingReason.NOT_OBSERVED
UNKNOWN = MissingReason.UNKNOWN


def names(w: FeatureWriter, category: FeatureCategory) -> list[str]:
    fs = get_feature_set(w.feature_version)
    return [d.name for d in fs.by_category(category)]
