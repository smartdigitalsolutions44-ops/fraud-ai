"""Feature engineering (Stage 2).

Stage 1 ships only the feature catalogue: the agreed feature names, types and the stored
columns each will be derived from. Computation arrives in Stage 2.
"""

from fraud_ai.features.catalog import FEATURE_CATALOG, FEATURE_CATALOG_VERSION, FeatureSpec

__all__ = ["FEATURE_CATALOG", "FEATURE_CATALOG_VERSION", "FeatureSpec"]
