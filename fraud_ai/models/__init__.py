"""ML model interfaces, model-version registry and prediction storage.

No model is trained in Stage 1. Concrete models (logistic regression, random forest,
gradient-boosted trees, then neural networks) implement :class:`FraudModel` in later stages.
"""

from fraud_ai.models.base import EvaluationResult, FraudModel

__all__ = ["EvaluationResult", "FraudModel"]
