"""Real-time scoring and risk-decision orchestration (Stage 8).

``FraudScoringService.score_event`` is the hot path: contract -> ingestion -> point-in-time
features -> cached, verified models -> calibration -> rules -> versioned policy ->
immutable assessment. The LLM (Stage 7) is never part of it.
"""

from fraud_ai.realtime.contract import EventContractError, parse_incoming
from fraud_ai.realtime.service import FraudScoringService, ScoringOutcome

__all__ = ["EventContractError", "FraudScoringService", "ScoringOutcome", "parse_incoming"]
