"""Event ingestion: validation, sanitisation and persistence of incoming events."""

from fraud_ai.ingestion.processor import EventProcessor, ProcessResult

__all__ = ["EventProcessor", "ProcessResult"]
