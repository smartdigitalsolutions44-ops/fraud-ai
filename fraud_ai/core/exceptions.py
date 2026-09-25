"""Domain exceptions."""


class FraudAIError(Exception):
    """Base class for application errors."""


class EventValidationError(FraudAIError):
    """An event failed schema or business validation."""


class SecurityViolationError(EventValidationError):
    """An event contained data the platform must never store (PAN, CVV, password, ...)."""


class EventProcessingError(FraudAIError):
    """An event was valid but could not be applied to the fraud database."""
