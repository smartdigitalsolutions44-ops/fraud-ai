"""Application logging with defence-in-depth redaction of sensitive values."""

from __future__ import annotations

import contextlib
import logging
import sys
from typing import Any

from fraud_ai.security.redaction import redact_text, redact_value

LOGGER_NAME = "fraud_ai"


class RedactingFilter(logging.Filter):
    """Scrub card numbers, CVVs, passwords and tokens from log records.

    Code must never log these in the first place; this filter is a safety net.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Render the final message first so redaction sees exactly what would be emitted
        # (redacting the format string alone could drop placeholders or miss arguments).
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        if record.args:
            record.args = tuple(_redact_arg(a) for a in _as_tuple(record.args))
            with contextlib.suppress(TypeError, ValueError):
                message = str(record.msg) % record.args
        record.msg = redact_text(message)
        record.args = None
        return True


def _as_tuple(args: Any) -> tuple[Any, ...]:
    if isinstance(args, dict):
        return (args,)
    return tuple(args)


def _redact_arg(arg: Any) -> Any:
    if isinstance(arg, str):
        return redact_text(arg)
    if isinstance(arg, dict):
        return {k: redact_value(str(k), v) for k, v in arg.items()}
    return arg


def configure_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    if not any(getattr(h, "_fraud_ai", False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler._fraud_ai = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
    logger.propagate = True
    return logger


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name if name.startswith(LOGGER_NAME) else f"{LOGGER_NAME}.{name}")
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger
