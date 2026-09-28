"""Application logging with defence-in-depth redaction of sensitive values."""

from __future__ import annotations

import contextlib
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from fraud_ai.security.redaction import redact_log_text, redact_value

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
        record.msg = redact_log_text(message)
        record.args = None
        return True


def _as_tuple(args: Any) -> tuple[Any, ...]:
    if isinstance(args, dict):
        return (args,)
    return tuple(args)


def _redact_arg(arg: Any) -> Any:
    if isinstance(arg, str):
        return redact_log_text(arg)
    if isinstance(arg, dict):
        return {k: redact_value(str(k), v) for k, v in arg.items()}
    return arg


class JsonFormatter(logging.Formatter):
    """One JSON object per line: time, level, logger and the (already redacted) message.
    Messages that are themselves JSON (the Stage 8 decision logs) are embedded as objects."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
        }
        try:
            parsed = json.loads(message) if message.startswith("{") else None
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            payload["event"] = parsed
        else:
            payload["message"] = message
        if record.exc_info:
            payload["exception"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, sort_keys=True, default=str)


def configure_logging(level: str = "INFO", fmt: str = "text") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    formatter: logging.Formatter = (
        JsonFormatter()
        if fmt == "json"
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    existing = [h for h in logger.handlers if getattr(h, "_fraud_ai", False)]
    for handler in existing:
        handler.setFormatter(formatter)
    if not existing:
        handler = logging.StreamHandler(sys.stderr)
        handler._fraud_ai = True  # type: ignore[attr-defined]
        handler.setFormatter(formatter)
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
    logger.propagate = True
    return logger


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name if name.startswith(LOGGER_NAME) else f"{LOGGER_NAME}.{name}")
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger
