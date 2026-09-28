"""Detection and redaction of data the platform must never store or log.

Never stored/logged: full card numbers (PAN), CVV/CVC, PINs, passwords, raw authentication
secrets and tokens. Payment methods are referenced by a vault token reference only.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

REDACTED = "[REDACTED]"

# Keys (normalised: lowercase alphanumerics only) that must never carry stored values.
_EXACT_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "clientsecret",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "sessiontoken",
        "bearertoken",
        "authtoken",
        "apikey",
        "authorization",
        "cookie",
        "cvv",
        "cvv2",
        "cvc",
        "cvc2",
        "cid",
        "securitycode",
        "pin",
        "pinblock",
        "pan",
        "cardnumber",
        "ccnumber",
        "creditcardnumber",
        "primaryaccountnumber",
        "otp",
        "mfacode",
        "totp",
        "securityanswer",
        "privatekey",
    }
)
_SENSITIVE_SUFFIXES = ("password", "passwd", "secret", "apikey", "cardnumber", "privatekey")
# A vault token *reference* is the safe, intended way to reference a payment method.
_SAFE_KEYS = frozenset({"tokenreference", "paymenttokenreference"})

_PAN_CANDIDATE = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")
_KV_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|"
    r"cvv2?|cvc2?|pin|otp|authorization)\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)


def _normalise_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_key(key: str) -> bool:
    norm = _normalise_key(key)
    if norm in _SAFE_KEYS:
        return False
    return norm in _EXACT_SENSITIVE_KEYS or norm.endswith(_SENSITIVE_SUFFIXES)


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def contains_card_number(text: str) -> bool:
    return any(_is_pan(m.group(0)) for m in _PAN_CANDIDATE.finditer(text))


def _is_pan(candidate: str) -> bool:
    digits = re.sub(r"[ -]", "", candidate)
    return 13 <= len(digits) <= 19 and luhn_valid(digits)


# Stage 10 log hardening: credentials and references that must never reach a log line.
_TEXT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # Service API credentials: keep the public key id, drop the secret.
    (re.compile(r"\b(fak_[0-9a-f]{16})\.[A-Za-z0-9_-]{8,}"), rf"\1.{REDACTED}"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {REDACTED}"),
    # Request/callback signatures.
    (re.compile(r"\bv1=[0-9a-f]{64}\b"), f"v1={REDACTED}"),
    # Provider secrets and client secrets (e.g. Stripe sk_/rk_/whsec_, *_secret_*).
    (re.compile(r"\b(?:sk|rk|whsec)_(?:test_|live_)?[A-Za-z0-9]{8,}"), REDACTED),
    (re.compile(r"\b(?:pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+"), REDACTED),
    # Payment instrument tokens (references to cards held by the processor).
    (re.compile(r"\b(?:tok|pm|src|card)_[A-Za-z0-9]{6,}"), REDACTED),
    # Passwords embedded in URLs (database / redis).
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/@\s]*:)[^@\s]+@"), rf"\1{REDACTED}@"),
    # Raw IPv4 addresses (personal data); IPv6 is not pattern-matched (too ambiguous).
    (
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
        ),
        "[REDACTED-IP]",
    ),
)


def redact_text(text: str) -> str:
    """Redact card numbers and ``key=value`` secrets appearing in free text (also used on
    stored metadata, so it deliberately stays narrow)."""
    text = _PAN_CANDIDATE.sub(lambda m: REDACTED if _is_pan(m.group(0)) else m.group(0), text)
    return _KV_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def redact_log_text(text: str) -> str:
    """:func:`redact_text` plus the Stage 10 log rules: API credentials, bearer tokens,
    signatures, provider secrets, payment tokens, URL passwords and raw IPv4 addresses.
    Used for log lines and audit details, never on stored business data."""
    for pattern, replacement in _TEXT_RULES:
        text = pattern.sub(replacement, text)
    return redact_text(text)


def redact_value(key: str, value: Any) -> Any:
    if is_sensitive_key(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return redact_mapping(value)
    if isinstance(value, list | tuple):
        return [redact_value(key, v) for v in value]
    return value


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    return {str(k): redact_value(str(k), v) for k, v in data.items()}


def find_forbidden_data(data: Any, path: str = "$") -> list[str]:
    """Return JSON paths inside ``data`` holding data that must never be stored."""
    return list(_iter_forbidden(data, path))


def _iter_forbidden(data: Any, path: str) -> Iterator[str]:
    if isinstance(data, Mapping):
        for key, value in data.items():
            child = f"{path}.{key}"
            if is_sensitive_key(str(key)) and value not in (None, ""):
                yield child
            else:
                yield from _iter_forbidden(value, child)
    elif isinstance(data, list | tuple):
        for i, value in enumerate(data):
            yield from _iter_forbidden(value, f"{path}[{i}]")
    elif isinstance(data, str) and contains_card_number(data):
        yield path
