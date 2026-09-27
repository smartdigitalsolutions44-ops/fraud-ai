"""Privacy gate for everything that goes to, or comes back from, the local LLM.

``scan`` walks any JSON-like structure and reports violations:

* **Forbidden keys** (email, phone, IP, address, card, token, password, secret, session,
  device id, ...) at any depth.
* **Values that look like**:
  * an email address or a phone number;
  * an IPv4 or IPv6 address;
  * a card number (Luhn-checked);
  * a payment token (``tok_…``) or a secret-looking assignment;
  * a raw UUID (a database primary key);
  * a long hex string (a hash or device id);
  * a street address.
* **Unexpected free text** in the evidence packet. Evidence values must be short machine
  tokens, so any sentence-like string is rejected, as is an embedded instruction such as
  "ignore previous instructions".

Model output (explanations) is scanned with the same patterns, except that normal prose is
allowed there.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from fraud_ai.security.pii import (
    ALLOWED_REF,
    EMAIL,
    INSTRUCTION,
    IPV4,
    IPV6,
    LONG_HEX,
    PHONE,
    SECRET_ASSIGNMENT,
    SEPARATORS,
    STREET,
    TOKEN,
    UUID,
    redact,
    text_violations,
)
from fraud_ai.security.redaction import is_sensitive_key

__all__ = [
    "ALLOWED_REF",
    "EMAIL",
    "FORBIDDEN_KEYS",
    "INSTRUCTION",
    "IPV4",
    "IPV6",
    "LONG_HEX",
    "PHONE",
    "SECRET_ASSIGNMENT",
    "SEPARATORS",
    "STREET",
    "TOKEN",
    "UUID",
    "redact",
    "scan",
    "scan_packet",
    "text_violations",
]

FORBIDDEN_KEYS = frozenset(
    {
        "email",
        "email_address",
        "phone",
        "phone_number",
        "ip",
        "ip_address",
        "ip_hash",
        "address",
        "full_address",
        "street",
        "postcode",
        "postal_code",
        "card",
        "card_number",
        "pan",
        "cvv",
        "pin",
        "card_last4",
        "token",
        "token_reference",
        "password",
        "secret",
        "session",
        "session_id",
        "device_id",
        "device_identifier",
        "device_hash",
        "user_id",
        "external_ref",
        "name",
        "first_name",
        "last_name",
    }
)


# The text patterns live in fraud_ai.security.pii (shared with the Stage 8 review queue).
def _walk(data: Any, path: str) -> Iterator[tuple[str, Any, str | None]]:
    if isinstance(data, dict):
        for key, value in data.items():
            yield f"{path}.{key}", value, str(key)
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(data, list | tuple):
        for i, value in enumerate(data):
            yield f"{path}[{i}]", value, None
            yield from _walk(value, f"{path}[{i}]")


def scan(
    data: Any, *, free_text_allowed: bool = False, free_text_keys: frozenset[str] = frozenset()
) -> list[str]:
    """Violations as ``"<path>: <reason>"`` strings (empty = clean)."""
    violations = []
    for path, value, key in _walk(data, "$"):
        if key is not None and (key.lower() in FORBIDDEN_KEYS or is_sensitive_key(key)):
            violations.append(f"{path}: forbidden key {key!r}")
        if isinstance(value, str):
            allowed = free_text_allowed or (key in free_text_keys)
            for reason in text_violations(value, free_text_allowed=allowed):
                violations.append(f"{path}: {reason}")
    return violations


def scan_packet(packet: Any) -> list[str]:
    """The packet gate. Header fields and every evidence value must be clean machine
    tokens; evidence *names* must not be sensitive fields; only the controlled limitation
    texts may contain prose."""
    canonical = packet.canonical()
    violations = []
    for key in ("schema_version", "event_ref", "event_type"):
        for reason in text_violations(str(canonical[key]), free_text_allowed=False):
            violations.append(f"$.{key}: {reason}")
    for item in canonical["evidence"]:
        name = item["name"]
        if name.lower() in FORBIDDEN_KEYS or is_sensitive_key(name):
            violations.append(f"$.evidence[{item['id']}]: forbidden field {name!r}")
        if isinstance(item["value"], str):
            for reason in text_violations(item["value"], free_text_allowed=False):
                violations.append(f"$.evidence[{item['id']}].value: {reason}")
    for i, lim in enumerate(canonical["limitations"]):
        for reason in text_violations(lim["text"], free_text_allowed=True):
            violations.append(f"$.limitations[{i}]: {reason}")
    return violations
