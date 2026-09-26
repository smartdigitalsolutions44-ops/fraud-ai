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

import ipaddress
import re
from collections.abc import Iterator
from typing import Any

from fraud_ai.security.redaction import (
    REDACTED,
    contains_card_number,
    is_sensitive_key,
    redact_text,
)

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
EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.IGNORECASE)
PHONE = re.compile(r"(?<![\w.])\+?\d[\d ()-]{8,}\d(?![\w.])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
IPV6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])", re.IGNORECASE)
UUID = re.compile(
    r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}", re.IGNORECASE
)
LONG_HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{24,}(?![0-9a-f])", re.IGNORECASE)
TOKEN = re.compile(r"\btok_[A-Za-z0-9]+|\bsk-[A-Za-z0-9]{8,}|\bghp_[A-Za-z0-9]{8,}")
SECRET_ASSIGNMENT = re.compile(
    r"\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE
)
STREET = re.compile(
    r"\b\d{1,5}\s+[A-Za-z][A-Za-z ]{1,40}\s(?:road|street|lane|avenue|drive|close|way|"
    r"court|place|crescent|terrace|rd|st|ave)\b",
    re.IGNORECASE,
)
INSTRUCTION = re.compile(
    r"\b(ignore|disregard|forget)\b.{0,40}\b(instruction|prompt|rule|above|previous)|"
    r"\b(system prompt|you are now|act as|jailbreak)\b|"
    r"\b(approve|block|decline|allow|whitelist)\b.{0,20}\b(transaction|account|payment|order|"
    r"this)\b",
    re.IGNORECASE,
)
# Tokens join words with separators ("ignore_previous_instructions"); read them as words.
SEPARATORS = re.compile(r"[_.:+-]+")
# Pseudonymous references this system itself produces are allowed.
ALLOWED_REF = re.compile(r"^(ev|ex)-[0-9a-f]{16}$")


def _ip(text: str) -> bool:
    for candidate in IPV4.findall(text) + IPV6.findall(text):
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            continue
    return False


def text_violations(text: str, *, free_text_allowed: bool) -> list[str]:
    if ALLOWED_REF.match(text):
        return []
    found = []
    if EMAIL.search(text):
        found.append("email address")
    if _ip(text):
        found.append("IP address")
    if contains_card_number(text):
        found.append("card number")
    if TOKEN.search(text) or SECRET_ASSIGNMENT.search(text):
        found.append("token or secret")
    if UUID.search(text):
        found.append("raw identifier (UUID)")
    elif LONG_HEX.search(text):
        found.append("long hex identifier")
    if STREET.search(text):
        found.append("street address")
    if PHONE.search(text) and not contains_card_number(text):
        found.append("phone number")
    if INSTRUCTION.search(text) or INSTRUCTION.search(SEPARATORS.sub(" ", text)):
        found.append("embedded instruction")
    if not free_text_allowed and (" " in text.strip() or len(text) > 64):
        found.append("unexpected free text")
    return found


def redact(text: str) -> str:
    """Mask anything identifier-like before a model output fragment is echoed in an error."""
    for pattern in (EMAIL, UUID, LONG_HEX, TOKEN, SECRET_ASSIGNMENT, STREET, IPV4, IPV6, PHONE):
        text = pattern.sub(REDACTED, text)
    return redact_text(text)


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
