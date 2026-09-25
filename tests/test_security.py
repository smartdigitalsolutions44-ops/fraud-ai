import logging
import os
import stat
import uuid
from pathlib import Path

import pytest

from fraud_ai.config.settings import Environment, Settings
from fraud_ai.security.hashing import Pseudonymiser, normalise_address
from fraud_ai.security.keys import (
    DEV_KEY_FILENAME,
    KeyConfigurationError,
    resolve_pseudonymisation_key,
)
from fraud_ai.security.redaction import (
    REDACTED,
    contains_card_number,
    find_forbidden_data,
    is_sensitive_key,
    luhn_valid,
    redact_mapping,
    redact_text,
)
from fraud_ai.utils.logging import RedactingFilter, get_logger

VISA_TEST = "4111111111111111"


def test_luhn() -> None:
    assert luhn_valid(VISA_TEST)
    assert luhn_valid("378282246310005")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("abc")


@pytest.mark.parametrize("text", [VISA_TEST, "4111 1111 1111 1111", "card: 4111-1111-1111-1111"])
def test_detects_card_numbers(text: str) -> None:
    assert contains_card_number(text)
    assert REDACTED in redact_text(text)
    assert "1111 1111" not in redact_text(text)


@pytest.mark.parametrize(
    "text", ["order 1234567890123", "phone 07700900123", "4111111111111112", "tok_vault_demo_0001"]
)
def test_ignores_non_card_digits(text: str) -> None:
    assert not contains_card_number(text)


def test_uuids_never_flagged_as_card_numbers() -> None:
    for _ in range(2000):
        assert not contains_card_number(str(uuid.uuid4()))
    assert not contains_card_number("12345678-1234-4234-8234-123456789012")


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "new_password",
        "cvv",
        "CVC2",
        "pin",
        "card_number",
        "cardNumber",
        "pan",
        "access_token",
        "api_key",
        "client_secret",
        "otp",
        "Authorization",
    ],
)
def test_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key", ["token_reference", "card_last4", "pinned", "shipping_address_id", "amount", "company"]
)
def test_safe_keys(key: str) -> None:
    assert not is_sensitive_key(key)


def test_find_forbidden_data_paths_nested() -> None:
    data = {
        "ok": 1,
        "nested": {"cvv": "123", "list": [{"note": f"pan {VISA_TEST}"}]},
        "password": "",
        "token_reference": "tok_abc",
    }
    assert find_forbidden_data(data) == ["$.nested.cvv", "$.nested.list[0].note"]


def test_redact_text_key_values() -> None:
    out = redact_text('login password=hunter2 token: "abc.def" cvv=123 ok=1')
    assert "hunter2" not in out and "abc.def" not in out and "123" not in out
    assert "ok=1" in out


def test_redact_mapping() -> None:
    assert redact_mapping({"password": "x", "a": {"secret": "y"}, "b": "fine"}) == {
        "password": REDACTED,
        "a": {"secret": REDACTED},
        "b": "fine",
    }


def test_pseudonymiser_is_deterministic_keyed_and_normalised() -> None:
    a = Pseudonymiser(b"a" * 32)
    b = Pseudonymiser(b"b" * 32)
    assert a.hash_ip("10.0.0.1") == a.hash_ip(" 10.0.0.1 ")
    assert a.hash_ip("2001:db8:0:0::1") == a.hash_ip("2001:db8::1")
    assert a.hash_ip("10.0.0.1") != b.hash_ip("10.0.0.1")
    assert a.hash_ip("10.0.0.1") != a.hash_device("10.0.0.1")  # namespaces differ
    assert len(a.hash_address("1 High St")) == 64
    assert a.hash_address("1 High St.,  LEEDS") == a.hash_address("1 high st leeds")
    assert normalise_address(" 1, High-St ") == "1 high st"
    with pytest.raises(ValueError):
        Pseudonymiser(b"short")


def test_dev_key_generated_once_with_private_permissions(tmp_path: Path) -> None:
    s = Settings(
        environment=Environment.DEVELOPMENT, pseudonymisation_key=None, data_directory=tmp_path
    )
    key1 = resolve_pseudonymisation_key(s)
    key2 = resolve_pseudonymisation_key(s)
    assert key1 == key2 and len(key1) == 64
    mode = stat.S_IMODE(os.stat(tmp_path / DEV_KEY_FILENAME).st_mode)
    assert mode == 0o600


def test_configured_key_used_and_prod_never_generates(tmp_path: Path) -> None:
    s = Settings(pseudonymisation_key="z" * 40, data_directory=tmp_path)
    assert resolve_pseudonymisation_key(s) == b"z" * 40
    staging = Settings.model_construct(
        environment=Environment.STAGING, pseudonymisation_key=None, data_directory=tmp_path
    )
    with pytest.raises(KeyConfigurationError):
        resolve_pseudonymisation_key(staging)
    assert not (tmp_path / DEV_KEY_FILENAME).exists()


def test_logging_filter_redacts(caplog: pytest.LogCaptureFixture) -> None:
    log = get_logger("test.redaction")
    with caplog.at_level(logging.INFO, logger="fraud_ai"):
        log.info("payment with card %s and password=%s", VISA_TEST, "hunter2")
        log.info("details %s", {"cvv": "999", "amount": 5})
    text = caplog.text
    assert VISA_TEST not in text and "hunter2" not in text and "999" not in text
    assert "amount" in text
    assert any(isinstance(f, RedactingFilter) for f in log.filters)
