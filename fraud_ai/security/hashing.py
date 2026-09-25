"""Keyed pseudonymisation (HMAC-SHA256).

Identifiers such as IP addresses, device identifiers, postal addresses and payment
fingerprints are stored as keyed hashes. Hashes are stable (so reuse across accounts can be
measured) but cannot be reversed or brute-forced without the key.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from enum import StrEnum


class HashNamespace(StrEnum):
    IP = "ip"
    DEVICE = "device"
    ADDRESS = "address"
    PAYMENT_FINGERPRINT = "payment_fingerprint"


class Pseudonymiser:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("pseudonymisation key must be at least 32 bytes")
        self._key = key

    def hash(self, namespace: HashNamespace, value: str) -> str:
        message = f"{namespace.value}:{value}".encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def hash_ip(self, ip: str) -> str:
        return self.hash(HashNamespace.IP, normalise_ip(ip))

    def hash_device(self, device_identifier: str) -> str:
        return self.hash(HashNamespace.DEVICE, device_identifier.strip())

    def hash_address(self, address: str) -> str:
        return self.hash(HashNamespace.ADDRESS, normalise_address(address))

    def hash_payment_fingerprint(self, fingerprint: str) -> str:
        return self.hash(HashNamespace.PAYMENT_FINGERPRINT, fingerprint.strip())


def normalise_ip(ip: str) -> str:
    return ipaddress.ip_address(ip.strip()).compressed


def normalise_address(address: str) -> str:
    lowered = address.lower()
    no_punct = re.sub(r"[^\w\s]", " ", lowered)
    return re.sub(r"\s+", " ", no_punct).strip()
