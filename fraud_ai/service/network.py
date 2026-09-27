"""Network-signal integrity: separate what the *server observed* from what the *client
claims*.

**Server-observed peer address.** This is the TCP peer. Forwarding headers
(``X-Forwarded-For``, ``Forwarded``) are honoured **only** when the peer is a configured
trusted proxy (``TRUSTED_PROXIES``). The chain is then walked right to left, skipping
trusted hops, and the first untrusted address is the client. Without trusted proxies the
headers are ignored completely, because anyone can send them.

The peer address is **never an identity**. Rate limits and authorisation use the API key.
It is used only to throttle repeated authentication failures. It is not logged and not
stored.

**Client-claimed network intelligence.** An event's ``metadata.network`` may carry
intelligence flags: VPN, Tor, proxy, datacenter, network type and the intel source. Those
flags are risk signals for the models, so a caller must not be able to whitewash an event
by submitting ``"is_known_vpn": false``. They are accepted only from a key holding the
``signals:trusted`` scope: the operator's own enrichment pipeline, not a merchant. A
request from any other key that carries them is **refused** with ``UNTRUSTED_SIGNAL``. It
is never silently dropped, so the integrator learns the contract.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Fields in ``metadata.network`` that only trusted infrastructure may assert.
INTEL_FIELDS = (
    "network_type",
    "is_mobile_network",
    "is_datacenter",
    "is_known_proxy",
    "is_known_vpn",
    "is_tor",
    "proxy_confidence",
    "intel_source",
)


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = value.strip().strip('"')
    if value.startswith("["):  # [v6]:port
        value = value[1:].split("]", 1)[0]
    elif value.count(":") == 1:  # v4:port
        value = value.split(":", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _trusted(addr: Any, networks: Sequence[Network]) -> bool:
    return addr is not None and any(addr in net for net in networks)


def _forwarded_chain(headers: Mapping[str, str]) -> list[str]:
    xff = headers.get("x-forwarded-for")
    if xff:
        return [p for p in (s.strip() for s in xff.split(",")) if p]
    fwd = headers.get("forwarded")
    chain: list[str] = []
    if fwd:
        for element in fwd.split(","):
            for pair in element.split(";"):
                key, _, value = pair.strip().partition("=")
                if key.lower() == "for" and value:
                    chain.append(value)
    return chain


def client_address(
    peer: str | None, headers: Mapping[str, str], trusted: Sequence[Network]
) -> str | None:
    """The server-observed client address (see module docs). ``None`` if unknown."""
    peer_ip = _ip(peer) if peer else None
    if peer_ip is None:
        return None
    if not trusted or not _trusted(peer_ip, trusted):
        return peer_ip.compressed
    for hop in reversed(_forwarded_chain(headers)):
        hop_ip = _ip(hop)
        if hop_ip is None:
            return peer_ip.compressed  # a malformed chain is not trusted
        if not _trusted(hop_ip, trusted):
            return hop_ip.compressed
    return peer_ip.compressed


def claimed_intel(event: Any) -> list[str]:
    """Paths of client-asserted intelligence fields in an event body."""
    if not isinstance(event, dict):
        return []
    metadata = event.get("metadata")
    network = metadata.get("network") if isinstance(metadata, dict) else None
    if not isinstance(network, dict):
        return []
    found = []
    for name in INTEL_FIELDS:
        value = network.get(name)
        if value is None or (name == "network_type" and value == "unknown"):
            continue
        found.append(f"metadata.network.{name}")
    return found


def headers_of(raw: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in raw:
        name = key.decode("latin-1").lower()
        text = value.decode("latin-1")
        out[name] = f"{out[name]},{text}" if name in out else text
    return out
