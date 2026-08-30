"""SSRF/private-network destination policy.

Every existing authorization primitive in this codebase — `allows_active_collection`,
`authorize_active_indicator`, `AuthorizedCollectionTarget.authorize` — decides ALLOW/DENY
from the HOSTNAME STRING against `CollectionScope`. None of them resolve DNS or look at
the IP address a connection would actually reach. An in-scope hostname that resolves (now,
or later via DNS rebinding between authorization and connection) to a loopback, RFC1918,
link-local, carrier-grade-NAT, multicast, or cloud-metadata address sails through those
checks unchecked — the exact SSRF/rebinding gap this module closes.

This is an ADDITIONAL, independent layer callers apply *after* hostname authorization
passes, not a replacement for it. A destination must clear both: `allows_active_collection`
(is this hostname in the operator's authorized scope) and `validate_destination_ips`/
`validate_destination_ips_async` (does it not resolve to a network Hydra must never touch
by default).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

# Fixed blocklist per the mission spec. Deliberately not sourced from
# CollectionScope — these are defaults that apply regardless of scope
# unless a run explicitly opts in via `allow_private_network_targets`.
_BLOCKED_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # covers the 169.254.169.254 metadata address
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)
_BLOCKED_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # ULA
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
)


def classify_ip(ip_str: str) -> str:
    """Return "allowed" or a specific block reason for one IP literal.

    Unparseable input fails closed (never "allowed") — a caller that cannot
    even parse the address it's about to connect to must not proceed.
    """
    try:
        addr = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError:
        return "unparseable"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        # ::ffff:10.0.0.1 is an IPv4-mapped IPv6 literal for 10.0.0.1 — classify
        # it as the IPv4 address it actually represents, not as an ordinary
        # IPv6 address the IPv6 blocklist has nothing to say about.
        addr = addr.ipv4_mapped
    blocklist = _BLOCKED_V4 if addr.version == 4 else _BLOCKED_V6
    for network in blocklist:
        if addr in network:
            return f"blocked_range:{network}"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return "blocked_reserved"
    return "allowed"


def _looks_like_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class DestinationDecision:
    allowed: bool
    reason: str
    resolved_ips: tuple[str, ...] = ()

    @property
    def connect_ip(self) -> str:
        """The single IP a caller should actually connect to (first resolved
        address) — binding the connection to what was just validated instead
        of leaving a second, unvalidated DNS lookup at connect time."""
        return self.resolved_ips[0] if self.resolved_ips else ""


def resolve_hostname(hostname: str) -> list[str]:
    """Real, synchronous DNS resolution. Raises on failure — callers must
    treat that as fail-closed, never as an empty/harmless result."""
    infos = socket.getaddrinfo(hostname, None)
    seen: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    return seen


async def resolve_hostname_async(hostname: str) -> list[str]:
    """Non-blocking equivalent of `resolve_hostname` for use inside an
    already-async proxy loop (`core/collection/crawler_proxy.py`)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(hostname, None)
    seen: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    return seen


def _decide(ips: list[str], *, allow_private_network_targets: bool) -> DestinationDecision:
    if not ips:
        return DestinationDecision(False, "dns_resolution_empty")
    if allow_private_network_targets:
        return DestinationDecision(True, "private_targets_explicitly_allowed", tuple(ips))
    for ip in ips:
        reason = classify_ip(ip)
        if reason != "allowed":
            return DestinationDecision(False, reason, tuple(ips))
    return DestinationDecision(True, "allowed", tuple(ips))


def validate_destination_ips(
    hostname: str, *, allow_private_network_targets: bool = False
) -> DestinationDecision:
    """Resolve `hostname` (synchronously) and check every resolved IP.

    Fails closed on a resolution error, an empty answer, or any blocked IP —
    unless `allow_private_network_targets` (from `CollectionScope`, an
    explicit operator opt-in) is set.
    """
    if _looks_like_ip_literal(hostname):
        return _decide(
            [hostname.strip("[]")], allow_private_network_targets=allow_private_network_targets
        )
    try:
        ips = resolve_hostname(hostname)
    except (OSError, UnicodeError):
        return DestinationDecision(False, "dns_resolution_failed")
    return _decide(ips, allow_private_network_targets=allow_private_network_targets)


async def validate_destination_ips_async(
    hostname: str, *, allow_private_network_targets: bool = False
) -> DestinationDecision:
    """Async equivalent of `validate_destination_ips`, for callers already
    running inside an event loop that must not block it on DNS I/O."""
    if _looks_like_ip_literal(hostname):
        return _decide(
            [hostname.strip("[]")], allow_private_network_targets=allow_private_network_targets
        )
    try:
        ips = await resolve_hostname_async(hostname)
    except (OSError, UnicodeError):
        return DestinationDecision(False, "dns_resolution_failed")
    return _decide(ips, allow_private_network_targets=allow_private_network_targets)
