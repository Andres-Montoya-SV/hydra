"""Native WHOIS client: Hydra follows the IANA -> registry -> registrar
referral chain itself, one TCP:43 connection at a time, instead of trusting
the system `whois` binary to do it invisibly.

The system client (the previous implementation of `modules/whois.py`) makes
its own referral-chain decisions and its own TCP connections, entirely
outside Hydra's authorization/SSRF layer — the only thing Hydra ever
authorized was the ORIGINAL domain being looked up, not any of the one-to-two
additional hosts (`whois.iana.org`, the TLD's registry server, sometimes a
distinct registrar server) that binary decided to contact on its own. Every
other active-collection network primitive in this codebase validates the
destination IP with `core/collection/ssrf.py` before connecting; the system
whois client never went through that check for any hop.

This module reimplements just enough of the referral-chain logic to preserve
the existing observable behavior (the same concatenated root-then-most-
specific raw text shape `modules/whois.py:_authoritative_block` already
expects) while validating every hop's resolved IP first — the same
`validate_destination_ips_async` check `ScopeEnforcingProxy` and
`AuthorizedCollectionTarget` already apply to HTTP destinations. A hop that
resolves to a private/loopback/link-local/CGNAT/metadata address is refused
and the chain stops there: whatever raw text earlier hops already produced is
kept (never discarded), but no further hop is attempted.

`allow_private_network_targets` is deliberately NOT threaded through from
`CollectionScope` here the way it is for target-directed HTTP: these
connections are never to the target itself, only to public WHOIS
infrastructure (IANA, registries, registrars) — there is no legitimate
scenario where an operator needs to opt into probing "private" infrastructure
for a WHOIS registry, so this always validates against the public-only
default regardless of the run's own scope settings.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

_WHOIS_PORT = 43
_IANA_WHOIS_HOST = "whois.iana.org"
_READ_CHUNK = 65536
# IANA (hop 1) -> registry (hop 2) -> registrar (hop 3, thin registries only).
# A malicious or misconfigured server chaining further referrals than this
# gets cut off rather than followed indefinitely.
_MAX_HOPS = 3

_REFERRAL_FIELD_RE = re.compile(r"^\s*(refer|whois)\s*:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_REGISTRAR_SERVER_RE = re.compile(
    r"^\s*registrar\s+whois\s+server\s*:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE
)


@dataclass(frozen=True)
class WhoisHop:
    """One TCP:43 query in the referral chain — attempted or refused."""

    host: str
    query: str
    allowed: bool
    reason: str
    response: str = ""


@dataclass(frozen=True)
class WhoisChainResult:
    """Outcome of following the referral chain for one domain.

    `raw` is the concatenated response text, root-first, in the same shape
    `modules/whois.py`'s existing parsing (`_authoritative_block`,
    `_parse_whois`) already expects from the system client's own referral
    following — callers should not need to change how they parse this.
    """

    hops: tuple[WhoisHop, ...]
    raw: str
    blocked: bool
    blocked_reason: str = ""


def _extract_field(text: str, pattern: re.Pattern[str]) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    value = match.group(match.lastindex or 1).strip().rstrip(".")
    return value or None


async def _query_hop(host: str, query: str, *, timeout: float) -> WhoisHop:
    from core.collection.ssrf import validate_destination_ips_async

    decision = await validate_destination_ips_async(host, allow_private_network_targets=False)
    if not decision.allowed:
        return WhoisHop(host=host, query=query, allowed=False, reason=decision.reason)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(decision.connect_ip, _WHOIS_PORT), timeout=timeout
        )
    except (OSError, TimeoutError) as exc:
        return WhoisHop(host=host, query=query, allowed=False, reason=f"connect_failed: {exc}")

    try:
        writer.write(f"{query}\r\n".encode("utf-8", errors="replace"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            chunk = await asyncio.wait_for(reader.read(_READ_CHUNK), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
    except (OSError, TimeoutError) as exc:
        return WhoisHop(host=host, query=query, allowed=False, reason=f"read_failed: {exc}")
    finally:
        try:
            writer.close()
        except OSError:
            pass

    response = b"".join(chunks).decode("utf-8", errors="replace")
    return WhoisHop(host=host, query=query, allowed=True, reason="allowed", response=response)


async def query_whois_chain(domain: str, *, timeout: float) -> WhoisChainResult:
    """Follow IANA -> registry -> (optional) registrar, validating and
    connecting to each hop directly. Never raises for a refused/failed hop —
    that is recorded on the returned `WhoisHop`/`WhoisChainResult`, the same
    fail-closed-but-observable contract as the rest of this codebase's
    authorization layer. May raise `asyncio.TimeoutError` only if the whole
    chain exceeds `timeout` (callers should wrap this call in
    `asyncio.wait_for` for a hard ceiling, matching the previous
    subprocess-timeout behavior)."""
    _root, _, tld = domain.rpartition(".")
    if not tld:
        return WhoisChainResult(hops=(), raw="", blocked=True, blocked_reason="unparseable_domain")

    hops: list[WhoisHop] = []
    raw_sections: list[str] = []

    hop1 = await _query_hop(_IANA_WHOIS_HOST, tld, timeout=timeout)
    hops.append(hop1)
    if not hop1.allowed:
        return WhoisChainResult(hops=tuple(hops), raw="", blocked=True, blocked_reason=hop1.reason)
    raw_sections.append(hop1.response)

    registry_host = _extract_field(hop1.response, _REFERRAL_FIELD_RE)
    if not registry_host:
        # No referral info in the root response — nothing more to chase.
        return WhoisChainResult(hops=tuple(hops), raw="\n".join(raw_sections), blocked=False)

    if len(hops) >= _MAX_HOPS:
        return WhoisChainResult(
            hops=tuple(hops),
            raw="\n".join(raw_sections),
            blocked=True,
            blocked_reason="max_referral_hops_exceeded",
        )

    hop2 = await _query_hop(registry_host, domain, timeout=timeout)
    hops.append(hop2)
    if not hop2.allowed:
        return WhoisChainResult(
            hops=tuple(hops),
            raw="\n".join(raw_sections),
            blocked=True,
            blocked_reason=hop2.reason,
        )
    raw_sections.append(hop2.response)

    registrar_host = _extract_field(hop2.response, _REGISTRAR_SERVER_RE)
    if registrar_host and registrar_host.lower() != registry_host.lower():
        if len(hops) >= _MAX_HOPS:
            return WhoisChainResult(
                hops=tuple(hops),
                raw="\n".join(raw_sections),
                blocked=True,
                blocked_reason="max_referral_hops_exceeded",
            )
        hop3 = await _query_hop(registrar_host, domain, timeout=timeout)
        hops.append(hop3)
        if not hop3.allowed:
            return WhoisChainResult(
                hops=tuple(hops),
                raw="\n".join(raw_sections),
                blocked=True,
                blocked_reason=hop3.reason,
            )
        raw_sections.append(hop3.response)

    return WhoisChainResult(hops=tuple(hops), raw="\n".join(raw_sections), blocked=False)
