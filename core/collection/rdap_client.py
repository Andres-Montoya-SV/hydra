"""Fase 12 (EASM roadmap): a minimal, SSRF-hardened RDAP client.

Mirrors `core/collection/whois_client.py`'s own discipline for the same
reason: RDAP is HTTP(S)-based, but the "validate every hop before
connecting, bound the number of hops, this is not the organization's own
scope-authorization path" invariant applies just as much to an RDAP
redirect chain as it does to a WHOIS TCP referral chain. This module
never touches `CollectionGateway`/`ScopeEnforcingProxy` — those
authorize scans of a customer's OWN domain; RDAP lookups always target
third-party registry/registrar infrastructure, exactly like
`whois_client.py`'s own hops, so `allow_private_network_targets` is
never threaded through here either.

Bootstraps through the single, well-known, IANA-recommended `rdap.org`
redirector (`https://rdap.org/domain/<domain>`) — the same "one
hardcoded, trusted, well-known entry point" pattern `modules/ctlogs.py`
already uses for `crt.sh`. `rdap.org` itself is never treated as
authoritative data; it typically 302/307-redirects to the actual
RIR/registry's own RDAP server, whose IP IS validated before Hydra
connects, since that target is registry-controlled, not a fixed,
pre-vetted host the way `rdap.org` is.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.collection.ssrf import validate_destination_ips
from utils.network import default_ssl_context

_BOOTSTRAP_HOST = "rdap.org"
_MAX_HOPS = 3
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # RDAP JSON responses are small; this is a generous cap
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


@dataclass(frozen=True)
class RdapHop:
    url: str
    allowed: bool
    reason: str
    status_code: int | None = None


@dataclass(frozen=True)
class RdapResult:
    hops: tuple[RdapHop, ...]
    status_code: int | None
    body: dict | None
    blocked: bool
    blocked_reason: str = ""


@dataclass(frozen=True)
class _FetchOutcome:
    hop: RdapHop
    body: bytes
    location: str | None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP while keeping the correct TLS SNI /
    Host for the logical hostname — closes the DNS-rebind gap between the
    SSRF check and the actual connection. `core/collection/whois_client.py`
    gets this same guarantee for free by connecting directly to
    `decision.connect_ip` for its own (non-virtual-hosted) raw TCP
    protocol; RDAP needs the extra step because HTTPS routing and TLS
    certificate validation both depend on the hostname, not the IP."""

    def __init__(
        self, host: str, pinned_ip: str, *, timeout: float, context: ssl.SSLContext
    ) -> None:
        super().__init__(host, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port or 443), self.timeout)
        self.sock = self.context.wrap_socket(sock, server_hostname=self.host)


def _fetch_one(url: str, *, timeout: float) -> _FetchOutcome:
    """Never raises — every failure mode (bad scheme, blocked
    destination, connection error, oversized response) is reported on
    the returned hop's `allowed`/`reason`, the same fail-closed-but-
    observable contract `core/collection/whois_client.py` already
    established."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return _FetchOutcome(
            RdapHop(url=url, allowed=False, reason="unsupported_scheme_or_host"), b"", None
        )

    decision = validate_destination_ips(parsed.hostname, allow_private_network_targets=False)
    if not decision.allowed:
        return _FetchOutcome(RdapHop(url=url, allowed=False, reason=decision.reason), b"", None)

    conn = _PinnedHTTPSConnection(
        parsed.hostname, decision.connect_ip, timeout=timeout, context=default_ssl_context()
    )
    conn.port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        conn.request(
            "GET",
            path,
            headers={
                "Accept": "application/rdap+json",
                "Host": parsed.hostname,
                "User-Agent": "Hydra-EASM-RDAP/1.0",
            },
        )
        response = conn.getresponse()
        body = response.read(_MAX_RESPONSE_BYTES + 1)
        status_code = response.status
        location = response.getheader("Location")
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return _FetchOutcome(
            RdapHop(url=url, allowed=False, reason=f"request_failed: {exc}"), b"", None
        )
    finally:
        try:
            conn.close()
        except OSError:
            pass

    if len(body) > _MAX_RESPONSE_BYTES:
        return _FetchOutcome(
            RdapHop(url=url, allowed=False, reason="response_too_large", status_code=status_code),
            b"",
            None,
        )

    return _FetchOutcome(
        RdapHop(url=url, allowed=True, reason="allowed", status_code=status_code), body, location
    )


def fetch_rdap_domain(
    domain: str,
    *,
    timeout: float = 10.0,
    fetcher: Callable[[str, float], _FetchOutcome] = _fetch_one,
) -> RdapResult:
    """Follows `rdap.org` -> (usually) the authoritative RIR/registry
    RDAP server, bounded to `_MAX_HOPS`, each hop SSRF-validated. Never
    raises: every outcome — success, a blocked hop, too many redirects,
    a malformed/unexpected response — is a `RdapResult`, never an
    exception, so a caller can log "RDAP unavailable for this domain"
    without a try/except around network internals.

    `fetcher` is an injection point for tests only (real callers never
    pass it) — the redirect-following/response-classification logic here
    is fully deterministic and independent of the actual network I/O
    `_fetch_one` performs.
    """
    url = f"https://{_BOOTSTRAP_HOST}/domain/{domain}"
    hops: list[RdapHop] = []

    for _ in range(_MAX_HOPS):
        outcome = fetcher(url, timeout)
        hops.append(outcome.hop)

        if not outcome.hop.allowed:
            return RdapResult(
                hops=tuple(hops),
                status_code=outcome.hop.status_code,
                body=None,
                blocked=True,
                blocked_reason=outcome.hop.reason,
            )

        status = outcome.hop.status_code
        if status in _REDIRECT_STATUSES and outcome.location:
            url = outcome.location
            continue

        if status is not None and 200 <= status < 300:
            try:
                parsed_body = json.loads(outcome.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return RdapResult(
                    hops=tuple(hops),
                    status_code=status,
                    body=None,
                    blocked=True,
                    blocked_reason="malformed_json_response",
                )
            if not isinstance(parsed_body, dict):
                return RdapResult(
                    hops=tuple(hops),
                    status_code=status,
                    body=None,
                    blocked=True,
                    blocked_reason="unexpected_response_shape",
                )
            return RdapResult(hops=tuple(hops), status_code=status, body=parsed_body, blocked=False)

        return RdapResult(
            hops=tuple(hops),
            status_code=status,
            body=None,
            blocked=True,
            blocked_reason=f"unexpected_status_{status}",
        )

    return RdapResult(
        hops=tuple(hops),
        status_code=None,
        body=None,
        blocked=True,
        blocked_reason="too_many_redirects",
    )
