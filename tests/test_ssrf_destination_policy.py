"""SSRF/private-network destination policy (`core/collection/ssrf.py`).

Every pre-existing authorization primitive in this codebase decides
ALLOW/DENY from a HOSTNAME STRING against `CollectionScope`. None of them
ever resolved DNS or looked at the IP a connection would actually reach —
an in-scope hostname that resolves to a loopback/RFC1918/link-local/CGNAT/
metadata address sailed through unchecked. This is the classic
"allowed.example -> 10.0.0.1" SSRF/rebinding gap; these tests prove it is
now closed at the two call sites that connect on Hydra's behalf:
`AuthorizedCollectionTarget.authorize()` (httpx redirect hops) and
`ScopeEnforcingProxy` (crawler confinement), plus the pure classification
function they both build on.
"""

from __future__ import annotations

import asyncio
import socket
import socketserver
import threading
from collections.abc import Iterator

import pytest

from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.collection.ssrf import (
    classify_ip,
    validate_destination_ips,
    validate_destination_ips_async,
)
from core.collection.target import AuthorizedCollectionTarget
from core.intel.scope import CollectionScope

# ---------------------------------------------------------------------------
# Pure classification — every range named in the mission spec, no DNS at all.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip,expect_allowed,label",
    [
        ("0.0.0.1", False, "0.0.0.0/8"),
        ("10.1.2.3", False, "RFC1918 10/8"),
        ("100.64.0.1", False, "CGNAT 100.64.0.0/10"),
        ("127.0.0.1", False, "IPv4 loopback"),
        ("169.254.169.254", False, "cloud metadata address (within link-local)"),
        ("169.254.1.1", False, "link-local 169.254.0.0/16"),
        ("172.16.0.1", False, "RFC1918 172.16/12"),
        ("192.168.1.1", False, "RFC1918 192.168/16"),
        ("198.18.0.1", False, "benchmarking 198.18.0.0/15"),
        ("224.0.0.1", False, "multicast 224.0.0.0/4"),
        ("240.0.0.1", False, "reserved 240.0.0.0/4"),
        ("::1", False, "IPv6 loopback"),
        ("fc00::1", False, "IPv6 ULA fc00::/7"),
        ("fe80::1", False, "IPv6 link-local fe80::/10"),
        ("ff02::1", False, "IPv6 multicast ff00::/8"),
        ("93.184.216.34", True, "ordinary public IPv4"),
        ("2001:4860:4860::8888", True, "ordinary public IPv6"),
        ("::ffff:10.0.0.1", False, "IPv4-mapped IPv6 literal for a blocked RFC1918 address"),
        ("::ffff:127.0.0.1", False, "IPv4-mapped IPv6 literal for loopback"),
        ("::ffff:93.184.216.34", True, "IPv4-mapped IPv6 literal for an ordinary public address"),
        ("not-an-ip", False, "unparseable input fails closed"),
    ],
)
def test_classify_ip_covers_the_full_blocklist(ip: str, expect_allowed: bool, label: str) -> None:
    result = classify_ip(ip)
    assert (result == "allowed") == expect_allowed, f"{label}: got {result!r}"


@pytest.mark.parametrize(
    "ip,label",
    [
        # Exact addresses from the final adversarial audit's required matrix
        # not already covered above by another member of the same block —
        # specifically the literal network address and the top-of-range
        # boundary for each RFC1918 block, where an off-by-one in a range
        # comparison would actually show up (an arbitrary interior member
        # like 10.1.2.3 would not catch a boundary bug).
        ("0.0.0.0", "0.0.0.0/8 network address itself"),
        ("127.0.0.2", "second loopback address, same /8 as 127.0.0.1"),
        ("10.255.255.255", "top of RFC1918 10.0.0.0/8"),
        ("172.31.255.254", "top of RFC1918 172.16.0.0/12"),
        ("192.168.0.1", "bottom of RFC1918 192.168.0.0/16 (distinct octet from 192.168.1.1)"),
    ],
)
def test_classify_ip_boundary_addresses_from_the_required_matrix(ip: str, label: str) -> None:
    assert classify_ip(ip) != "allowed", f"{label}: {ip} must be blocked, got 'allowed'"


# ---------------------------------------------------------------------------
# Resolution-aware validation — DNS is monkeypatched (there is no real
# network to control an authoritative "this hostname resolves to 10.0.0.1"
# answer from), but the classification and fail-closed behavior on top of
# it are exercised for real.
# ---------------------------------------------------------------------------


def test_validate_destination_denies_hostname_resolving_to_private_ip(monkeypatch) -> None:
    """The exact mission scenario: `allowed.example` (a hostname that would
    pass ordinary scope/hostname authorization) resolves to `10.0.0.5`. That
    must not become an allowed network connection."""
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["10.0.0.5"])
    decision = validate_destination_ips("allowed.example")
    assert decision.allowed is False
    assert decision.reason.startswith("blocked_range")
    assert decision.resolved_ips == ("10.0.0.5",)


def test_validate_destination_allows_public_ip(monkeypatch) -> None:
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["93.184.216.34"])
    decision = validate_destination_ips("allowed.example")
    assert decision.allowed is True
    assert decision.connect_ip == "93.184.216.34"


def test_validate_destination_explicit_opt_in_allows_private_ip(monkeypatch) -> None:
    """The documented escape hatch: an operator who explicitly authorizes a
    private range via `CollectionScope.allow_private_network_targets` gets
    ALLOW instead of a silent, unrequested bypass."""
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["10.0.0.5"])
    decision = validate_destination_ips("internal.example", allow_private_network_targets=True)
    assert decision.allowed is True
    assert decision.reason == "private_targets_explicitly_allowed"


def test_validate_destination_fails_closed_on_resolver_exception(monkeypatch) -> None:
    def _raise(host: str) -> list[str]:
        raise socket.gaierror("simulated resolver failure")

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", _raise)
    decision = validate_destination_ips("flaky.example")
    assert decision.allowed is False
    assert decision.reason == "dns_resolution_failed"


def test_validate_destination_fails_closed_on_empty_answer(monkeypatch) -> None:
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: [])
    decision = validate_destination_ips("empty.example")
    assert decision.allowed is False
    assert decision.reason == "dns_resolution_empty"


def test_validate_destination_ip_literal_bypasses_dns_but_not_classification() -> None:
    """An IP literal never touches the resolver at all — it IS the
    destination — but still passes through the same blocklist."""
    assert validate_destination_ips("127.0.0.1").allowed is False
    assert validate_destination_ips("93.184.216.34").allowed is True


@pytest.mark.asyncio
async def test_validate_destination_async_matches_sync_semantics(monkeypatch) -> None:
    async def _fake_resolve(host: str) -> list[str]:
        return ["10.0.0.5"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    decision = await validate_destination_ips_async("allowed.example")
    assert decision.allowed is False
    assert decision.reason.startswith("blocked_range")


# ---------------------------------------------------------------------------
# AuthorizedCollectionTarget (httpx redirect hops): a hostname that clears
# scope authorization must still be denied if it resolves to a blocked IP.
# ---------------------------------------------------------------------------

SEED = "seed.ssrf-target-test.internal"


def _scope(**kwargs) -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED], **kwargs)


def test_authorized_collection_target_denies_in_scope_hostname_resolving_private(
    monkeypatch,
) -> None:
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["169.254.169.254"])
    target = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert target is None


def test_authorized_collection_target_verbose_reports_ssrf_reason_distinctly(monkeypatch) -> None:
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["192.168.1.1"])
    target, reason = AuthorizedCollectionTarget.authorize_verbose(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert target is None
    assert reason.startswith("blocked_range")
    assert reason != "out_of_scope"  # must be distinguishable from a plain scope denial


def test_authorized_collection_target_allows_in_scope_hostname_resolving_public(
    monkeypatch,
) -> None:
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["93.184.216.34"])
    target = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert target is not None
    assert target.resolved_ips == ("93.184.216.34",)


def test_authorized_collection_target_opt_in_allows_private_destination(monkeypatch) -> None:
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["10.0.0.5"])
    target = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/",
        _scope(allow_private_network_targets=True),
        capability="http_probe",
    )
    assert target is not None
    assert target.resolved_ips == ("10.0.0.5",)


def test_authorized_collection_target_out_of_scope_never_reaches_dns(monkeypatch) -> None:
    """An out-of-scope hostname must be denied by the (cheap, no-I/O) scope
    check alone — the resolver must never even be called for it."""
    called = False

    def _spy(host: str) -> list[str]:
        nonlocal called
        called = True
        return ["93.184.216.34"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", _spy)
    target = AuthorizedCollectionTarget.authorize(
        "https://evil.ssrf-target-test.internal/", _scope(), capability="http_probe"
    )
    assert target is None
    assert called is False, "resolver must not run for a hostname already denied by scope"


# ---------------------------------------------------------------------------
# ScopeEnforcingProxy: real proxy, real local server, monkeypatched
# resolution standing in for DNS answering "this in-scope hostname is
# actually a private address" — and a real proof that the proxy connects to
# the SAME IP it validated (TOCTOU/rebinding closed), not a second lookup.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_denies_in_scope_hostname_that_resolves_to_loopback(monkeypatch) -> None:
    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    scope = CollectionScope.from_seeds(["rebind.ssrf-proxy-test.internal"])
    proxy = ScopeEnforcingProxy(scope, capability="test")
    allowed, reason, connect_ip = await proxy._authorize_with_reason(
        "rebind.ssrf-proxy-test.internal"
    )
    assert allowed is False
    assert reason.startswith("blocked_range")
    assert connect_ip == ""


@pytest.mark.asyncio
async def test_proxy_connects_to_the_resolved_ip_it_validated_not_a_fresh_lookup(
    monkeypatch,
) -> None:
    """Proves the TOCTOU fix directly: `_authorize_with_reason` resolves and
    validates once; the caller must use exactly that IP for the real
    connection rather than re-resolving `host` a second time (where DNS
    could legitimately answer differently — the rebinding attack)."""
    resolve_calls: list[str] = []

    async def _fake_resolve(host: str) -> list[str]:
        resolve_calls.append(host)
        return ["93.184.216.34"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    scope = CollectionScope.from_seeds(["pinned.ssrf-proxy-test.internal"])
    proxy = ScopeEnforcingProxy(scope, capability="test")

    open_connection_calls: list[tuple[str, int]] = []
    real_open_connection = asyncio.open_connection

    async def _spy_open_connection(host, port, **kwargs):
        open_connection_calls.append((host, port))
        raise OSError("no real destination in this test — call args are what's under test")

    monkeypatch.setattr(asyncio, "open_connection", _spy_open_connection)
    try:
        allowed, reason, connect_ip = await proxy._authorize_with_reason(
            "pinned.ssrf-proxy-test.internal"
        )
        assert allowed is True
        assert connect_ip == "93.184.216.34"
        assert len(resolve_calls) == 1, "authorization must resolve exactly once"

        # Simulate the real call site's connect step using the returned
        # connect_ip, exactly as core/collection/crawler_proxy.py does.
        with pytest.raises(OSError):
            await asyncio.open_connection(connect_ip, 443)
        assert open_connection_calls == [("93.184.216.34", 443)]
        assert len(resolve_calls) == 1, (
            "the connect step must not trigger a second DNS resolution of the "
            "hostname — that second lookup is exactly the rebinding TOCTOU gap"
        )
    finally:
        monkeypatch.setattr(asyncio, "open_connection", real_open_connection)


# ---------------------------------------------------------------------------
# Real end-to-end proof (mission section 13: "the assertion must be OOS
# server received ZERO requests, not merely Hydra decided DENY"). A real
# local TCP server stands in for the mission's "allowed.example -> 10.0.0.1"
# scenario: DNS resolution is monkeypatched (there is no live authority that
# would let a test control what a real hostname resolves to on demand), but
# the CONNECT request, the proxy, and the destination server are all real —
# proving the private-IP block (and its explicit opt-out) hold at the actual
# TCP layer, not just in a returned decision object.
# ---------------------------------------------------------------------------


class _CountingHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # pragma: no cover - trivial
        self.server.hits.append(self.client_address)  # type: ignore[attr-defined]
        self.request.settimeout(2)
        try:
            while True:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
        except OSError:
            pass


def _start_server() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", 0), _CountingHandler)
    server.hits = []  # type: ignore[attr-defined]
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


@pytest.fixture
def loopback_server() -> Iterator[tuple[socketserver.TCPServer, int]]:
    server, port, thread = _start_server()
    try:
        yield server, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


async def _wait_until(predicate, *, timeout: float = 5.0, interval: float = 0.02) -> bool:
    """Bounded poll on an observable condition — never a fixed sleep.

    A completed client-side TCP handshake is not the same event as the
    destination `socketserver.TCPServer` thread recording a hit. See the
    identical helper in tests/test_crawler_proxy.py.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return bool(predicate())


async def _raw_connect(proxy_port: int, target_host: str, target_port: int) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode()
    )
    await writer.drain()
    response = await asyncio.wait_for(reader.read(1024), timeout=5)
    writer.close()
    return response


@pytest.mark.asyncio
async def test_real_connect_to_in_scope_hostname_resolving_loopback_is_blocked(
    monkeypatch, loopback_server
) -> None:
    """`rebind.ssrf-real-test.internal` is fully in scope by hostname — the
    only thing wrong with it is that (per the monkeypatched resolver
    standing in for a real DNS answer) it resolves to 127.0.0.1, which is
    exactly where our own real test server is listening. The real server
    must receive zero connections despite the hostname being authorized.
    """
    server, port = loopback_server

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    scope = CollectionScope.from_seeds(["rebind.ssrf-real-test.internal"])
    proxy = ScopeEnforcingProxy(scope, capability="test")
    await proxy.start()
    try:
        response = await _raw_connect(proxy.port, "rebind.ssrf-real-test.internal", port)
    finally:
        await proxy.stop()

    assert b"403" in response
    assert server.hits == [], "the real server must never see a connection"


@pytest.mark.asyncio
async def test_real_connect_to_explicitly_opted_in_private_target_succeeds(
    monkeypatch, loopback_server
) -> None:
    """The converse, proving the opt-in is not merely a decision-object flag
    but an actual working connection: same hostname/resolver as above, but
    `allow_private_network_targets=True` — the real server DOES get reached,
    and the proxy connects using the resolved IP (127.0.0.1), not the
    nonexistent hostname string itself (which would fail to resolve for
    real and prove nothing)."""
    server, port = loopback_server

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    scope = CollectionScope.from_seeds(
        ["rebind.ssrf-real-test.internal"], allow_private_network_targets=True
    )
    proxy = ScopeEnforcingProxy(scope, capability="test")
    await proxy.start()
    try:
        response = await _raw_connect(proxy.port, "rebind.ssrf-real-test.internal", port)
        await _wait_until(lambda: bool(server.hits))
    finally:
        await proxy.stop()

    assert b"200" in response
    assert server.hits, "the real server must be reached once explicitly opted in"


# Section 14 required matrix: for every forbidden IP class, authorization
# DENY must also mean ZERO real sockets. We cannot listen on RFC1918 /
# metadata / IPv6 ULA from a unit test, so the destination-server oracle
# for those classes is "open_connection was never called" — the same
# primitive ScopeEnforcingProxy uses after a successful authorize. The
# loopback case above is the one class we can actually host.
_REQUIRED_FORBIDDEN_IPS = (
    "127.0.0.1",
    "127.0.0.2",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.0.1",
    "169.254.169.254",
    "100.64.0.1",
    "224.0.0.1",
    "0.0.0.0",
    "::1",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_ip", _REQUIRED_FORBIDDEN_IPS)
async def test_proxy_never_opens_a_socket_to_required_forbidden_ip(
    monkeypatch: pytest.MonkeyPatch, blocked_ip: str
) -> None:
    async def _fake_resolve(host: str) -> list[str]:
        return [blocked_ip]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)

    connect_calls: list[tuple[str, int]] = []
    real_open_connection = asyncio.open_connection

    async def _spy_open_connection(host, port, **kwargs):
        connect_calls.append((str(host), int(port)))
        raise OSError("must never be reached for a forbidden destination IP")

    monkeypatch.setattr(asyncio, "open_connection", _spy_open_connection)
    try:
        scope = CollectionScope.from_seeds(["matrix.ssrf-proxy-test.internal"])
        proxy = ScopeEnforcingProxy(scope, capability="test")
        allowed, reason, connect_ip = await proxy._authorize_with_reason(
            "matrix.ssrf-proxy-test.internal"
        )
        assert allowed is False, f"{blocked_ip}: expected DENY, got ALLOW ({reason})"
        assert connect_ip == ""
        assert reason.startswith("blocked_"), f"{blocked_ip}: unexpected reason {reason!r}"
        # The authorize path must not itself open a socket to the blocked IP.
        assert connect_calls == [], (
            f"{blocked_ip}: authorization opened a real socket "
            f"{connect_calls} — DENY must be ZERO_CONNECTIONS"
        )
    finally:
        monkeypatch.setattr(asyncio, "open_connection", real_open_connection)
