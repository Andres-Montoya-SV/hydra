"""OPSEC proxy chaining: `collector -> Hydra confinement proxy -> external
proxy -> target`, never `collector -> external proxy -> target` directly.

Before this turn, when `Settings.outbound_proxy_url` was configured, httpx
and browser_probe talked to that external proxy *directly*, bypassing
Hydra's own confinement proxy entirely — an explicitly documented exception.
This mission mandates closing it: `ScopeEnforcingProxy` now chains to the
external proxy internally (`upstream_proxy_url`,
`core/collection/crawler_proxy.py`), so Hydra's own scope/SSRF authorization
always runs *before* anything is forwarded to the external proxy, and an
unauthorized destination never reaches the external proxy at all.

The "external proxy" here is a second, real `ScopeEnforcingProxy` instance
configured to allow everything — a legitimate stand-in for a real external
HTTP/CONNECT proxy (it speaks the identical wire protocol), used only to
observe what Hydra's own proxy actually forwards to it. This is not testing
`ScopeEnforcingProxy` twice; it's using one real proxy implementation as an
external network peer to inspect Hydra's chaining behavior, exactly the way
`tests/test_crawler_proxy.py` uses a plain TCP server as a peer.
"""

from __future__ import annotations

import asyncio
import socketserver
import threading
from collections.abc import Iterator

import pytest

from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.intel.scope import CollectionScope

SEED = "app.opsec-chain-test.internal"
OOS = "evil.opsec-chain-test.internal"


def _scope(**kwargs) -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED], **kwargs)


class _CountingHandler(socketserver.BaseRequestHandler):
    hits: list[tuple] = []

    def handle(self) -> None:  # pragma: no cover - trivial
        self.server.hits.append(self.client_address)  # type: ignore[attr-defined]
        self.request.settimeout(2)
        try:
            self.request.recv(65536)
        except OSError:
            pass
        try:
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
        except OSError:
            pass


def _serve_target() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", 0), _CountingHandler)
    server.hits = []  # type: ignore[attr-defined]
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


@pytest.fixture
def target_server() -> Iterator[tuple[socketserver.TCPServer, int]]:
    _CountingHandler.hits = []
    server, port, thread = _serve_target()
    try:
        yield server, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
async def test_authorized_destination_is_forwarded_through_the_external_proxy(
    target_server,
) -> None:
    """`collector -> Hydra proxy -> external proxy -> target`: the target
    server receives the connection, AND the external proxy itself is the one
    that actually opened the socket to it — proving the chain, not just that
    Hydra decided ALLOW."""
    server, port = target_server

    # Stand-in external proxy: allows everything (127.0.0.1), so its own
    # authorization never interferes with what we're testing here — Hydra's
    # own gate is what's under test.
    external_scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    external_proxy = ScopeEnforcingProxy(external_scope, capability="external-test-proxy")
    await external_proxy.start()

    # SEED itself is a domain, not 127.0.0.1 — point the CONNECT target at
    # the real destination server's own loopback address, authorized via the
    # explicit private-target opt-in (this test is about chaining, not SSRF).
    hydra_scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    hydra_proxy = ScopeEnforcingProxy(
        hydra_scope,
        capability="httpx",
        upstream_proxy_url=external_proxy.proxy_url,
    )
    await hydra_proxy.start()
    try:
        response = await _raw_connect(hydra_proxy.port, "127.0.0.1", port)
    finally:
        await hydra_proxy.stop()
        await external_proxy.stop()

    assert b"200" in response
    assert server.hits, "the real target server should have been reached"
    assert external_proxy.allowed_hosts == [
        "127.0.0.1"
    ], "the external proxy should have handled exactly the CONNECT Hydra forwarded to it"


@pytest.mark.asyncio
async def test_out_of_scope_redirect_never_reaches_the_external_proxy(target_server) -> None:
    """The critical chaining property: an unauthorized destination must be
    refused by Hydra's own proxy BEFORE anything is ever forwarded to the
    external proxy — the external proxy must show zero activity for it."""
    server, port = target_server

    external_scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    external_proxy = ScopeEnforcingProxy(external_scope, capability="external-test-proxy")
    await external_proxy.start()

    # Hydra's own scope only authorizes SEED (a domain) — the OOS hostname
    # below must never even be forwarded to the external proxy.
    hydra_proxy = ScopeEnforcingProxy(
        _scope(), capability="httpx", upstream_proxy_url=external_proxy.proxy_url
    )
    await hydra_proxy.start()
    try:
        response = await _raw_connect(hydra_proxy.port, OOS, port)
    finally:
        await hydra_proxy.stop()
        await external_proxy.stop()

    assert b"403" in response
    assert server.hits == [], "the real target server must never be reached"
    assert (
        external_proxy.allowed_hosts == []
    ), "the external proxy must never see a request for a destination Hydra denied"
    assert external_proxy.denied == [], "the external proxy was never even asked"


@pytest.mark.asyncio
async def test_private_ip_destination_never_reaches_the_external_proxy(
    monkeypatch: pytest.MonkeyPatch, target_server
) -> None:
    """An in-scope *hostname* that resolves to a private IP (per Hydra's own
    resolver — the SSRF pre-check that runs before anything is forwarded)
    must never reach the external proxy either, even though the hostname
    itself would otherwise be authorized."""
    server, port = target_server

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)

    external_scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    external_proxy = ScopeEnforcingProxy(external_scope, capability="external-test-proxy")
    await external_proxy.start()

    hydra_scope = CollectionScope.from_seeds(["rebind.opsec-chain-test.internal"])
    hydra_proxy = ScopeEnforcingProxy(
        hydra_scope, capability="httpx", upstream_proxy_url=external_proxy.proxy_url
    )
    await hydra_proxy.start()
    try:
        response = await _raw_connect(hydra_proxy.port, "rebind.opsec-chain-test.internal", port)
    finally:
        await hydra_proxy.stop()
        await external_proxy.stop()

    assert b"403" in response
    assert server.hits == [], "the real target server must never be reached"
    assert external_proxy.allowed_hosts == [], "the external proxy must never see this destination"
