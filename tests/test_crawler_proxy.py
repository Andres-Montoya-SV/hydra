"""ScopeEnforcingProxy: real TCP-level containment for tools Hydra can't gate by input file.

These tests drive the proxy exactly the way a real HTTP client would (raw
sockets speaking the proxy protocol) and assert on whether the destination
server ever received a connection — not on what the proxy claims to have
done.
"""

from __future__ import annotations

import asyncio
import socketserver
import threading
from collections.abc import Iterator

import pytest

from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.intel.scope import CollectionScope

SEED = "app.example-seed.test"
OOS = "evil.example-oos.test"


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED])


class _CountingHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # pragma: no cover - trivial
        self.server.hits.append(self.client_address)  # type: ignore[attr-defined]
        self.request.settimeout(2)
        try:
            while True:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                self.server.received.append(chunk)  # type: ignore[attr-defined]
        except OSError:
            pass


def _start_destination_server() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", 0), _CountingHandler)
    server.hits = []  # type: ignore[attr-defined]
    server.received = []  # type: ignore[attr-defined]
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


@pytest.fixture
def destination() -> Iterator[tuple[socketserver.TCPServer, int]]:
    server, port, thread = _start_destination_server()
    try:
        yield server, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


async def _raw_connect_request(proxy_port: int, target_host: str, target_port: int) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode()
    )
    await writer.drain()
    response = await asyncio.wait_for(reader.read(1024), timeout=5)
    writer.close()
    return response


async def _raw_http_proxy_request(proxy_port: int, target_host: str, target_port: int) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    url = f"http://{target_host}:{target_port}/"
    writer.write(
        f"GET {url} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=5)
    writer.close()
    return response


@pytest.mark.asyncio
async def test_connect_to_out_of_scope_host_is_denied_and_never_connects(destination) -> None:
    server, port = destination
    proxy = ScopeEnforcingProxy(_scope(), capability="crawl")
    await proxy.start()
    try:
        # OOS is a real hostname resolving nowhere useful in test scope, but the
        # proxy must reject on the authorization check before ever attempting
        # a connection — target host/port here point at our own destination
        # server (loopback) specifically so a bypassed check would be visible.
        response = await _raw_connect_request(proxy.port, OOS, port)
    finally:
        await proxy.stop()

    assert b"403" in response
    assert server.hits == []
    assert proxy.denied and proxy.denied[0].host == OOS
    assert proxy.allowed_hosts == []


@pytest.mark.asyncio
async def test_connect_to_authorized_host_is_forwarded(destination) -> None:
    server, port = destination
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    proxy = ScopeEnforcingProxy(scope, capability="crawl")
    await proxy.start()
    try:
        response = await _raw_connect_request(proxy.port, "127.0.0.1", port)
        # give the destination server's thread a moment to record the hit
        await asyncio.sleep(0.2)
    finally:
        await proxy.stop()

    assert b"200" in response
    assert server.hits, "authorized CONNECT target should have been reached"
    assert proxy.allowed_hosts == ["127.0.0.1"]
    assert proxy.denied == []


@pytest.mark.asyncio
async def test_stop_waits_for_in_flight_connection_tasks(destination) -> None:
    """Regression: `stop()` used to only close the listening socket —
    `server.close()`/`wait_closed()` stop new connections but say nothing
    about a connection-handling task already inside `_splice`. A caller that
    treats a returned `stop()` as "this proxy instance is fully quiescent"
    (every live test in this suite does exactly that in a `finally:` block)
    could have a splice loop still running in the background afterward,
    keeping sockets open past the point the caller — and pytest-asyncio's
    function-scoped event loop teardown right after — assumed everything was
    closed. `stop()` must not return until every task it spawned has too."""
    server, port = destination
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    proxy = ScopeEnforcingProxy(scope, capability="crawl")
    await proxy.start()

    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
    await writer.drain()
    await asyncio.wait_for(reader.readline(), timeout=5)  # "HTTP/1.1 200 Connection Established"
    # The CONNECT succeeded and the splice loop for it is now running as a
    # background task owned by the proxy — this is the in-flight state
    # `stop()` must account for, not a hypothetical.
    assert proxy._active_tasks, "expected an in-flight connection-handling task after CONNECT"

    await proxy.stop()

    assert (
        proxy._active_tasks == set()
    ), "stop() must not return while a connection task is still running"
    writer.close()


@pytest.mark.asyncio
async def test_plain_http_proxy_request_to_oos_host_is_denied_and_never_connects(
    destination,
) -> None:
    server, port = destination
    proxy = ScopeEnforcingProxy(_scope(), capability="crawl")
    await proxy.start()
    try:
        response = await _raw_http_proxy_request(proxy.port, OOS, port)
    finally:
        await proxy.stop()

    assert b"403" in response
    assert server.hits == []
    assert proxy.denied and proxy.denied[0].host == OOS


@pytest.mark.asyncio
async def test_plain_http_post_body_is_forwarded_intact_to_authorized_host(destination) -> None:
    """The splice-based forwarder must not truncate a POST body — it never
    parses Content-Length, it just pipes bytes, so this proves that actually
    works rather than assuming it from the implementation."""
    server, port = destination
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    proxy = ScopeEnforcingProxy(scope, capability="crawl")
    await proxy.start()
    body = b'{"template": "fuzz-payload", "value": "x" * 500}'
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        request = (
            f"POST http://127.0.0.1:{port}/submit HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin1") + body
        writer.write(request)
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
    finally:
        await proxy.stop()

    assert server.hits, "authorized POST should have reached the destination"
    received = b"".join(server.received)
    assert body in received, "POST body must be forwarded intact, not truncated"


@pytest.mark.asyncio
async def test_missing_scope_denies_every_connection() -> None:
    """No CollectionScope object at all must fail closed, not open."""
    proxy = ScopeEnforcingProxy(None, capability="crawl")
    await proxy.start()
    try:
        response = await _raw_connect_request(proxy.port, SEED, 443)
    finally:
        await proxy.stop()
    assert b"403" in response
    assert proxy.denied and proxy.denied[0].host == SEED


@pytest.mark.asyncio
async def test_authorization_exception_denies_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import core.collection.crawler_proxy as crawler_proxy_module

    def boom(host: str, scope: object, operation: str, reason: str) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(crawler_proxy_module, "authorize_active_indicator", boom)

    proxy = ScopeEnforcingProxy(_scope(), capability="crawl")
    await proxy.start()
    try:
        response = await _raw_connect_request(proxy.port, SEED, 443)
    finally:
        await proxy.stop()
    assert b"403" in response


@pytest.mark.asyncio
async def test_connect_userinfo_style_target_is_parsed_by_real_host(destination) -> None:
    """CONNECT doesn't have userinfo per spec, but a malformed/malicious client
    sending one must not let the userinfo-looking prefix leak through as the
    authorized host — rpartition(':') on the raw target string is what the
    proxy actually authorizes against, so this proves that stays correct."""
    server, port = destination
    proxy = ScopeEnforcingProxy(_scope(), capability="crawl")
    await proxy.start()
    try:
        # A client can't literally put "user@host" before the CONNECT target
        # per spec, but a target that merely *contains* the seed as a
        # substring must not be treated as authorized by anything looser
        # than an exact host match.
        response = await _raw_connect_request(proxy.port, f"{SEED}.{OOS}", port)
    finally:
        await proxy.stop()
    assert b"403" in response
    assert server.hits == []


@pytest.mark.asyncio
async def test_plain_http_userinfo_confusion_authorizes_real_host_only(destination) -> None:
    """GET http://seed@oos/ — the authorized-looking string before '@' is
    userinfo, not the host; the real host (oos) must be denied, and an
    authorized-looking host used as userinfo must not smuggle an OOS host
    through."""
    server, port = destination
    proxy = ScopeEnforcingProxy(_scope(), capability="crawl")
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        url = f"http://{SEED}@127.0.0.1:{port}/"
        writer.write(
            f"GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()
    finally:
        await proxy.stop()

    # The real host here is 127.0.0.1 (not in scope, SEED is a domain) — the
    # userinfo-looking SEED prefix must not authorize it.
    assert b"403" in response
    assert server.hits == []
