"""CollectionGateway: the structural network boundary (core/collection/gateway.py).

Proves the property the whole `AuthorizedCollectionTarget` design exists for
but that no single object previously packaged end to end: a plugin cannot
call the gateway's network method with a bare string, only with a value that
came from `authorize()` — and `authorize()` itself is the same fail-closed
scope/capability/OPSEC/destination-IP decision already verified in
`tests/test_authorized_collection_target.py`/`tests/test_ssrf_destination_policy.py`.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator

import pytest

from core.collection.gateway import CollectionGateway
from core.collection.target import AuthorizedCollectionTarget
from core.intel.scope import CollectionScope

SEED = "app.gateway-test.internal"
OOS = "evil.gateway-test.internal"


@pytest.fixture(autouse=True)
def _fake_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic `.internal` test domains never resolve — stub the SSRF
    layer's resolver to a fixed public-looking address so these tests
    exercise gateway/authorization behavior, not real DNS."""
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(
        "core.collection.ssrf.resolve_hostname_async",
        _async_resolve,
    )


async def _async_resolve(host: str) -> list[str]:
    return ["203.0.113.10"]


def _scope(**kwargs) -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED], **kwargs)


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


def _serve() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", 0), _CountingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


@pytest.fixture
def target_server() -> Iterator[int]:
    _CountingHandler.hits = []
    server, port, thread = _serve()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# ---------------------------------------------------------------------------
# authorize() — pure decision, no I/O
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorize_denies_out_of_scope_host() -> None:
    async with CollectionGateway(_scope(), capability="http_verify") as gateway:
        assert gateway.authorize(f"https://{OOS}/") is None


@pytest.mark.asyncio
async def test_authorize_returns_a_real_target_for_in_scope_host() -> None:
    async with CollectionGateway(_scope(), capability="http_verify") as gateway:
        target = gateway.authorize(f"https://{SEED}/")
        assert target is not None
        assert isinstance(target, AuthorizedCollectionTarget)
        assert target.hostname == SEED


@pytest.mark.asyncio
async def test_authorize_denies_without_scope() -> None:
    async with CollectionGateway(None, capability="http_verify") as gateway:
        assert gateway.authorize(f"https://{SEED}/") is None


# ---------------------------------------------------------------------------
# http_get() — cannot be called with a bare string, only a sealed target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_get_rejects_a_plain_string() -> None:
    """The structural property: `http_get` is not `requests.get` with extra
    steps — it physically refuses a bare URL, so the only way to make a
    request is to have already called `authorize()` and gotten a real
    target back."""
    async with CollectionGateway(_scope(), capability="http_verify") as gateway:
        with pytest.raises(TypeError):
            await gateway.http_get(f"https://{SEED}/", timeout=5)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_http_get_rejects_a_forged_target_object() -> None:
    """Even a hand-built object of the right *shape* fails — `http_get`
    checks `isinstance(target, AuthorizedCollectionTarget)`, and that class
    itself cannot be constructed directly (test_authorized_collection_target.py)."""

    class _FakeTarget:
        raw = f"https://{OOS}/"
        hostname = OOS

    async with CollectionGateway(_scope(), capability="http_verify") as gateway:
        with pytest.raises(TypeError):
            await gateway.http_get(_FakeTarget(), timeout=5)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_http_get_reaches_the_real_authorized_destination(target_server: int) -> None:
    """Real local server, real confinement proxy, real urllib request — the
    authorized target must actually be reached."""
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    async with CollectionGateway(scope, capability="http_verify") as gateway:
        target = gateway.authorize(f"http://127.0.0.1:{target_server}/")
        assert target is not None
        response = await gateway.http_get(target, timeout=5)

    assert response.status_code == 200
    assert _CountingHandler.hits


@pytest.mark.asyncio
async def test_denied_target_never_becomes_a_request(target_server: int) -> None:
    """The other half of the property: a hostname that fails `authorize()`
    never gets an `AuthorizedCollectionTarget` at all, so there is nothing to
    hand `http_get` — the real server must receive zero connections."""
    scope = _scope()  # only SEED is in scope; the real target server is 127.0.0.1
    async with CollectionGateway(scope, capability="http_verify") as gateway:
        target = gateway.authorize(f"http://127.0.0.1:{target_server}/")
        assert target is None

    assert _CountingHandler.hits == []


@pytest.mark.asyncio
async def test_in_scope_hostname_resolving_private_ip_is_denied_before_any_request(
    monkeypatch: pytest.MonkeyPatch, target_server: int
) -> None:
    """DNS-rebinding scenario at the gateway level: SEED is in scope by
    name, but resolves (per the stubbed resolver) to the real local server's
    loopback address. `authorize()` must deny it — the destination-IP check
    runs as part of authorization, before any request is even attempted."""
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["127.0.0.1"])
    async with CollectionGateway(_scope(), capability="http_verify") as gateway:
        target = gateway.authorize(f"https://{SEED}/")
        assert target is None

    assert _CountingHandler.hits == []
