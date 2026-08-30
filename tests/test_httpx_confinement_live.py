"""Real httpx binary + real ScopeEnforcingProxy + real CollectionScope.

Before this turn, `HttpxPlugin.run()` never routed the real installed httpx
binary through Hydra's confinement proxy at all — `AuthorizedCollectionTarget`
validated a hostname/IP in Python, but httpx then independently resolved and
connected to that hostname a second time, on its own, outside anything Hydra
could observe or pin. That is the DNS-rebinding/TOCTOU gap this turn's
mission calls out by name. This file proves the fix end-to-end against the
real binary, not by re-testing `ScopeEnforcingProxy` in isolation (already
covered by `tests/test_crawler_proxy.py`/`test_ssrf_destination_policy.py`).

Key fact this relies on: once a client is routed through an HTTP forward
proxy (`-proxy`), *the proxy* resolves the target hostname from the request
line/CONNECT target — the client (httpx) never resolves it itself. So
monkeypatching the proxy's resolver (Python code in this same process)
faithfully simulates "this hostname's DNS answer" for the real httpx
subprocess, without needing control over real DNS infrastructure.
"""

from __future__ import annotations

import http.server
import shutil
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.httpx import HttpxPlugin
from utils.files import write_lines

pytestmark = pytest.mark.skipif(shutil.which("httpx") is None, reason="httpx binary not installed")


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"reached")


def _make_redirect_handler(oos_port: int, oos_host: str):
    class _RedirectHandler(_QuietHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://{oos_host}:{oos_port}/secret")
            self.end_headers()

    return _RedirectHandler


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def oos_server() -> Iterator[int]:
    _CountingHandler.hits = []
    httpd, port, thread = _serve(_CountingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_httpx_reaches_authorized_target_through_confinement_proxy(tmp_path: Path) -> None:
    """Sanity check: routing through the proxy must not break the normal,
    authorized case — the real destination must still be reached."""
    server, port, thread = _serve(_CountingHandler)
    try:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        hosts_path = output_dir / "resolved.txt"
        seed_url = f"http://127.0.0.1:{port}/"
        write_lines(hosts_path, [seed_url], base_dir=output_dir)

        settings = Settings(project_root=tmp_path)
        context = PipelineContext(
            targets=[DomainTarget(domain="127.0.0.1")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(
                ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
            ),
        )
        plugin = HttpxPlugin(settings)
        result = await plugin.run(context, hosts_path)
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert _CountingHandler.hits, "authorized target should have been reached through the proxy"
    assert result.success


@pytest.mark.asyncio
async def test_httpx_redirect_escape_is_blocked_by_confinement_proxy(
    tmp_path: Path, oos_server: int
) -> None:
    """The initial probe is in-scope; the `Location` header points at a
    different host the confinement proxy (not just the Python-level
    redirect-hop check) must independently refuse to connect to."""
    seed_httpd, seed_port, seed_thread = _serve(_make_redirect_handler(oos_server, "localhost"))
    try:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        hosts_path = output_dir / "resolved.txt"
        seed_url = f"http://127.0.0.1:{seed_port}/"
        write_lines(hosts_path, [seed_url], base_dir=output_dir)

        settings = Settings(project_root=tmp_path)
        context = PipelineContext(
            targets=[DomainTarget(domain="127.0.0.1")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(
                ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
            ),
        )
        plugin = HttpxPlugin(settings)
        await plugin.run(context, hosts_path)
    finally:
        seed_httpd.shutdown()
        seed_thread.join(timeout=2)

    assert _CountingHandler.hits == [], (
        "the redirect target (a different host than the authorized seed) must "
        "receive zero connections — neither the Python-level redirect-hop "
        "check nor the confinement proxy may let this through"
    )


@pytest.mark.asyncio
async def test_httpx_in_scope_hostname_resolving_to_private_ip_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, oos_server: int
) -> None:
    """The DNS-rebinding/TOCTOU scenario, against the real binary: the seed
    hostname is fully in scope by name, but (per the confinement proxy's
    resolver, standing in for a real DNS answer no test can control on
    demand) resolves to the loopback address our own real server listens
    on. httpx must never reach it — proving the proxy's resolve-validate-
    connect step, not just the Python-level pre-check, is what's actually
    gating the real subprocess's real connection.
    """

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    hosts_path = output_dir / "resolved.txt"
    seed_url = f"http://rebind.httpx-live-test.internal:{oos_server}/"
    write_lines(hosts_path, [seed_url], base_dir=output_dir)

    settings = Settings(project_root=tmp_path)
    context = PipelineContext(
        targets=[DomainTarget(domain="rebind.httpx-live-test.internal")],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(["rebind.httpx-live-test.internal"]),
    )
    plugin = HttpxPlugin(settings)
    await plugin.run(context, hosts_path)

    assert _CountingHandler.hits == [], (
        "an in-scope hostname that resolves to a private/loopback address "
        "must never be reached by the real httpx subprocess"
    )
