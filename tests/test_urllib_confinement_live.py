"""Real urllib request (via `core/http_probe.py:http_get`) + real
ScopeEnforcingProxy, driven through the actual `Soft404CheckPlugin.run()`.

Before this turn, `soft404_check`/`param_fuzz`/`cloud_bucket_enum` all called
`http_get(url, proxy_url=self.settings.outbound_proxy_url)` — `None` unless an
external OPSEC-hiding proxy was configured. In the default configuration,
that meant urllib did its own independent DNS resolution and connection,
completely outside Hydra's confinement proxy — the same DNS-rebinding/TOCTOU
gap this turn closed for httpx and the browser. All three plugins share the
identical `http_get(..., proxy_url=...)` call shape and the identical fix
(route through `self._crawler_confinement(context)`); this file proves it
end-to-end for one of them (`soft404_check`, the simplest) against a real
local server — the other two are covered by their existing unit tests, which
already tolerate an arbitrary `proxy_url` value since they mock `http_get`
itself.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.soft404_check import Soft404CheckPlugin


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(404)  # soft404_check only cares that *a* response arrived
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"not found")


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def target_server() -> Iterator[int]:
    _CountingHandler.hits = []
    httpd, port, thread = _serve(_CountingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def _context_for(tmp_path: Path, scope: CollectionScope, url: str) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain="probe-test")],
        output_dir=output_dir,
        collection_scope=scope,
    )
    context.httpx_results = [{"input": url, "url": url, "host": url}]
    return context


@pytest.mark.asyncio
async def test_soft404_reaches_authorized_target_through_confinement_proxy(
    tmp_path: Path, target_server: int
) -> None:
    """Sanity check: routing urllib through the proxy must not break the
    normal, authorized case."""
    url = f"http://127.0.0.1:{target_server}/"
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    settings = Settings(project_root=tmp_path, enable_soft404_check=True)
    plugin = Soft404CheckPlugin(settings)
    context = _context_for(tmp_path, scope, url)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert _CountingHandler.hits, "authorized target should have been reached through the proxy"


@pytest.mark.asyncio
async def test_soft404_in_scope_hostname_resolving_private_ip_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_server: int
) -> None:
    """The DNS-rebinding/TOCTOU scenario, against the real urllib request:
    the target hostname is fully in scope by name, but (per the confinement
    proxy's resolver, standing in for a real DNS answer no test can control
    on demand) resolves to the loopback address our own real server listens
    on. The real server must receive zero connections.
    """

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)

    url = f"http://rebind.urllib-live-test.internal:{target_server}/"
    scope = CollectionScope.from_seeds(["rebind.urllib-live-test.internal"])
    settings = Settings(project_root=tmp_path, enable_soft404_check=True)
    plugin = Soft404CheckPlugin(settings)
    context = _context_for(tmp_path, scope, url)

    await plugin.run(context, tmp_path / "unused")

    assert _CountingHandler.hits == [], (
        "an in-scope hostname that resolves to a private/loopback address "
        "must never be reached by the real urllib request"
    )
