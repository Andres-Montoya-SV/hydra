"""Real WebKit + real ScopeEnforcingProxy, driven through the actual
`BrowserProbePlugin.run()` — not raw Playwright calls.

`_install_scope_request_guard` (tested in `tests/test_browser_probe_scope_guard.py`)
decides abort/continue from a hostname-string scope check; it does not itself
resolve DNS or pin the destination IP. Before this turn, browser_probe never
routed WebKit's own network stack through Hydra's confinement proxy at all —
only the JS-visible `route()`/`route_web_socket()` layer existed. This file
proves the new `proxy=` launch option (the same `ScopeEnforcingProxy` already
verified against katana/hakrawler/nuclei/httpx) actually engages for a real
WebKit browser launched by the real plugin, and that it independently blocks
a destination the route()-level guard alone cannot reason about correctly:
an in-scope *hostname* that resolves to a private/loopback address.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")

from config.settings import Settings  # noqa: E402
from core.intel.scope import CollectionScope  # noqa: E402
from core.models import DomainTarget, PipelineContext  # noqa: E402
from modules.browser_probe import BrowserProbePlugin  # noqa: E402


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")


class _HeaderCapturingHandler(_QuietHandler):
    last_headers: object = None

    def do_GET(self) -> None:  # noqa: N802
        type(self).last_headers = self.headers
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")


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
        httpd.server_close()
        thread.join(timeout=2)


@pytest.fixture
def header_capturing_server() -> Iterator[int]:
    _HeaderCapturingHandler.last_headers = None
    httpd, port, thread = _serve(_HeaderCapturingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
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
    context.alive_urls = [url]
    return context


async def _require_webkit() -> None:
    """Skip cleanly if the WebKit *binary* isn't installed — the module-level
    `pytest.importorskip("playwright")` above only guards against the
    `playwright` Python package being missing, not against `playwright
    install webkit` never having been run. These tests drive the real
    `BrowserProbePlugin.run()`, which launches WebKit deep inside
    `modules/browser_probe.py`, so (unlike
    `tests/test_browser_probe_scope_guard.py`, which launches WebKit
    directly in the test body) a trial launch/close has to happen here,
    before the plugin gets a chance to raise an uncaught
    `BrowserType.launch: Executable doesn't exist` error instead of a skip.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        try:
            browser = await playwright.webkit.launch(headless=True)
        except Exception as exc:  # pragma: no cover - environment without webkit binary
            pytest.skip(f"WebKit browser binary not available: {exc}")
        else:
            await browser.close()


@pytest.mark.asyncio
async def test_browser_probe_reaches_authorized_target_through_confinement_proxy(
    tmp_path: Path, target_server: int
) -> None:
    """Sanity check: real WebKit launched with `proxy=` pointed at the real
    confinement proxy must still reach an authorized destination."""
    await _require_webkit()
    url = f"http://127.0.0.1:{target_server}/"
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    settings = Settings(project_root=tmp_path, enable_browser_probe=True)
    plugin = BrowserProbePlugin(settings)
    context = _context_for(tmp_path, scope, url)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert (
        _CountingHandler.hits
    ), "authorized target should have been reached through WebKit's proxy"


@pytest.mark.asyncio
async def test_browser_probe_in_scope_hostname_resolving_private_ip_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_server: int
) -> None:
    """The DNS-rebinding/TOCTOU scenario for the browser: the target hostname
    is fully in scope by name, but (per the confinement proxy's resolver,
    standing in for a real DNS answer no test can control on demand)
    resolves to the loopback address our own real server listens on. Real
    WebKit, launched by the real plugin, must never reach it — this is the
    confinement PROXY blocking the connection, independent of whatever the
    JS-level `route()` guard would have decided for this hostname string.
    """

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    await _require_webkit()

    url = f"http://rebind.browser-live-test.internal:{target_server}/"
    scope = CollectionScope.from_seeds(["rebind.browser-live-test.internal"])
    settings = Settings(project_root=tmp_path, enable_browser_probe=True)
    plugin = BrowserProbePlugin(settings)
    context = _context_for(tmp_path, scope, url)

    await plugin.run(context, tmp_path / "unused")

    assert _CountingHandler.hits == [], (
        "an in-scope hostname that resolves to a private/loopback address "
        "must never be reached by the real WebKit browser"
    )


@pytest.mark.asyncio
async def test_browser_probe_appends_attribution_to_real_device_user_agent(
    tmp_path: Path, header_capturing_server: int
) -> None:
    """ATTRIBUTION_USER_AGENT must reach the real WebKit request — appended
    onto the existing iPhone/Safari fingerprint (`_IPHONE_USER_AGENT`), never
    replacing it, since the mobile-device UA is what the cloaking-detection
    comparison against httpx depends on. Real WebKit, real local server."""
    await _require_webkit()
    url = f"http://127.0.0.1:{header_capturing_server}/"
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    settings = Settings(
        project_root=tmp_path,
        enable_browser_probe=True,
        attribution_user_agent="bugcrowd; cosmiccashew",
    )
    plugin = BrowserProbePlugin(settings)
    context = _context_for(tmp_path, scope, url)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert _HeaderCapturingHandler.last_headers is not None, "WebKit never reached the server"
    ua = _HeaderCapturingHandler.last_headers.get("User-Agent") or ""
    assert "iPhone" in ua, f"real device fingerprint must survive, got {ua!r}"
    assert "bugcrowd" in ua, f"expected attribution marker in real User-Agent, got {ua!r}"
