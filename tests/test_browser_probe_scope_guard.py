"""Every browser_probe request must be authorized, not just document navigation.

`_install_scope_request_guard` routes every Playwright request — the main
document, cross-origin iframe navigation, and every subresource type
(script/image/stylesheet/font/xhr/fetch/websocket/...) — through
`browser_request_decision`. These tests exercise the guard against a real
WebKit browser and real local HTTP servers so the resource-type and
navigation-request behavior asserted here is what Playwright actually does,
not an assumption baked into a mock. A couple of fast fake-object tests cover
the fail-closed exception path without needing a browser at all.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")

from playwright.async_api import async_playwright  # noqa: E402

from core.models import DomainTarget, PipelineContext  # noqa: E402
from modules import browser_probe  # noqa: E402

SEED = "app.metaversejustice.com"


def _context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(targets=[DomainTarget(domain=SEED)], output_dir=output_dir)


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence per-request stderr noise
        pass


def _serve(directory: Path) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    def handler(*args: object, **kwargs: object) -> _QuietHandler:
        return _QuietHandler(*args, directory=str(directory), **kwargs)  # type: ignore[arg-type]

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def oos_server(tmp_path: Path) -> Iterator[int]:
    """A second origin standing in for a host outside CollectionScope."""
    directory = tmp_path / "oos"
    directory.mkdir()
    (directory / "blocked.js").write_text("void 0;")
    (directory / "blocked.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (directory / "frame.html").write_text("<html><body>oos frame content</body></html>")
    (directory / "xhr-blocked").write_text("{}")
    httpd, port, thread = _serve(directory)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _allow_only_port(main_port: int):
    """Stand-in CollectionScope check: only the in-scope server's own port is allowed.

    Real host/pattern matching (`allows_active_collection`) is exercised
    elsewhere (test_scope_authorization.py, test_redirect_safety.py); what
    these tests verify is that the guard applies that decision to every
    resource type Playwright reports, using real requests.
    """

    def _decide(url: str, context: object) -> bool:
        return f":{main_port}" in url

    return _decide


async def _run_probe_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    index_html: str,
    *,
    port_offset: str = "in_scope",
) -> dict[str, int]:
    directory = tmp_path / port_offset
    directory.mkdir()
    (directory / "ok.js").write_text("void 0;")
    (directory / "index.html").write_text(index_html)
    httpd, port, thread = _serve(directory)
    monkeypatch.setattr(browser_probe, "allow_browser_navigation", _allow_only_port(port))

    blocked_counts: dict[str, int] = {}
    try:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.webkit.launch(headless=True)
            except Exception as exc:  # pragma: no cover - environment without webkit binary
                pytest.skip(f"WebKit browser binary not available: {exc}")
            try:
                browser_context = await browser.new_context()
                context = _context(tmp_path)
                # Context-level, matching production _probe_target — this is
                # what makes a window.open() popup inherit the same guard.
                await browser_probe._install_scope_request_guard(
                    browser_context, context, blocked_counts
                )
                page = await browser_context.new_page()
                try:
                    await page.goto(
                        f"http://127.0.0.1:{port}/index.html",
                        wait_until="networkidle",
                        timeout=5000,
                    )
                except Exception as exc:
                    # A blocked subresource can keep the page noisy enough to
                    # miss networkidle; blocked_counts is already populated
                    # by the guard regardless of how goto() itself resolves.
                    print(f"page.goto did not settle cleanly (expected under blocking): {exc}")
                await page.wait_for_timeout(500)
            finally:
                await browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
    return blocked_counts


@pytest.mark.asyncio
async def test_subresources_from_out_of_scope_hosts_are_blocked_and_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, oos_server: int
) -> None:
    """script/image/fetch to an OOS origin are blocked; same-origin script is not."""
    index_html = f"""<html><body>
    <script src="/ok.js"></script>
    <script src="http://127.0.0.1:{oos_server}/blocked.js"></script>
    <img src="http://127.0.0.1:{oos_server}/blocked.png">
    <script>fetch('http://127.0.0.1:{oos_server}/xhr-blocked').catch(() => {{}});</script>
    </body></html>"""

    blocked_counts = await _run_probe_page(tmp_path, monkeypatch, index_html)

    assert blocked_counts.get("script", 0) >= 1
    assert blocked_counts.get("image", 0) >= 1
    assert blocked_counts.get("fetch", 0) + blocked_counts.get("xhr", 0) >= 1


@pytest.mark.asyncio
async def test_cross_origin_iframe_navigation_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, oos_server: int
) -> None:
    """A cross-origin <iframe> navigation is a `document`-type request and is blocked.

    Confirms empirically (not by assumption) that Playwright's
    `is_navigation_request()` fires for sub-frame navigation, and that our
    per-request guard — unlike the old guard, which only ran when installed
    on `page.route` and happened to already cover this — blocks it via the
    same `browser_request_decision` path as every other resource type.
    """
    index_html = f"""<html><body>
    <iframe src="http://127.0.0.1:{oos_server}/frame.html"></iframe>
    </body></html>"""

    blocked_counts = await _run_probe_page(tmp_path, monkeypatch, index_html)

    assert blocked_counts.get("document", 0) >= 1


@pytest.mark.asyncio
async def test_in_scope_page_with_no_third_party_references_has_zero_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No OOS reference on the page → no regression in the common case."""
    index_html = """<html><body>
    <script src="/ok.js"></script>
    <h1>all same-origin</h1>
    </body></html>"""

    blocked_counts = await _run_probe_page(tmp_path, monkeypatch, index_html)

    assert blocked_counts == {}


@pytest.mark.asyncio
async def test_subresource_guard_fails_closed_on_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug evaluating policy for a subresource (not just navigation) blocks it."""
    context = _context(tmp_path)

    def _boom(request: object, ctx: object) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr(browser_probe, "browser_request_decision", _boom)

    calls: dict[str, object] = {"abort": None, "continued": False}

    class FakeRequest:
        url = f"https://cdn.{SEED}.evil/tracker.js"
        resource_type = "script"

        def is_navigation_request(self) -> bool:
            return False

    class FakeRoute:
        request = FakeRequest()

        async def abort(self, reason: str) -> None:
            calls["abort"] = reason

        async def continue_(self) -> None:
            calls["continued"] = True

    handlers: dict[str, object] = {}

    class FakeContext:
        async def route(self, pattern: str, handler: object) -> None:
            handlers["guard"] = handler

        async def route_web_socket(self, pattern: str, handler: object) -> None:
            handlers["websocket_guard"] = handler

    blocked_counts: dict[str, int] = {}
    await browser_probe._install_scope_request_guard(FakeContext(), context, blocked_counts)
    await handlers["guard"](FakeRoute())

    assert calls["abort"] == "blockedbyclient"
    assert calls["continued"] is False
    assert blocked_counts.get("script") == 1


@pytest.mark.asyncio
async def test_websocket_guard_fails_closed_on_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug evaluating policy for a WebSocket connection blocks it, same as any other type."""
    context = _context(tmp_path)

    def _boom(url: str, ctx: object) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr(browser_probe, "allow_browser_navigation", _boom)

    calls: dict[str, object] = {"closed": None, "connected": False}

    class FakeWebSocketRoute:
        url = f"wss://cdn.{SEED}.evil/socket"

        async def close(self, *, code: int | None = None, reason: str | None = None) -> None:
            calls["closed"] = (code, reason)

        def connect_to_server(self) -> None:
            calls["connected"] = True

    handlers: dict[str, object] = {}

    class FakeContext:
        async def route(self, pattern: str, handler: object) -> None:
            handlers["guard"] = handler

        async def route_web_socket(self, pattern: str, handler: object) -> None:
            handlers["websocket_guard"] = handler

    blocked_counts: dict[str, int] = {}
    await browser_probe._install_scope_request_guard(FakeContext(), context, blocked_counts)
    await handlers["websocket_guard"](FakeWebSocketRoute())

    assert calls["closed"] is not None
    assert calls["connected"] is False
    assert blocked_counts.get("websocket") == 1


@pytest.mark.asyncio
async def test_websocket_to_out_of_scope_host_never_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OOS WebSocket target never receives a TCP connection at all.

    Playwright's WebSocketRoute defaults to *not* connecting to the real
    server unless the handler calls connect_to_server(); this test proves
    that default is actually reached for an unauthorized destination — by
    checking whether the raw TCP-level connection was ever attempted, not
    just whether a WS handshake "succeeded" — using a bare TCP accept
    counter as the target (no WS protocol needed to prove a connection
    attempt occurred).
    """
    accepted: list[str] = []

    class _RecordingHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            accepted.append(str(self.client_address))
            self.request.close()

    socketserver.TCPServer.allow_reuse_address = True
    ws_httpd = socketserver.TCPServer(("127.0.0.1", 0), _RecordingHandler)
    ws_port = ws_httpd.server_address[1]
    ws_thread = threading.Thread(target=ws_httpd.serve_forever, daemon=True)
    ws_thread.start()

    directory = tmp_path / "in_scope"
    directory.mkdir()
    index_html = f"""<html><body>
    <script>
    try {{ new WebSocket('ws://127.0.0.1:{ws_port}/'); }} catch (e) {{}}
    </script>
    </body></html>"""
    (directory / "index.html").write_text(index_html)
    httpd, port, thread = _serve(directory)
    monkeypatch.setattr(browser_probe, "allow_browser_navigation", _allow_only_port(port))

    try:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.webkit.launch(headless=True)
            except Exception as exc:  # pragma: no cover - environment without webkit binary
                pytest.skip(f"WebKit browser binary not available: {exc}")
            try:
                browser_context = await browser.new_context()
                context = _context(tmp_path)
                blocked_counts: dict[str, int] = {}
                await browser_probe._install_scope_request_guard(
                    browser_context, context, blocked_counts
                )
                page = await browser_context.new_page()
                await page.goto(
                    f"http://127.0.0.1:{port}/index.html",
                    wait_until="load",
                    timeout=5000,
                )
                await page.wait_for_timeout(500)
            finally:
                await browser.close()
    finally:
        ws_httpd.shutdown()
        ws_httpd.server_close()
        ws_thread.join(timeout=2)
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)

    assert accepted == []
    assert blocked_counts.get("websocket", 0) >= 1


@pytest.mark.asyncio
async def test_window_open_popup_to_out_of_scope_host_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, oos_server: int
) -> None:
    """A window.open() popup inherits the same context-level guard as the opener.

    A page-scoped route (the pre-fix implementation) would leave a popup
    page — a new Playwright Page created in the same browser context —
    completely unguarded. This proves the popup's own top-level navigation
    to an OOS host is blocked, not just requests made by the original page.
    """
    directory = tmp_path / "in_scope"
    directory.mkdir()
    index_html = f"""<html><body>
    <script>window.open('http://127.0.0.1:{oos_server}/frame.html', '_blank');</script>
    </body></html>"""
    (directory / "index.html").write_text(index_html)
    httpd, port, thread = _serve(directory)
    monkeypatch.setattr(browser_probe, "allow_browser_navigation", _allow_only_port(port))

    try:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.webkit.launch(headless=True)
            except Exception as exc:  # pragma: no cover - environment without webkit binary
                pytest.skip(f"WebKit browser binary not available: {exc}")
            try:
                browser_context = await browser.new_context()
                context = _context(tmp_path)
                blocked_counts: dict[str, int] = {}
                await browser_probe._install_scope_request_guard(
                    browser_context, context, blocked_counts
                )
                page = await browser_context.new_page()
                await page.goto(
                    f"http://127.0.0.1:{port}/index.html",
                    wait_until="load",
                    timeout=5000,
                )
                await page.wait_for_timeout(500)
            finally:
                await browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)

    # The opener's own navigation was to the in-scope host; any blocked
    # `document` request had to come from the popup's own top-level nav.
    assert blocked_counts.get("document", 0) >= 1
