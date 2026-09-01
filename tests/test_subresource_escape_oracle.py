"""Sections 10–11: authorized page referencing unauthorized subresources.

The destination server is the oracle. An authorized page served from
``127.0.0.1`` embeds script/image/stylesheet/font/iframe/link targets on
``localhost``. CollectionScope authorizes only ``127.0.0.1``.

Covered collectors (where the binary/engine is installed):

* katana  — crawler follows links and may fetch page-referenced URLs
* hakrawler
* browser_probe — real WebKit + proxy= + route guard

nuclei is not driven here: a default template run is unbounded and not a
deterministic destination-oracle. It shares the same ``-proxy`` /
``ScopeEnforcingProxy`` path already proven in
``tests/test_crawler_proxy_flag_enforcement.py``.
"""

from __future__ import annotations

import asyncio
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
from modules.browser_probe import BrowserProbePlugin
from modules.hakrawler import HakrawlerPlugin
from modules.katana import KatanaPlugin
from utils.files import write_lines


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _EvilHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"reached - subresource confinement failed")


def _make_page_handler(evil_port: int):
    html = f"""<!doctype html>
<html><head>
  <link rel="stylesheet" href="http://localhost:{evil_port}/style.css">
  <link rel="preload" as="font" href="http://localhost:{evil_port}/font.woff">
</head><body>
  <a href="http://localhost:{evil_port}/">evil</a>
  <script src="http://localhost:{evil_port}/script.js"></script>
  <img src="http://localhost:{evil_port}/image.png">
  <iframe src="http://localhost:{evil_port}/frame"></iframe>
  <script>
    navigator.sendBeacon && navigator.sendBeacon("http://localhost:{evil_port}/beacon");
    fetch("http://localhost:{evil_port}/xhr").catch(function(){{}});
  </script>
</body></html>
""".encode()

    class _PageHandler(_QuietHandler):
        hits: list[str] = []

        def do_GET(self) -> None:  # noqa: N802
            type(self).hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html)

    return _PageHandler


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


async def _wait_until(predicate, *, timeout: float = 8.0, interval: float = 0.02) -> bool:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return bool(predicate())


@pytest.fixture
def evil_server() -> Iterator[int]:
    _EvilHandler.hits = []
    httpd, port, thread = _serve(_EvilHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )


def _context(tmp_path: Path, seed_url: str) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain="127.0.0.1")],
        output_dir=output_dir,
        collection_scope=_scope(),
    )
    context.alive_urls = [seed_url]
    context.httpx_results = [{"input": seed_url, "url": seed_url, "host": seed_url}]
    write_lines(output_dir / "alive.txt", [seed_url], base_dir=output_dir)
    return context


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("katana") is None, reason="katana binary not installed")
async def test_katana_page_subresources_never_reach_evil(
    tmp_path: Path, evil_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))

    page_cls = _make_page_handler(evil_server)
    page_cls.hits = []
    seed_httpd, seed_port, seed_thread = _serve(page_cls)
    seed_url = f"http://127.0.0.1:{seed_port}/"
    try:
        context = _context(tmp_path, seed_url)
        plugin = KatanaPlugin(Settings(project_root=tmp_path))
        await plugin.run(context, context.output_dir / "alive.txt")
        await _wait_until(lambda: bool(page_cls.hits))
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert page_cls.hits, "katana must fetch the authorized page"
    assert _EvilHandler.hits == [], (
        "katana must not fetch unauthorized script/image/css/iframe/link "
        f"targets; evil server saw {_EvilHandler.hits}"
    )


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("hakrawler") is None, reason="hakrawler binary not installed")
async def test_hakrawler_page_subresources_never_reach_evil(
    tmp_path: Path, evil_server: int
) -> None:
    page_cls = _make_page_handler(evil_server)
    page_cls.hits = []
    seed_httpd, seed_port, seed_thread = _serve(page_cls)
    seed_url = f"http://127.0.0.1:{seed_port}/"
    try:
        context = _context(tmp_path, seed_url)
        plugin = HakrawlerPlugin(Settings(project_root=tmp_path))
        await plugin.run(context, context.output_dir / "resolved.txt")
        await _wait_until(lambda: bool(page_cls.hits))
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert page_cls.hits, "hakrawler must fetch the authorized page"
    assert _EvilHandler.hits == [], (
        "hakrawler must not fetch unauthorized page-referenced URLs; "
        f"evil server saw {_EvilHandler.hits}"
    )


@pytest.mark.asyncio
async def test_browser_probe_subresources_never_reach_evil(
    tmp_path: Path, evil_server: int
) -> None:
    pytest.importorskip("playwright")
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        try:
            browser = await playwright.webkit.launch(headless=True)
        except Exception as exc:
            pytest.skip(f"WebKit browser binary not available: {exc}")
        else:
            await browser.close()

    page_cls = _make_page_handler(evil_server)
    page_cls.hits = []
    seed_httpd, seed_port, seed_thread = _serve(page_cls)
    seed_url = f"http://127.0.0.1:{seed_port}/"
    try:
        context = _context(tmp_path, seed_url)
        plugin = BrowserProbePlugin(Settings(project_root=tmp_path, enable_browser_probe=True))
        await plugin.run(context, tmp_path / "unused")
        await _wait_until(lambda: bool(page_cls.hits))
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert page_cls.hits, "WebKit must load the authorized document"
    assert _EvilHandler.hits == [], (
        "browser_probe must not fetch unauthorized script/image/font/iframe/"
        f"beacon/xhr; evil server saw {_EvilHandler.hits}"
    )
