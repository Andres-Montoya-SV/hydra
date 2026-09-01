"""Section 9: real destination-server proof that redirects cannot expand
authorization.

The authorized seed is ``127.0.0.1``; the unauthorized destination is
``localhost`` on a second real server. Those are different hostname strings
under CollectionScope even though both resolve to loopback — the same
pattern as tests/test_httpx_confinement_live.py.

Variants covered here (the absolute-URL 302 is already in
test_httpx_confinement_live.py):

* relative Location (same authorized host — MUST reach the seed server)
* scheme-relative Location (``//localhost:...`` — evil gets ZERO)
* dangerous schemes (javascript/data/file/about/vbscript) — never become
  a network destination; evil gets ZERO
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
from modules.httpx import HttpxPlugin
from utils.files import write_lines

pytestmark = pytest.mark.skipif(shutil.which("httpx") is None, reason="httpx binary not installed")


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
        self.wfile.write(b"reached - redirect confinement failed")


class _AllowedHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        if self.path == "/relative-hop":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"same-host relative hop ok")
            return
        location = getattr(self.server, "location", "/")  # type: ignore[attr-defined]
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


async def _wait_until(predicate, *, timeout: float = 5.0, interval: float = 0.02) -> bool:
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


def _context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain="127.0.0.1")],
        output_dir=output_dir,
        collection_scope=_scope(),
    )


async def _run_httpx(tmp_path: Path, seed_url: str) -> PipelineContext:
    context = _context(tmp_path)
    hosts_path = context.output_dir / "resolved.txt"
    write_lines(hosts_path, [seed_url], base_dir=context.output_dir)
    plugin = HttpxPlugin(Settings(project_root=tmp_path))
    await plugin.run(context, hosts_path)
    return context


@pytest.mark.asyncio
async def test_relative_redirect_stays_on_authorized_host(tmp_path: Path) -> None:
    """A same-host relative Location is authorization-preserving: the
    authorized server must receive the follow-up hop."""
    _AllowedHandler.hits = []
    seed_httpd, seed_port, seed_thread = _serve(_AllowedHandler)
    seed_httpd.location = "/relative-hop"  # type: ignore[attr-defined]
    try:
        await _run_httpx(tmp_path, f"http://127.0.0.1:{seed_port}/")
        await _wait_until(lambda: "/relative-hop" in _AllowedHandler.hits)
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert (
        "/" in _AllowedHandler.hits or _AllowedHandler.hits
    ), "authorized seed must receive the first request"
    assert (
        "/relative-hop" in _AllowedHandler.hits
    ), "same-host relative redirect must be followed on the authorized host"


@pytest.mark.asyncio
async def test_scheme_relative_redirect_to_evil_gets_zero_connections(
    tmp_path: Path, evil_server: int
) -> None:
    _AllowedHandler.hits = []
    seed_httpd, seed_port, seed_thread = _serve(_AllowedHandler)
    seed_httpd.location = f"//localhost:{evil_server}/secret"  # type: ignore[attr-defined]
    try:
        await _run_httpx(tmp_path, f"http://127.0.0.1:{seed_port}/")
        await _wait_until(lambda: bool(_AllowedHandler.hits))
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert _AllowedHandler.hits, "authorized seed must receive the first request"
    assert _EvilHandler.hits == [], (
        "scheme-relative Location to an unauthorized host must produce "
        "ZERO connections on the evil server"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        "javascript:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html,evil",
        "about:blank",
        "file:///etc/passwd",
    ],
)
async def test_dangerous_scheme_redirect_never_becomes_a_network_destination(
    tmp_path: Path, evil_server: int, location: str
) -> None:
    """These schemes must never be rewritten into a request that hits the
    evil server (or any other network destination)."""
    _AllowedHandler.hits = []
    seed_httpd, seed_port, seed_thread = _serve(_AllowedHandler)
    seed_httpd.location = location  # type: ignore[attr-defined]
    try:
        context = await _run_httpx(tmp_path, f"http://127.0.0.1:{seed_port}/")
        await _wait_until(lambda: bool(_AllowedHandler.hits))
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert _AllowedHandler.hits, "authorized seed must receive the first request"
    assert _EvilHandler.hits == [], f"{location!r} must never become a network destination"
    denials = [
        row
        for row in (context.metadata.get("network_requests") or [])
        if row.get("decision") == "DENY"
        and str(row.get("reason") or "").startswith("blocked_scheme:")
    ]
    assert denials, f"{location!r} must be recorded as blocked_scheme in the audit trail"
