"""Mandatory adversarial proof (mission Phase 16): does `ScopeEnforcingProxy`
actually stop a process that ignores its own `-proxy` configuration and opens
a raw socket directly?

The honest answer, and the one `core/collection/crawler_proxy.py` already
documents in prose, is **no** — an application-level HTTP/HTTPS forward
proxy has no way to intercept a raw `socket.connect()` that never goes
through an HTTP client's proxy-selection logic in the first place. This test
demonstrates that concretely with a real subprocess and a real local server,
rather than leaving it as an assertion in a docstring nobody verified.

Because that gap is real, Hydra classifies collectors explicitly instead of
claiming universal confinement: `PROXY_VERIFIED_TOOLS` in
`core/collection/crawler_proxy.py` lists only the tools whose real installed
binaries were driven through `tests/test_crawler_confinement_live.py` and
shown to route every connection through `-proxy`. Any other plugin using
`_crawler_confinement` gets an explicit `UNTRUSTED_NETWORK_TOOL` warning
instead of a silent, unverified claim of confinement — verified here too.
"""

from __future__ import annotations

import http.server
import socketserver
import subprocess
import sys
import threading
from collections.abc import Iterator

import pytest

from config.settings import Settings
from core.collection.crawler_proxy import PROXY_VERIFIED_TOOLS
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.httpx import HttpxPlugin


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.end_headers()


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def evil_server() -> Iterator[int]:
    _CountingHandler.hits = []
    httpd, port, thread = _serve(_CountingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def test_raw_socket_bypass_is_not_stopped_by_the_confinement_proxy(evil_server: int) -> None:
    """A managed collector that opens a raw socket instead of going through
    its configured HTTP client entirely bypasses `ScopeEnforcingProxy` — it
    never speaks the proxy protocol at all, so there is nothing for the
    proxy to authorize or deny. Proven with a real subprocess, a real
    socket, and a real local server counting real TCP connections — not by
    inspecting Hydra's own output.
    """
    script = (
        "import socket\n"
        f"s = socket.create_connection(('127.0.0.1', {evil_server}), timeout=5)\n"
        "s.sendall(b'GET / HTTP/1.1\\r\\nHost: evil\\r\\nConnection: close\\r\\n\\r\\n')\n"
        "s.recv(1024)\n"
        "s.close()\n"
    )
    # Deliberately set HTTP_PROXY/HTTPS_PROXY as Hydra would for a confined
    # tool — a raw socket.connect() consults neither, which is exactly the
    # gap being demonstrated.
    env = {
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(  # noqa: S603 - fixed argv, no untrusted input
        [sys.executable, "-c", script],
        env=env,
        timeout=10,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert len(_CountingHandler.hits) == 1, (
        "expected the raw-socket child process to reach the evil server "
        "directly, proving an application-level HTTP proxy cannot intercept "
        "a connection that never uses an HTTP client's proxy logic"
    )


def test_only_live_verified_tools_are_treated_as_proxy_confined() -> None:
    """`PROXY_VERIFIED_TOOLS` must name exactly the tools/collectors whose
    real binaries/engines/mechanisms were driven through the live
    confinement test — not be silently widened to cover one nobody has
    actually verified, and not left out just because it shares a code path
    with something that IS verified (that exact assumption would have missed
    the real `cloud_bucket_enum`/`ScopeEnforcingProxy` authorization-operation
    mismatch bug `tests/test_urllib_confinement_live.py` surfaced).
    """
    assert PROXY_VERIFIED_TOOLS == frozenset(
        {
            "katana",
            "hakrawler",
            "nuclei",
            "httpx",
            "browser_probe",
            "soft404_check",
            "param_fuzz",
            "cloud_bucket_enum",
        }
    )


@pytest.mark.asyncio
async def test_unverified_tool_gets_untrusted_network_tool_warning(tmp_path) -> None:
    """Any plugin using `_crawler_confinement` whose name is not in
    `PROXY_VERIFIED_TOOLS` must get an explicit `UNTRUSTED_NETWORK_TOOL`
    warning rather than silently inheriting an unverified confinement claim.
    `NaabuPlugin` never calls `_crawler_confinement` in its own `run()` — it
    is reused here purely as a real, already-registered plugin instance
    whose name ("naabu") is not in the verified set, to exercise the guard
    without registering a new fake plugin class (which would pollute
    `ReconPlugin._registry` for every other test in the same process).
    """
    from modules.naabu import NaabuPlugin

    settings = Settings(project_root=tmp_path)
    plugin = NaabuPlugin(settings)
    assert plugin.name not in PROXY_VERIFIED_TOOLS

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds(["seed.untrusted-test.internal"])
    context = PipelineContext(
        targets=[DomainTarget(domain="seed.untrusted-test.internal")],
        output_dir=output_dir,
        collection_scope=scope,
        run_id="untrusted-tool",
    )

    async with plugin._crawler_confinement(context):
        pass

    assert any("UNTRUSTED_NETWORK_TOOL" in w for w in context.warnings)
    assert any("naabu" in w for w in context.warnings)


@pytest.mark.asyncio
async def test_verified_tool_gets_no_untrusted_network_tool_warning(tmp_path) -> None:
    """The converse: a tool that IS in `PROXY_VERIFIED_TOOLS` must not be
    flagged, so the warning stays a signal, not noise on every run."""
    from modules.katana import KatanaPlugin

    settings = Settings(project_root=tmp_path)
    plugin = KatanaPlugin(settings)
    assert plugin.name in PROXY_VERIFIED_TOOLS

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds(["seed.trusted-test.internal"])
    context = PipelineContext(
        targets=[DomainTarget(domain="seed.trusted-test.internal")],
        output_dir=output_dir,
        collection_scope=scope,
        run_id="trusted-tool",
    )

    async with plugin._crawler_confinement(context):
        pass

    assert not any("UNTRUSTED_NETWORK_TOOL" in w for w in context.warnings)


@pytest.mark.asyncio
async def test_httpx_is_now_verified_and_gets_no_untrusted_network_tool_warning(tmp_path) -> None:
    """`httpx` joined `PROXY_VERIFIED_TOOLS` this turn — confirms it does not
    get flagged, mirroring the katana case above."""
    settings = Settings(project_root=tmp_path)
    plugin = HttpxPlugin(settings)
    assert plugin.name in PROXY_VERIFIED_TOOLS

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds(["seed.trusted-httpx-test.internal"])
    context = PipelineContext(
        targets=[DomainTarget(domain="seed.trusted-httpx-test.internal")],
        output_dir=output_dir,
        collection_scope=scope,
        run_id="trusted-httpx-tool",
    )

    async with plugin._crawler_confinement(context):
        pass

    assert not any("UNTRUSTED_NETWORK_TOOL" in w for w in context.warnings)
