"""Real nuclei binary + real ScopeEnforcingProxy + real CollectionScope.

`tests/test_crawler_confinement_live.py` proves this same property for
`katana`/`hakrawler` via redirect-following, since both crawl and follow
redirects by default. nuclei does not: `-fr`/`-follow-redirects` is
opt-in (confirmed against the real installed binary's `-h` output) and
`modules/nuclei.py` never passes it, so a redirect-escape test would
prove nothing for nuclei's actual default configuration.

nuclei's real out-of-scope-contact risk is different and already
documented with real evidence
(`docs/archive/FINAL_NETWORK_CONFINEMENT_AUDIT_2026-08-31.md`): its own
*templates* can declare an alternate destination via a raw-request
`@Host` override, independent of the scanned target's actual URL — e.g.
the real, shipped `azure-domain-tenant.yaml` template unconditionally
sends a request to `https://login.microsoftonline.com` regardless of
what's being scanned. This test reproduces that exact mechanism with a
minimal custom template pointed at a local "out of scope" server instead
of a real third-party host, so the test is self-contained and needs no
network access — proving nuclei's own template-driven host override,
routed through the real confinement proxy, never reaches an unauthorized
destination.

This does not go through `NucleiPlugin.run()` directly: that method's
fixed argv has no `-duc` (`-disable-update-check`), and a genuinely fresh
`$HOME` (needed to point nuclei at an isolated, single-template
directory rather than the real machine's full ~2,700-template corpus,
which would make this test slow and non-deterministic) makes nuclei's
own update check block for the better part of a minute waiting on
network I/O — unrelated to anything under test. Instead this drives the
same two real, unmodified production classes `NucleiPlugin` itself
uses — `core.collection.crawler_proxy.ScopeEnforcingProxy` and the real
`nuclei` binary — directly, exactly the "real binary + real confinement
proxy + real scope" property the katana/hakrawler tests check, with
`-duc` added only to keep the test fast and hermetic.
"""

from __future__ import annotations

import asyncio
import http.server
import os
import shutil
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.intel.scope import CollectionScope


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
        self.wfile.write(b"reached - confinement failed to block this")


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def seed_server() -> Iterator[int]:
    httpd, port, thread = _serve(_QuietHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


@pytest.fixture
def oos_server() -> Iterator[int]:
    _CountingHandler.hits = []
    httpd, port, thread = _serve(_CountingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _write_oos_escape_template(templates_dir: Path, oos_port: int) -> None:
    """A minimal template using the real `@Host` raw-request override
    mechanism — the same one the real, shipped `azure-domain-tenant.yaml`
    template uses to unconditionally contact
    login.microsoftonline.com — pointed at a local port instead of a
    real third-party host. `localhost` (not `127.0.0.1`) is used
    deliberately: same loopback interface, but a different hostname
    *string* under `CollectionScope`'s real, unmodified classification,
    exactly like the katana/hakrawler tests' seed-vs-redirect-target
    distinction — proving the proxy's authorization is host-string-based,
    not "is this address routable" based.
    """
    templates_dir.mkdir(parents=True, exist_ok=True)
    (templates_dir / "oos_escape.yaml").write_text(
        f"""\
id: test-oos-escape
info:
  name: test oos escape
  author: test
  severity: info
http:
  - raw:
      - |
        @Host: http://localhost:{oos_port}
        GET /leaked HTTP/1.1
        Host: localhost

    matchers:
      - type: status
        status:
          - 200
"""
    )


async def _run_nuclei_through_proxy(
    tmp_path: Path, seed_port: int, oos_port: int, *, use_proxy: bool
) -> tuple[int, str, str, ScopeEnforcingProxy]:
    fake_home = tmp_path / "home"
    _write_oos_escape_template(fake_home / "nuclei-templates", oos_port)
    list_file = tmp_path / "targets.txt"
    list_file.write_text(f"http://127.0.0.1:{seed_port}/\n")

    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    proxy = ScopeEnforcingProxy(scope, capability="nuclei")
    await proxy.start()
    try:
        env = dict(os.environ)
        env["HOME"] = str(fake_home)
        args = [
            "nuclei",
            "-l",
            str(list_file),
            "-silent",
            "-jsonl",
            "-duc",
        ]
        if use_proxy:
            args.extend(["-proxy", proxy.proxy_url])
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return proc.returncode or 0, stdout.decode(), stderr.decode(), proxy
    finally:
        await proxy.stop()


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei binary not installed")
async def test_nuclei_template_host_override_escape_is_blocked_by_confinement_proxy(
    tmp_path: Path, seed_server: int, oos_server: int
) -> None:
    """The real safety property: a real nuclei template using the real
    `@Host` raw-request override to contact a destination the scanned
    target never pointed it at must never reach that destination once
    routed through the real confinement proxy."""
    _, _stdout, _stderr, proxy = await _run_nuclei_through_proxy(
        tmp_path, seed_server, oos_server, use_proxy=True
    )

    assert _CountingHandler.hits == [], (
        "nuclei's own template-driven @Host override reached the OOS "
        "destination — confinement proxy failed to block it"
    )
    assert any(
        denied.host == "localhost" and denied.capability == "nuclei" for denied in proxy.denied
    ), [(d.host, d.capability, d.method) for d in proxy.denied]


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei binary not installed")
async def test_nuclei_template_host_override_reaches_real_server_without_confinement(
    tmp_path: Path, seed_server: int, oos_server: int
) -> None:
    """Negative control for the test above: proves the `@Host` override
    template genuinely *can* reach the OOS server (so the previous test's
    zero hits is the proxy blocking it, not the template silently
    failing to fire for an unrelated reason) — the exact same real
    binary and real template, with no confinement proxy in the way."""
    _, _stdout, _stderr, _proxy = await _run_nuclei_through_proxy(
        tmp_path, seed_server, oos_server, use_proxy=False
    )

    assert _CountingHandler.hits == ["/leaked"], (
        "sanity check failed: the @Host-override template should reach the "
        "OOS server directly when no confinement proxy is involved at all"
    )
