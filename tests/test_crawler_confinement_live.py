"""Real katana binary + real ScopeEnforcingProxy + real CollectionScope.

katana follows HTTP redirects internally by default (confirmed in
docs/NETWORK_BOUNDARY_AUDIT.md against the real installed binary's -h
output) — a gated -list only constrains its starting seed, not what it
decides to fetch next. This test makes the authorized seed 302 to a second
local server and proves katana's own redirect-follow attempt to that
destination never reaches it, now that the confinement proxy is wired in.

No monkeypatching of the authorization path: `127.0.0.1` (the seed) and
`localhost` (the redirect target) are different hostname strings under
`CollectionScope`'s real, unmodified classification even though both
resolve to the loopback interface — real host-based scope, real katana
subprocess, real local TCP servers throughout.
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
from modules.hakrawler import HakrawlerPlugin
from modules.katana import KatanaPlugin
from utils.files import read_jsonl, write_lines


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence per-request stderr noise
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"reached - confinement failed to block this")


def _make_redirect_handler(oos_port: int):
    class _RedirectHandler(_QuietHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{oos_port}/secret")
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
        httpd.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("katana") is None, reason="katana binary not installed")
async def test_katana_redirect_escape_is_blocked_by_confinement_proxy(
    tmp_path: Path, oos_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Environment-specific: some sandboxes pre-create ~/.config owned by a
    # different user, and katana fails outright ("could not init default
    # config") if it can't write there — unrelated to anything under test.
    fake_home = tmp_path / "home"
    (fake_home / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))

    seed_httpd, seed_port, seed_thread = _serve(_make_redirect_handler(oos_server))
    try:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        alive_path = output_dir / "alive.txt"
        seed_url = f"http://127.0.0.1:{seed_port}/"
        write_lines(alive_path, [seed_url], base_dir=output_dir)

        settings = Settings(project_root=tmp_path)
        context = PipelineContext(
            targets=[DomainTarget(domain="127.0.0.1")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(
                ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
            ),
        )
        context.alive_urls = [seed_url]

        plugin = KatanaPlugin(settings)
        result = await plugin.run(context, alive_path)
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert _CountingHandler.hits == [], (
        "katana's own redirect-follow reached the OOS destination — "
        "confinement proxy failed to block it"
    )
    assert any(
        "confinement proxy blocked" in w and "localhost" in w for w in context.warnings
    ), context.warnings

    if result.output_path is not None and result.output_path.exists():
        records = read_jsonl(result.output_path)
        assert not any("localhost" in str(r.get("url") or "") for r in records)
        assert not any(f":{oos_server}" in str(r.get("url") or "") for r in records)


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("katana") is None, reason="katana binary not installed")
async def test_katana_oos_url_injected_into_input_never_reaches_the_real_server(
    tmp_path: Path, oos_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Different attack shape from the redirect-escape test above: instead of
    katana discovering the OOS destination on its own mid-crawl, an
    out-of-scope URL is already sitting in `alive.txt` — simulating a bug in
    an upstream module (dnsx/httpx/etc.) leaking an unauthorized entry into a
    shared artifact this plugin trusts as its seed list, rather than a
    confinement failure specific to katana. Two independent layers should
    both catch this: `_authorized_input` must never forward the OOS entry
    into the `-list` file handed to the binary, and even if it somehow did,
    `ScopeEnforcingProxy` must still refuse the connection. Only the real
    destination server's hit count can actually prove which of those held —
    or that neither did — so that is what this test checks.
    """
    fake_home = tmp_path / "home"
    (fake_home / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    alive_path = output_dir / "alive.txt"
    oos_url = f"http://localhost:{oos_server}/leaked"
    write_lines(alive_path, [oos_url], base_dir=output_dir)

    settings = Settings(project_root=tmp_path)
    context = PipelineContext(
        targets=[DomainTarget(domain="127.0.0.1")],
        output_dir=output_dir,
        # Scope authorizes only 127.0.0.1 — "localhost" (the injected OOS
        # entry's host string) is a different, unauthorized name under this
        # scope's real, unmodified classification, exactly like the redirect
        # test above.
        collection_scope=CollectionScope.from_seeds(
            ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
        ),
    )
    context.alive_urls = [oos_url]

    plugin = KatanaPlugin(settings)
    result = await plugin.run(context, alive_path)

    assert _CountingHandler.hits == [], (
        "an out-of-scope URL already present in alive.txt (simulating a "
        "leak from another module) must never reach the real server, "
        "whether caught by the input-authorization pre-filter or the "
        "confinement proxy"
    )
    # The pre-filter layer specifically: the authorized copy of the input
    # file katana actually reads must not contain the OOS entry at all.
    authorized_files = list(output_dir.glob("authorized_katana_*"))
    for authorized_file in authorized_files:
        assert oos_url not in authorized_file.read_text(encoding="utf-8")
    assert result.skipped or result.success


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("hakrawler") is None, reason="hakrawler binary not installed")
async def test_hakrawler_redirect_escape_is_blocked_by_confinement_proxy(
    tmp_path: Path, oos_server: int
) -> None:
    """Same property as the katana test above, against the hakrawler binary.

    Empirically (not from -h docs), the installed hakrawler version refuses
    to report anything past a redirect landing on a different host than the
    seed unless -subs is passed ("No URLs were found... redirects to a
    subdomain... not included in the scope") — it appears to stop before
    ever requesting the destination, which the confinement proxy's empty
    `denied` list here corroborates (nothing to block because hakrawler
    itself never asked). The confinement proxy is still real defense in
    depth if that internal behavior changes or a template does reach out;
    this test's job is the safety property (never reached), not asserting
    which layer stopped it.
    """
    seed_httpd, seed_port, seed_thread = _serve(_make_redirect_handler(oos_server))
    try:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        seed_url = f"http://127.0.0.1:{seed_port}/"
        write_lines(output_dir / "alive.txt", [seed_url], base_dir=output_dir)

        settings = Settings(project_root=tmp_path)
        context = PipelineContext(
            targets=[DomainTarget(domain="127.0.0.1")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(
                ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
            ),
        )
        context.alive_urls = [seed_url]

        plugin = HakrawlerPlugin(settings)
        result = await plugin.run(context, output_dir / "resolved.txt")
    finally:
        seed_httpd.shutdown()
        seed_httpd.server_close()
        seed_thread.join(timeout=2)

    assert _CountingHandler.hits == [], (
        "hakrawler's own redirect-follow reached the OOS destination — "
        "confinement proxy failed to block it (whether via its own internal "
        "scope check or the confinement proxy, that host must never be reached)"
    )
    assert result.output_path is not None
    if result.output_path.exists():
        crawled = read_jsonl(result.output_path)
        assert not any("localhost" in str(r.get("url") or "") for r in crawled)
