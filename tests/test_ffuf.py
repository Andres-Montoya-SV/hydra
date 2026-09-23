"""`modules/ffuf.py` — hidden endpoint/content discovery.

`tests/fixtures/ffuf_real_output.json` is a real, full capture from an
actual `ffuf -w modules/data/ffuf_wordlist_quick.txt -e .bak,.old,.zip,.sql
-ac -rate 80 -t 30 -maxtime-job 30 -of json` run against a real local
test server during this module's own development — a `.git/config` and
a `.env` file that genuinely existed, plus a `README.md` that also
genuinely existed (to exercise the "not every discovered path is a
finding" low-severity path), all real 200s. Every other one of the
~900 real requests in that run got a real 404 and is correctly absent
from `results` — not filtered by this module, filtered by ffuf's own
default matcher never matching a 404 in the first place.
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
from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.ffuf import (
    FfufPlugin,
    _categorize_path,
    _read_ffuf_json,
    _row_to_finding,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
_FFUF_AVAILABLE = shutil.which("ffuf") is not None


async def _async_resolve(host: str) -> list[str]:
    return ["203.0.113.10"]


@pytest.fixture(autouse=True)
def _fake_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic `*.example.com` test hostnames never really resolve —
    stub the SSRF layer's resolver to a fixed public-looking address, the
    same pattern tests/test_collection_gateway.py uses, so authorization
    tests exercise scope logic, not real DNS."""
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["203.0.113.10"])
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _async_resolve)


def _real_rows() -> list[dict[str, object]]:
    return _read_ffuf_json(FIXTURES_DIR / "ffuf_real_output.json")


class TestRealFixtureParsing:
    def test_all_three_real_hits_are_parsed(self) -> None:
        rows = _real_rows()
        assert len(rows) == 3
        urls = {r["url"] for r in rows}
        assert urls == {
            "http://127.0.0.1:18082/.git/config",
            "http://127.0.0.1:18082/.env",
            "http://127.0.0.1:18082/README.md",
        }

    def test_git_config_is_critical(self) -> None:
        row = next(r for r in _real_rows() if r["url"].endswith(".git/config"))
        finding = _row_to_finding(row, "example.com")
        assert finding is not None
        assert finding["severity"] == "critical"

    def test_env_file_is_critical(self) -> None:
        row = next(r for r in _real_rows() if r["url"].endswith(".env"))
        finding = _row_to_finding(row, "example.com")
        assert finding is not None
        assert finding["severity"] == "critical"

    def test_readme_is_low_not_critical(self) -> None:
        """A genuine ffuf hit that isn't security-sensitive — proves the
        sensitive-path categorization correctly prioritizes .git/.env
        over an unremarkable 200, per the task's own explicit ask."""
        row = next(r for r in _real_rows() if r["url"].endswith("README.md"))
        finding = _row_to_finding(row, "example.com")
        assert finding is not None
        assert finding["severity"] == "low"
        assert finding["confidence_score"] < 90


class TestCategorizePath:
    def test_git_config_is_critical(self) -> None:
        assert _categorize_path("/.git/config") == ("critical", 90)

    def test_env_file_is_critical(self) -> None:
        assert _categorize_path("/.env") == ("critical", 90)

    def test_backup_extension_is_critical(self) -> None:
        assert _categorize_path("/config.php.bak") == ("critical", 90)

    def test_admin_panel_is_high(self) -> None:
        assert _categorize_path("/admin") == ("high", 75)

    def test_actuator_is_high(self) -> None:
        assert _categorize_path("/actuator/env") == ("high", 75)

    def test_generic_path_is_low(self) -> None:
        assert _categorize_path("/some-random-file.txt") == ("low", 50)

    def test_robots_txt_is_excluded_entirely(self) -> None:
        """The task's own explicit example: /robots.txt responding is not
        interesting — must not become a finding at all, not just a low
        severity one."""
        assert _categorize_path("/robots.txt") is None

    def test_sitemap_is_excluded_entirely(self) -> None:
        assert _categorize_path("/sitemap.xml") is None

    def test_favicon_is_excluded_entirely(self) -> None:
        assert _categorize_path("/favicon.ico") is None

    def test_leading_slash_and_case_do_not_affect_exclusion(self) -> None:
        assert _categorize_path("Robots.txt") is None
        assert _categorize_path("/ROBOTS.TXT") is None


class TestSoft404Interaction:
    """`modules/soft404_check.py`'s own signal is consulted BEFORE ffuf
    ever runs against a host — proven against the real interaction
    point (`context.metadata["soft_404_detected_hosts"]`), not just
    described."""

    def _context(self, tmp_path: Path, *, soft_404_hosts: list[str]) -> PipelineContext:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        (output_dir / "alive.txt").write_text(
            "https://soft404.example.com\nhttps://normal.example.com\n",
            encoding="utf-8",
        )
        context = PipelineContext(
            targets=[DomainTarget(domain="example.com")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["example.com"]),
        )
        context.metadata["soft_404_detected_hosts"] = soft_404_hosts
        return context

    @pytest.mark.asyncio
    async def test_a_soft_404_flagged_host_is_never_fuzzed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(project_root=tmp_path, enable_ffuf=True)
        context = self._context(tmp_path, soft_404_hosts=["soft404.example.com"])
        plugin = FfufPlugin(settings)

        fuzzed_hosts: list[str] = []

        async def fake_fuzz_host(self_, ctx, proxy_url, target, wordlist):  # noqa: ANN001
            fuzzed_hosts.append(target.hostname)
            return []

        monkeypatch.setattr(FfufPlugin, "_fuzz_host", fake_fuzz_host)
        await plugin.run(context, tmp_path / "unused")

        assert "soft404.example.com" not in fuzzed_hosts
        assert "normal.example.com" in fuzzed_hosts
        assert any("soft404_check" in w for w in context.warnings)

    @pytest.mark.asyncio
    async def test_all_hosts_soft_404_flagged_produces_a_clean_skip(self, tmp_path: Path) -> None:
        settings = Settings(project_root=tmp_path, enable_ffuf=True)
        context = self._context(
            tmp_path,
            soft_404_hosts=["soft404.example.com", "normal.example.com"],
        )
        plugin = FfufPlugin(settings)
        result = await plugin.run(context, tmp_path / "unused")
        assert result.skipped is True


class TestScopeEnforcementPreAuthorization:
    """Proves the pre-authorization layer: an out-of-scope host from
    alive.txt never becomes one of the AuthorizedCollectionTarget objects
    handed to `_fuzz_host` — the same class of test every other active
    plugin already has."""

    def _context(self, tmp_path: Path) -> PipelineContext:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        (output_dir / "alive.txt").write_text(
            "https://example.com\nhttps://evil-out-of-scope.example\n",
            encoding="utf-8",
        )
        return PipelineContext(
            targets=[DomainTarget(domain="example.com")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["example.com"]),
        )

    @pytest.mark.asyncio
    async def test_out_of_scope_host_never_reaches_fuzz_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(project_root=tmp_path, enable_ffuf=True)
        context = self._context(tmp_path)
        plugin = FfufPlugin(settings)

        fuzzed_hosts: list[str] = []

        async def fake_fuzz_host(self_, ctx, proxy_url, target, wordlist):  # noqa: ANN001
            fuzzed_hosts.append(target.hostname)
            return []

        monkeypatch.setattr(FfufPlugin, "_fuzz_host", fake_fuzz_host)
        await plugin.run(context, tmp_path / "unused")

        assert "example.com" in fuzzed_hosts
        assert "evil-out-of-scope.example" not in fuzzed_hosts


# --- Real-binary tests below: skipped when ffuf isn't installed, since the
# fixture-based tests above already cover parsing/categorization logic
# deterministically. These prove the two properties that can only be
# proven against a real subprocess: the confinement proxy actually blocks
# an out-of-scope target, and ffuf's own -maxtime-job actually enforces a
# real time ceiling rather than merely accepting the flag.


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # noqa: D102
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(404)
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


@pytest.mark.skipif(not _FFUF_AVAILABLE, reason="requires the real ffuf binary on PATH")
class TestRealConfinementBlocksOutOfScope:
    @pytest.mark.asyncio
    async def test_out_of_scope_target_never_receives_a_real_request(
        self, target_server: int
    ) -> None:
        # Scope only allows a name the target server does NOT answer to —
        # 127.0.0.1 itself is out of scope for this CollectionScope.
        scope = CollectionScope.from_seeds(["example.com"])
        proxy = ScopeEnforcingProxy(scope, capability="ffuf_test")
        await proxy.start()
        try:
            import tempfile

            with tempfile.TemporaryDirectory() as td:
                wordlist = Path(td) / "wl.txt"
                wordlist.write_text("a\nb\nc\n")
                out = Path(td) / "out.json"
                proc = await asyncio.create_subprocess_exec(
                    "ffuf",
                    "-w",
                    str(wordlist),
                    "-u",
                    f"http://127.0.0.1:{target_server}/FUZZ",
                    "-x",
                    proxy.proxy_url,
                    "-mc",
                    "all",
                    "-json",
                    "-o",
                    str(out),
                    "-of",
                    "json",
                    "-noninteractive",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=15)
        finally:
            await proxy.stop()

        assert _CountingHandler.hits == []


@pytest.mark.skipif(not _FFUF_AVAILABLE, reason="requires the real ffuf binary on PATH")
class TestRealMaxTimeJobBudgetIsEnforced:
    @pytest.mark.asyncio
    async def test_a_large_wordlist_stops_early_at_the_time_budget(
        self, target_server: int, tmp_path: Path
    ) -> None:
        wordlist = tmp_path / "big.txt"
        wordlist.write_text("\n".join(f"path{i}" for i in range(5000)))
        out = tmp_path / "out.json"

        proc = await asyncio.create_subprocess_exec(
            "ffuf",
            "-w",
            str(wordlist),
            "-u",
            f"http://127.0.0.1:{target_server}/FUZZ",
            "-p",
            "0.05",
            "-maxtime-job",
            "1",
            "-mc",
            "all",
            "-json",
            "-o",
            str(out),
            "-of",
            "json",
            "-noninteractive",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=10)

        # A real, enforced ceiling — not the full 5000-entry wordlist.
        assert len(_CountingHandler.hits) < 5000
        assert len(_CountingHandler.hits) > 0
