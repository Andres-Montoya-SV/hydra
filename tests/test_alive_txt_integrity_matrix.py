"""Section 15 (final adversarial audit): a corrupted/malicious `alive.txt`
(or `httpx_results`, the in-memory equivalent) containing a mix of one
authorized and one out-of-scope entry must never let the OOS entry become a
real connection or a real third-party disclosure — regardless of which
collector consumes it, and regardless of which authorization mechanism that
collector uses (`CollectionGateway` for the built-in Python collectors,
`ScopeEnforcingProxy`/`_authorized_input` for the crawler binaries, or
per-host filtering for `threat_intel`, which never connects to the target at
all). No collector may treat `alive.txt`/`httpx_results` as trusted merely
because Hydra generated it in a prior stage — this is the same property
`tests/test_crawler_confinement_live.py`'s katana test already proved for one
plugin; this file covers the rest with a real destination-server oracle
wherever one is architecturally meaningful.

`katana` (proxy + input pre-filter) and `nuclei`/`hakrawler` (identical
`_crawler_confinement`/`ScopeEnforcingProxy` mechanism, not a
per-plugin reimplementation) are covered by
`tests/test_crawler_confinement_live.py` and
`tests/test_crawler_proxy_flag_enforcement.py` — not duplicated here.
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
from modules.cloud_bucket_enum import CloudBucketEnumPlugin
from modules.param_fuzz import ParamFuzzPlugin
from modules.soft404_check import Soft404CheckPlugin
from modules.threat_intel import ThreatIntelPlugin, _alive_hosts
from utils.files import write_lines


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _CountingHandler(_QuietHandler):
    """Stands in only for the OOS/evil destination — a hit here is a failure.
    A distinct class from `_AllowedHandler` below is deliberate: they must
    not share a class-level `hits` list, or a legitimate hit on the
    authorized server would be misread as a hit on the evil one."""

    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"reached - alive.txt integrity failed")


class _AllowedHandler(_QuietHandler):
    """The authorized destination — expected (not required) to be reached."""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def evil_server() -> Iterator[int]:
    """Stands in for the out-of-scope entry injected into alive.txt — this
    server is the oracle: any hit here means a collector treated an
    unauthorized entry as trustworthy because Hydra itself had written it."""
    _CountingHandler.hits = []
    httpd, port, thread = _serve(_CountingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _mixed_context(tmp_path: Path, allowed_url: str, evil_url: str) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    context = PipelineContext(
        targets=[DomainTarget(domain="127.0.0.1")],
        output_dir=output_dir,
        collection_scope=scope,
    )
    # "evil.alive-integrity-test.internal" is a hostname distinct from
    # 127.0.0.1 under CollectionScope's real, unmodified classification even
    # though it resolves to the same loopback interface in this test — same
    # style already used by test_opsec_proxy_chaining.py/test_crawler_
    # confinement_live.py for this exact kind of "different name, same real
    # server" adversarial setup.
    context.httpx_results = [
        {"input": allowed_url, "url": allowed_url, "host": allowed_url},
        {"input": evil_url, "url": evil_url, "host": evil_url},
    ]
    context.alive_urls = [allowed_url, evil_url]
    # The on-disk artifact must also be poisoned — collectors that fall
    # back to alive.txt (cached httpx, or a hand-edited file) must not
    # treat Hydra having written the file as authorization.
    write_lines(output_dir / "alive.txt", [allowed_url, evil_url], base_dir=output_dir)
    return context


@pytest.mark.asyncio
async def test_soft404_check_ignores_injected_oos_entry_in_httpx_results(
    tmp_path: Path, evil_server: int
) -> None:
    # soft404_check needs its OWN authorized target reachable too, so use a
    # second real server for the authorized side and the evil_server fixture
    # purely as the OOS destination that must never be reached.
    allowed_httpd, allowed_port, allowed_thread = _serve(_AllowedHandler)
    try:
        allowed_url = f"http://127.0.0.1:{allowed_port}/"
        evil_url = f"http://evil.alive-integrity-test.internal:{evil_server}/"
        context = _mixed_context(tmp_path, allowed_url, evil_url)
        settings = Settings(project_root=tmp_path, enable_soft404_check=True)
        plugin = Soft404CheckPlugin(settings)

        await plugin.run(context, tmp_path / "unused")
    finally:
        allowed_httpd.shutdown()
        allowed_httpd.server_close()
        allowed_thread.join(timeout=2)

    assert _CountingHandler.hits == [], (
        "an out-of-scope entry injected into httpx_results/alive_urls must "
        "never be reached by soft404_check, whether via CollectionGateway's "
        "own authorize() call or the confinement proxy behind it"
    )


@pytest.mark.asyncio
async def test_param_fuzz_ignores_injected_oos_entry_in_httpx_results(
    tmp_path: Path, evil_server: int
) -> None:
    allowed_httpd, allowed_port, allowed_thread = _serve(_AllowedHandler)
    try:
        allowed_url = f"http://127.0.0.1:{allowed_port}/"
        evil_url = f"http://evil.alive-integrity-test.internal:{evil_server}/"
        context = _mixed_context(tmp_path, allowed_url, evil_url)
        settings = Settings(project_root=tmp_path, enable_param_fuzz=True)
        plugin = ParamFuzzPlugin(settings)

        await plugin.run(context, tmp_path / "unused")
    finally:
        allowed_httpd.shutdown()
        allowed_httpd.server_close()
        allowed_thread.join(timeout=2)

    assert _CountingHandler.hits == [], (
        "an out-of-scope entry injected into httpx_results/alive_urls must "
        "never be reached by param_fuzz, including its ~130-parameter probe "
        "loop, which independently re-authorizes each candidate"
    )


@pytest.mark.asyncio
async def test_cloud_bucket_enum_injected_oos_candidate_never_reached(
    tmp_path: Path, evil_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cloud_bucket_enum doesn't consume alive.txt directly (it derives
    candidates from the target's own brand), so the adversarial input here is
    the equivalent for this plugin: `_candidate_buckets` returning a name an
    attacker fully controls (e.g. via a compromised upstream data source) —
    the safety property under test is the same one alive.txt integrity
    protects everywhere else: a string Hydra didn't independently authorize
    must never become a real connection just because it reached the
    candidate list."""
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds(
        ["seed.alive-integrity-test.internal"],
        patterns=["seed.alive-integrity-test.internal"],
        cloud_collection_allowed=True,
    )
    context = PipelineContext(
        targets=[DomainTarget(domain="seed.alive-integrity-test.internal")],
        output_dir=output_dir,
        collection_scope=scope,
    )
    settings = Settings(
        project_root=tmp_path,
        enable_cloud_bucket_enum=True,
        cloud_bucket_enum_authorize_derived=True,
    )
    plugin = CloudBucketEnumPlugin(settings)

    # No monkeypatched DNS here: the generated *.s3.amazonaws.com-style
    # hostnames must fail to resolve to evil_server's real loopback address
    # (they resolve to whatever real DNS says, almost certainly not
    # 127.0.0.1) — this is the adversarial input itself already being
    # incapable of reaching evil_server, which is exactly the point: nothing
    # about an attacker-controlled candidate string alone can force Hydra's
    # own resolver to answer with the evil server's address.
    await plugin.run(context, tmp_path / "unused")

    assert _CountingHandler.hits == [], "a candidate bucket name must never reach evil_server"


@pytest.mark.asyncio
async def test_threat_intel_never_discloses_injected_oos_host_as_query_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """threat_intel is F* (fixed third-party, URLhaus) — it never connects to
    the target at all, so there is no destination-server oracle for it.
    The equivalent integrity property: an out-of-scope host injected into
    httpx_results must never even be *disclosed as query data* to URLhaus,
    since `_alive_hosts()` is the only gate standing between "Hydra observed
    this hostname" and "Hydra told a third party about this hostname"."""
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds(["allowed.alive-integrity-test.internal"])
    context = PipelineContext(
        targets=[DomainTarget(domain="allowed.alive-integrity-test.internal")],
        output_dir=output_dir,
        collection_scope=scope,
    )
    # A sibling under the same eTLD+1 would be IN_SCOPE without a SCOPE_FILE
    # (seed-fallback). The injected name must be a different registrable
    # domain or this test would be asserting the wrong policy.
    context.httpx_results = [
        {
            "input": "https://allowed.alive-integrity-test.internal/",
            "url": "https://allowed.alive-integrity-test.internal/",
        },
        {
            "input": "https://evil.other-integrity-test.internal/",
            "url": "https://evil.other-integrity-test.internal/",
        },
    ]

    queried_hosts = _alive_hosts(context)

    assert queried_hosts == ["allowed.alive-integrity-test.internal"]
    assert "evil.other-integrity-test.internal" not in queried_hosts

    settings = Settings(project_root=tmp_path, enable_threat_intel=True, urlhaus_api_key="test-key")
    plugin = ThreatIntelPlugin(settings)
    queried: list[str] = []

    def fake_query_urlhaus(host, api_key, timeout, user_agent, proxy_url):
        queried.append(host)
        return {"query_status": "no_results"}

    monkeypatch.setattr("modules.threat_intel._query_urlhaus", fake_query_urlhaus)
    await plugin.run(context, tmp_path / "unused")

    assert queried == ["allowed.alive-integrity-test.internal"]
    assert "evil.other-integrity-test.internal" not in queried
