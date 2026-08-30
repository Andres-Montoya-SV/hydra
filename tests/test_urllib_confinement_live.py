"""Real urllib request (via `core/http_probe.py:http_get`) + real
ScopeEnforcingProxy, driven through the actual plugin `.run()` methods for
all three plugins that share this mechanism: `soft404_check`, `param_fuzz`,
`cloud_bucket_enum`.

Before a prior turn, all three called `http_get(url,
proxy_url=self.settings.outbound_proxy_url)` — `None` unless an external
OPSEC-hiding proxy was configured. In the default configuration, that meant
urllib did its own independent DNS resolution and connection, completely
outside Hydra's confinement proxy — the same DNS-rebinding/TOCTOU gap closed
for httpx and the browser around the same time. All three share the
identical `http_get(..., proxy_url=...)` call shape; this file proves it
live for each of them against a real local server, which is also what
qualifies each for `core/collection/crawler_proxy.py:PROXY_VERIFIED_TOOLS` —
a live-discovered bug (a real run against `virusbarrier.xyz` produced a false
`UNTRUSTED_NETWORK_TOOL` warning for `param_fuzz`, whose own text claimed its
"real binary" hadn't been verified — `param_fuzz` has no binary at all, it is
this exact urllib mechanism) is what prompted actually writing these two
missing tests instead of assuming the shared call shape was equivalent to
being verified.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from config.settings import Settings
from core.collection.gateway import CollectionGateway
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.cloud_bucket_enum import CloudBucketEnumPlugin
from modules.param_fuzz import ParamFuzzPlugin
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


@pytest.mark.asyncio
async def test_param_fuzz_reaches_authorized_target_through_confinement_proxy(
    tmp_path: Path, target_server: int
) -> None:
    """Same property as soft404_check, for param_fuzz: the baseline request
    (and every subsequent per-parameter probe) must reach a real authorized
    local server through the real confinement proxy."""
    url = f"http://127.0.0.1:{target_server}/"
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    settings = Settings(project_root=tmp_path, enable_param_fuzz=True)
    plugin = ParamFuzzPlugin(settings)
    context = _context_for(tmp_path, scope, url)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert _CountingHandler.hits, "authorized target should have been reached through the proxy"


@pytest.mark.asyncio
async def test_param_fuzz_in_scope_hostname_resolving_private_ip_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_server: int
) -> None:
    """DNS-rebinding/TOCTOU scenario for param_fuzz's real urllib baseline
    request: an in-scope hostname resolving to the real server's own
    loopback address must never actually be reached."""

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)

    url = f"http://rebind.param-fuzz-live-test.internal:{target_server}/"
    scope = CollectionScope.from_seeds(["rebind.param-fuzz-live-test.internal"])
    settings = Settings(project_root=tmp_path, enable_param_fuzz=True)
    plugin = ParamFuzzPlugin(settings)
    context = _context_for(tmp_path, scope, url)

    await plugin.run(context, tmp_path / "unused")

    assert _CountingHandler.hits == [], (
        "an in-scope hostname that resolves to a private/loopback address "
        "must never be reached by the real urllib request"
    )


@pytest.mark.asyncio
async def test_param_fuzz_gateway_http_get_rejects_a_plain_string(
    tmp_path: Path, target_server: int
) -> None:
    """Same structural guarantee `tests/test_collection_gateway.py` proves
    generically, demonstrated at param_fuzz's own call site: the
    `CollectionGateway` it constructs (`capability="param_fuzz"`) must
    reject a raw string passed to `http_get()` with `TypeError` — never
    silently forward it to `core/http_probe.py` — and the real server must
    never see a connection for the rejected call."""
    scope = CollectionScope.from_seeds(
        ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
    )
    async with CollectionGateway(scope, capability="param_fuzz") as gateway:
        with pytest.raises(TypeError):
            await gateway.http_get(
                f"http://127.0.0.1:{target_server}/",  # type: ignore[arg-type]
                timeout=5,
            )
    assert (
        _CountingHandler.hits == []
    ), "a raw string rejected by http_get() must never reach the real server"


def _cloud_bucket_context(
    tmp_path: Path, scope: CollectionScope, seed_domain: str
) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain=seed_domain)],
        output_dir=output_dir,
        collection_scope=scope,
    )


@pytest.mark.asyncio
async def test_cloud_bucket_enum_reaches_authorized_target_through_confinement_proxy(
    tmp_path: Path, target_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cloud_bucket_enum builds real `*.s3.amazonaws.com`-shaped URLs so that
    `authorize_active_indicator`'s cloud-endpoint opt-in logic actually
    engages (it keys off the hostname suffix, not an arbitrary domain) —
    `_provider_url` here keeps that real cloud-suffixed hostname (so
    authorization is exercised unmodified) but adds the local test server's
    port, and the confinement proxy's own resolver is redirected to
    `127.0.0.1` so the real TCP connection lands on the real local server
    instead of real AWS/GCS/Azure infrastructure.
    """

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    monkeypatch.setattr(
        "modules.cloud_bucket_enum._provider_url",
        lambda provider, bucket: f"http://{bucket}.s3.amazonaws.com:{target_server}/",
    )
    scope = CollectionScope.from_seeds(
        ["seed.cloud-live-test.internal"],
        patterns=["seed.cloud-live-test.internal"],
        cloud_collection_allowed=True,
        allow_private_network_targets=True,
    )
    settings = Settings(
        project_root=tmp_path,
        enable_cloud_bucket_enum=True,
        cloud_bucket_enum_authorize_derived=True,
    )
    plugin = CloudBucketEnumPlugin(settings)
    context = _cloud_bucket_context(tmp_path, scope, "seed.cloud-live-test.internal")

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert _CountingHandler.hits, "canary/candidate probes should reach the real server"


@pytest.mark.asyncio
async def test_cloud_bucket_enum_without_opt_in_never_reaches_any_server(
    tmp_path: Path, target_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the explicit `CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED` opt-in, the
    plugin must skip entirely — zero requests, not merely zero *successful*
    ones — even though a generated cloud endpoint would otherwise pass the
    real confinement proxy exactly like the test above."""
    monkeypatch.setattr(
        "modules.cloud_bucket_enum._provider_url",
        lambda provider, bucket: f"http://{bucket}.s3.amazonaws.com:{target_server}/",
    )
    scope = CollectionScope.from_seeds(
        ["seed.cloud-live-test.internal"], patterns=["seed.cloud-live-test.internal"]
    )
    settings = Settings(
        project_root=tmp_path, enable_cloud_bucket_enum=True
    )  # cloud_bucket_enum_authorize_derived left at its False default
    plugin = CloudBucketEnumPlugin(settings)
    context = _cloud_bucket_context(tmp_path, scope, "seed.cloud-live-test.internal")

    result = await plugin.run(context, tmp_path / "unused")

    assert result.skipped
    assert _CountingHandler.hits == []


@pytest.mark.asyncio
async def test_cloud_bucket_enum_in_scope_hostname_resolving_private_ip_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_server: int
) -> None:
    """DNS-rebinding/TOCTOU scenario for cloud_bucket_enum: even with cloud
    collection explicitly authorized, a generated bucket hostname that
    resolves to a *different* private/loopback address (not the real local
    server used to prove the ALLOW case above) must never actually be
    reached — the confinement proxy connects to the validated IP, and
    validation itself denies a private/loopback answer by default."""

    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    monkeypatch.setattr(
        "modules.cloud_bucket_enum._provider_url",
        lambda provider, bucket: f"http://{bucket}.s3.amazonaws.com:{target_server}/",
    )
    scope = CollectionScope.from_seeds(
        ["seed.cloud-live-test.internal"],
        patterns=["seed.cloud-live-test.internal"],
        cloud_collection_allowed=True,
        # allow_private_network_targets left at its False default — this is
        # what's actually under test.
    )
    settings = Settings(
        project_root=tmp_path,
        enable_cloud_bucket_enum=True,
        cloud_bucket_enum_authorize_derived=True,
    )
    plugin = CloudBucketEnumPlugin(settings)
    context = _cloud_bucket_context(tmp_path, scope, "seed.cloud-live-test.internal")

    await plugin.run(context, tmp_path / "unused")

    assert _CountingHandler.hits == [], (
        "a generated bucket hostname resolving to a private/loopback address "
        "must never be reached, even with cloud collection explicitly "
        "authorized — the private-IP block is independent of the cloud opt-in"
    )


@pytest.mark.asyncio
async def test_cloud_bucket_enum_genuine_dns_failure_never_reports_false_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Known, non-security limitation, verified safe: when a generated
    Azure/GCS candidate genuinely fails to resolve (a real NXDOMAIN, the
    normal "this bucket name isn't taken" signal for those two providers —
    S3 has wildcard DNS and doesn't have this case), the confinement proxy's
    own SSRF check now fails closed on that resolution error *before*
    `http_get` ever runs, denying the CONNECT tunnel. `core.http_probe.http_get`
    reports that denial as `status_code=None` with a "tunnel connection
    failed" error (not a DNS-error-shaped string `_is_dns_failure` recognizes),
    so `_classify` falls through to `"unknown"` rather than the more accurate
    `"not_found"` — a real accuracy regression for this one heuristic, but
    verified here to never degrade into a false `"exists_private"`/
    `"public_listable"` positive, which is the property that actually
    matters for safety.
    """

    async def _fake_resolve_always_fails(host: str) -> list[str]:
        raise OSError("simulated NXDOMAIN — this candidate name does not exist")

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve_always_fails)
    scope = CollectionScope.from_seeds(
        ["seed.cloud-live-test.internal"],
        patterns=["seed.cloud-live-test.internal"],
        cloud_collection_allowed=True,
    )
    settings = Settings(
        project_root=tmp_path,
        enable_cloud_bucket_enum=True,
        cloud_bucket_enum_authorize_derived=True,
    )
    plugin = CloudBucketEnumPlugin(settings)
    context = _cloud_bucket_context(tmp_path, scope, "seed.cloud-live-test.internal")

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert "0 existing bucket(s)" in result.message, (
        f"a real DNS-resolution failure must never be misclassified as an "
        f"existing bucket: {result.message}"
    )


@pytest.mark.asyncio
async def test_cloud_bucket_enum_gateway_http_get_rejects_a_plain_string(
    tmp_path: Path, target_server: int
) -> None:
    """Same structural guarantee `tests/test_collection_gateway.py` proves
    generically, demonstrated at cloud_bucket_enum's own call site: the
    `CollectionGateway` it constructs (`capability="cloud_enum"`) must
    reject a raw string passed to `http_get()` with `TypeError` — never
    silently forward it to `core/http_probe.py` — and the real server must
    never see a connection for the rejected call."""
    scope = CollectionScope.from_seeds(
        ["seed.cloud-live-test.internal"],
        patterns=["seed.cloud-live-test.internal"],
        cloud_collection_allowed=True,
        allow_private_network_targets=True,
    )
    async with CollectionGateway(scope, capability="cloud_enum") as gateway:
        with pytest.raises(TypeError):
            await gateway.http_get(
                f"http://reconprobe.s3.amazonaws.com:{target_server}/",  # type: ignore[arg-type]
                timeout=5,
            )
    assert (
        _CountingHandler.hits == []
    ), "a raw string rejected by http_get() must never reach the real server"
