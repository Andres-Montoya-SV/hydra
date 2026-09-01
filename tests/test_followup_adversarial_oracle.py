"""Section 16: follow-up from a CT SAN must not become an unauthorized
network connection.

seed.example is collected. Its certificate SAN list contains
www.seed.example (in scope) and evil.example (out of scope).

Expected:

* seed collected
* www eligible / collected if authorized
* evil observed
* evil NOT_ALLOWED
* evil ZERO real connections

Then www returns 302 → evil. Same expected set, plus seed/www evidence
survives the redirect walk.
"""

from __future__ import annotations

import asyncio
import http.server
import shutil
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.intel.engine import IntelEngine
from core.intel.model import CollectionStatus, IndicatorKind, ScopeStatus
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from core.runner import PipelineRunner, intel_config_for_pipeline
from modules.httpx import HttpxPlugin
from utils.files import read_lines, write_jsonl, write_lines

SEED = "seed.example"
WWW = "www.seed.example"
EVIL = "evil.example"


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
        self.wfile.write(b"reached - follow-up confinement failed")


def _make_redirect_handler(evil_port: int):
    class _RedirectHandler(_QuietHandler):
        hits: list[str] = []

        def do_GET(self) -> None:  # noqa: N802
            type(self).hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{evil_port}/from-www")
            self.end_headers()

    return _RedirectHandler


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


def _seed_context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    write_lines(output_dir / "resolved.txt", [SEED], base_dir=output_dir)
    write_jsonl(
        output_dir / "dnsx_records.jsonl",
        [{"host": SEED, "a": ["203.0.113.10"], "status_code": "NOERROR"}],
        base_dir=output_dir,
    )
    write_lines(output_dir / "alive.txt", [f"https://{SEED}/"], base_dir=output_dir)
    write_jsonl(
        output_dir / "httpx.json",
        [{"input": SEED, "url": f"https://{SEED}/", "host": SEED}],
        base_dir=output_dir,
    )
    write_jsonl(
        output_dir / "ctlogs.jsonl",
        [
            {
                "id": 1,
                "common_name": SEED,
                "name_value": f"{SEED}\n{WWW}\n{EVIL}",
                "issuer_name": "Test CA",
                "serial_number": "aa11",
                "fingerprint_sha256": "ab" * 32,
                "query_domain": SEED,
            }
        ],
        base_dir=output_dir,
    )
    return PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED],
        resolved=[SEED],
        alive_urls=[f"https://{SEED}/"],
        output_dir=output_dir,
        run_id="followup-oracle",
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED, WWW]),
        metadata={"dns_probes": 1, "http_probes": 1},
    )


def test_followup_ct_san_marks_evil_observed_not_allowed(tmp_path: Path) -> None:
    context = _seed_context(tmp_path)
    settings = Settings(
        project_root=tmp_path,
        enable_followup_collection=True,
        max_discovery_depth=1,
        max_followup_indicators=10,
    )
    config = intel_config_for_pipeline(context, settings)
    engine = IntelEngine(config)
    engine.queue.mark_collected(IndicatorKind.DOMAIN, SEED, collector="seed")
    engine.ingest_artifacts(context.output_dir)
    engine.correlate()
    runner = PipelineRunner(settings)
    plan = runner.schedule_followup_collection(context, engine)

    assert WWW in plan.dns_targets
    assert EVIL not in plan.dns_targets
    assert EVIL not in plan.http_targets

    evil_entity = engine.entities.get(f"domain:{EVIL}")
    assert evil_entity is not None, "evil SAN must be observed as an entity"
    assert evil_entity.scope_status is ScopeStatus.OUT_OF_SCOPE
    assert evil_entity.collection_status is CollectionStatus.NOT_ALLOWED
    assert any(obs.entity_id == evil_entity.entity_id for obs in engine.observations)

    www_item = engine.queue.get(IndicatorKind.DOMAIN, WWW)
    assert www_item is not None
    assert www_item.collection_status is CollectionStatus.IN_FLIGHT


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("httpx") is None, reason="httpx binary not installed")
async def test_followup_www_302_to_evil_gets_zero_connections(
    tmp_path: Path, evil_server: int
) -> None:
    """www (authorized follow-up) 302s to evil. The evil server is the
    oracle. Seed alive.txt must still contain the seed afterward."""
    redirect_cls = _make_redirect_handler(evil_server)
    redirect_cls.hits = []
    www_httpd, www_port, www_thread = _serve(redirect_cls)
    try:
        context = _seed_context(tmp_path)
        www_url = f"http://127.0.0.1:{www_port}/"
        # Follow-up HTTP uses the same plugin path as the runner: a file of
        # authorized targets. The planner's hostname list cannot bind our
        # ephemeral port, so the URL here is the authorized www stand-in
        # (127.0.0.1, in scope) whose Location names the unauthorized host.
        write_lines(
            context.output_dir / "followup_http_targets.txt",
            [www_url],
            base_dir=context.output_dir,
        )
        context.collection_scope = CollectionScope.from_seeds(
            ["127.0.0.1"], patterns=["127.0.0.1"], allow_private_network_targets=True
        )
        plugin = HttpxPlugin(Settings(project_root=tmp_path))
        suffix = "_followup_1"
        context.metadata["httpx_output_suffix"] = suffix
        await plugin.run(context, context.output_dir / "followup_http_targets.txt")
        await _wait_until(lambda: bool(redirect_cls.hits))
    finally:
        www_httpd.shutdown()
        www_httpd.server_close()
        www_thread.join(timeout=2)

    assert redirect_cls.hits, "authorized www stand-in must receive the follow-up request"
    assert _EvilHandler.hits == [], (
        "302 from an authorized follow-up host to evil.example (localhost "
        f"here) must produce ZERO connections; evil saw {_EvilHandler.hits}"
    )
    assert f"https://{SEED}/" in read_lines(
        context.output_dir / "alive.txt"
    ), "canonical seed alive.txt must survive the follow-up redirect walk"


@pytest.mark.asyncio
async def test_followup_empty_second_pass_does_not_drop_seed(tmp_path: Path) -> None:
    """Section 18 adjunct: a second empty follow-up must leave seed
    resolved/alive/httpx artifacts intact."""
    context = _seed_context(tmp_path)
    settings = Settings(
        project_root=tmp_path,
        enable_followup_collection=True,
        max_discovery_depth=1,
        max_followup_indicators=10,
    )
    runner = PipelineRunner(settings)
    dnsx = runner.tool_manager.get_plugin("dnsx")
    httpx = runner.tool_manager.get_plugin("httpx")
    assert dnsx and httpx

    async def empty_dnsx(ctx: PipelineContext, input_path: Path) -> PluginResult:
        suffix = str(ctx.metadata.get("dnsx_output_suffix") or "")
        write_lines(ctx.output_dir / f"resolved{suffix}.txt", [], base_dir=ctx.output_dir)
        write_jsonl(ctx.output_dir / f"dnsx_records{suffix}.jsonl", [], base_dir=ctx.output_dir)
        return PluginResult(success=True, output_path=ctx.output_dir / f"resolved{suffix}.txt")

    async def empty_httpx(ctx: PipelineContext, input_path: Path) -> PluginResult:
        suffix = str(ctx.metadata.get("httpx_output_suffix") or "")
        write_jsonl(ctx.output_dir / f"httpx{suffix}.json", [], base_dir=ctx.output_dir)
        write_lines(ctx.output_dir / f"alive{suffix}.txt", [], base_dir=ctx.output_dir)
        return PluginResult(success=True, output_path=ctx.output_dir / f"httpx{suffix}.json")

    dnsx.run = empty_dnsx  # type: ignore[method-assign]
    httpx.run = empty_httpx  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: name in {"dnsx", "httpx"}  # type: ignore[method-assign]
    runner.tool_manager.ensure_mandatory_tools = AsyncMock()

    seed_alive = read_lines(context.output_dir / "alive.txt")
    seed_resolved = read_lines(context.output_dir / "resolved.txt")
    await runner._maybe_collect_followups(context, context.output_dir / "resolved.txt")
    await runner._maybe_collect_followups(context, context.output_dir / "resolved.txt")

    assert read_lines(context.output_dir / "alive.txt") == seed_alive
    assert read_lines(context.output_dir / "resolved.txt") == seed_resolved
    assert SEED in context.resolved or SEED in seed_resolved
    assert f"https://{SEED}/" in seed_alive
