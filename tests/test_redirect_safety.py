"""HTTP redirects are observations, never authorization to scan the destination."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.model import CollectionStatus, ScopeStatus
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules.browser_probe import _httpx_targets, allow_browser_navigation
from modules.hakrawler import HakrawlerPlugin
from modules.httpx import (
    HttpxPlugin,
    authorize_httpx_records,
    authorized_alive_url,
    httpx_final_url,
)
from modules.katana import KatanaPlugin
from modules.nuclei import NucleiPlugin
from modules.threat_intel import _alive_hosts
from modules.vuln_match import _collect_techs
from utils.files import read_jsonl, read_lines, write_jsonl, write_lines

SEED = "app.metaversejustice.com"
IN_SCOPE_DEST = "www.metaversejustice.com"
OOS = "login.vendor-cdn.net"
SCOPE_PATTERNS = ["metaversejustice.com", "*.metaversejustice.com"]


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=SCOPE_PATTERNS)


def _context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=_scope(),
    )


def _record(*, input_host: str, final_url: str, chain: list | None = None, **extra) -> dict:
    rec = {
        "input": input_host,
        "host": input_host,
        "url": final_url,
        "status_code": 200,
        "title": "ok",
        **extra,
    }
    if chain is not None:
        rec["chain"] = chain
    return rec


@pytest.mark.asyncio
async def test_in_scope_redirect_stays_an_active_target(tmp_path: Path, settings: Settings) -> None:
    """Authorized host → in-scope host: follow and treat the landing URL as alive."""
    context = _context(tmp_path)
    plugin = HttpxPlugin(settings)
    hosts = context.output_dir / "resolved.txt"
    write_lines(hosts, [SEED], base_dir=context.output_dir)
    landing = f"https://{IN_SCOPE_DEST}/dashboard"

    async def fake_exec(ctx, args, output_path, **kwargs):
        write_jsonl(
            output_path,
            [_record(input_host=SEED, final_url=landing, location=landing)],
            base_dir=ctx.output_dir,
        )
        return PluginResult(success=True, output_path=output_path, lines_produced=1)

    plugin._execute_self_output = fake_exec  # type: ignore[method-assign]
    await plugin.run(context, hosts)

    alive = read_lines(context.output_dir / "alive.txt")
    assert landing in alive
    assert all(OOS not in line for line in alive)
    assert context.alive_urls == alive
    obs = read_jsonl(context.output_dir / "httpx_redirects.jsonl")
    assert obs == []
    stored = read_jsonl(context.output_dir / "httpx.json")
    assert stored[0]["scope_status"] == ScopeStatus.IN_SCOPE.value


@pytest.mark.asyncio
async def test_oos_redirect_is_observation_not_alive_target(
    tmp_path: Path, settings: Settings
) -> None:
    """Authorized host → OOS: record observation, never put dest in alive.txt."""
    context = _context(tmp_path)
    plugin = HttpxPlugin(settings)
    hosts = context.output_dir / "resolved.txt"
    write_lines(hosts, [SEED], base_dir=context.output_dir)
    oos_url = f"https://{OOS}/sso"

    async def fake_exec(ctx, args, output_path, **kwargs):
        write_jsonl(
            output_path,
            [
                _record(
                    input_host=SEED,
                    final_url=oos_url,
                    location=oos_url,
                    chain=[
                        {"url": f"https://{SEED}/"},
                        {"url": oos_url, "status_code": 302},
                    ],
                )
            ],
            base_dir=ctx.output_dir,
        )
        return PluginResult(success=True, output_path=output_path, lines_produced=1)

    plugin._execute_self_output = fake_exec  # type: ignore[method-assign]
    await plugin.run(context, hosts)

    alive = read_lines(context.output_dir / "alive.txt")
    assert oos_url not in alive
    assert all(OOS not in line for line in alive)
    assert any(SEED in line for line in alive)

    obs = read_jsonl(context.output_dir / "httpx_redirects.jsonl")
    assert len(obs) == 1
    assert obs[0]["final_url"] == oos_url
    assert obs[0]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value
    assert obs[0]["collection_status"] == CollectionStatus.NOT_ALLOWED.value
    assert obs[0]["confidence_score"] == 95
    assert obs[0]["raw_artifact"] == "httpx.json"
    assert not obs[0]["raw_artifact"].startswith("/")

    stored = read_jsonl(context.output_dir / "httpx.json")
    assert stored[0]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value
    assert oos_url in stored[0]["url"]

    katana = KatanaPlugin(settings)
    assert all(OOS not in u for u in katana._alive_urls(context))
    nuclei = NucleiPlugin(settings)
    assert all(OOS not in u for u in nuclei._alive_urls(context))
    hakrawler = HakrawlerPlugin(settings)
    assert all(OOS not in u for u in hakrawler._alive_urls(context))

    context.httpx_results = stored
    probe_urls = [t["probe_url"] for t in _httpx_targets(context)]
    assert all(OOS not in u for u in probe_urls)
    assert allow_browser_navigation(oos_url, context) is False
    assert allow_browser_navigation(f"https://{SEED}/", context) is True
    assert OOS not in _alive_hosts(context)
    assert SEED in _alive_hosts(context)
    context.httpx_results[0]["tech"] = ["nginx:1.25.0"]
    assert _collect_techs(context) == []


def test_multi_hop_filter_uses_final_destination_not_first_hop() -> None:
    scope = _scope()
    intermediate = f"https://{IN_SCOPE_DEST}/next"
    final = f"https://{OOS}/end"
    record = _record(
        input_host=SEED,
        final_url=final,
        chain=[
            {"url": f"https://{SEED}/"},
            {"url": intermediate, "status_code": 302},
            {"url": final, "status_code": 302},
        ],
    )
    assert httpx_final_url(record) == final
    alive = authorized_alive_url(record, scope)
    assert alive is not None
    assert OOS not in alive
    assert SEED in alive or IN_SCOPE_DEST in (alive or "")

    annotated, alive_urls, obs = authorize_httpx_records([record], scope)
    assert all(OOS not in u for u in alive_urls)
    assert obs
    assert obs[0]["final_url"] == final
    assert obs[0]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value
    assert intermediate in obs[0]["redirect_chain"]
    assert annotated[0]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value


def test_in_scope_httpx_alive_behavior_unchanged_without_oos_redirect() -> None:
    """No OOS hop: alive.txt still receives the httpx `url` field (common case)."""
    scope = _scope()
    url = f"https://{SEED}/login"
    record = _record(input_host=SEED, final_url=url)
    annotated, alive_urls, obs = authorize_httpx_records([record], scope)
    assert alive_urls == [url]
    assert obs == []
    assert annotated[0]["scope_status"] == ScopeStatus.IN_SCOPE.value
    assert authorized_alive_url(record, scope) == url


@pytest.mark.asyncio
async def test_katana_and_nuclei_receive_authorized_alive_file(
    tmp_path: Path, settings: Settings
) -> None:
    context = _context(tmp_path)
    oos_url = f"https://{OOS}/"
    seed_url = f"https://{SEED}/"
    write_lines(
        context.output_dir / "alive.txt",
        [seed_url, oos_url],
        base_dir=context.output_dir,
    )
    captured: dict[str, str] = {}

    def _list_file(args: list[str]) -> Path:
        if "-list" in args:
            return Path(args[args.index("-list") + 1])
        return Path(args[args.index("-l") + 1])

    async def capture(ctx, args, output_path, **kwargs):
        captured["list"] = _list_file(args).read_text(encoding="utf-8")
        Path(output_path).write_text("", encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=0)

    katana = KatanaPlugin(settings)
    katana._execute_self_output = capture  # type: ignore[method-assign]
    await katana.run(context, context.output_dir / "alive.txt")
    assert seed_url in captured["list"]
    assert OOS not in captured["list"]

    nuclei = NucleiPlugin(settings)
    nuclei._execute_self_output = capture  # type: ignore[method-assign]
    await nuclei.run(context, context.output_dir / "alive.txt")
    assert seed_url in captured["list"]
    assert OOS not in captured["list"]
