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


def _httpx_stub(pages: dict[str, dict], requested: list[str]):
    """Fake `_execute_self_output` standing in for the real httpx binary.

    Mimics httpx without `-follow-redirects`: it answers exactly one request
    per invocation — the `-u` single target, or every host in the `-l` list
    file on the very first call — and never manufactures a response for a
    URL that isn't in `pages`. `requested` records every URL actually asked
    for, in order, so tests can assert on attempted requests, not just on
    where they landed.
    """

    async def fake_exec(ctx, args, output_path, **kwargs):
        if "-u" in args:
            targets = [args[args.index("-u") + 1]]
        else:
            list_path = Path(args[args.index("-l") + 1])
            targets = read_lines(list_path)
        records = []
        for target in targets:
            requested.append(target)
            page = pages.get(target)
            if page is not None:
                records.append(page)
        write_jsonl(output_path, records, base_dir=ctx.output_dir)
        return PluginResult(success=True, output_path=output_path, lines_produced=len(records))

    return fake_exec


@pytest.mark.asyncio
async def test_in_scope_redirect_stays_an_active_target(tmp_path: Path, settings: Settings) -> None:
    """Authorized host → in-scope host: followed hop by hop, landing URL is alive.

    Same outward behavior as before the redirect-safety fix (landing URL ends
    up in alive.txt, no observation is recorded) — httpx just no longer
    fetches the destination on its own; Hydra authorizes then requests it.
    """
    context = _context(tmp_path)
    plugin = HttpxPlugin(settings)
    hosts = context.output_dir / "resolved.txt"
    write_lines(hosts, [SEED], base_dir=context.output_dir)
    seed_url = f"https://{SEED}/"
    landing = f"https://{IN_SCOPE_DEST}/dashboard"
    requested: list[str] = []
    pages = {
        SEED: {
            "input": SEED,
            "host": SEED,
            "url": seed_url,
            "status_code": 302,
            "location": landing,
        },
        landing: {
            "input": landing,
            "host": IN_SCOPE_DEST,
            "url": landing,
            "status_code": 200,
            "title": "ok",
        },
    }
    plugin._execute_self_output = _httpx_stub(pages, requested)  # type: ignore[method-assign]
    await plugin.run(context, hosts)

    # Exactly the origin, then the authorized landing hop — one httpx call per hop.
    assert requested == [SEED, landing]

    alive = read_lines(context.output_dir / "alive.txt")
    assert landing in alive
    assert all(OOS not in line for line in alive)
    assert context.alive_urls == alive
    obs = read_jsonl(context.output_dir / "httpx_redirects.jsonl")
    assert obs == []
    stored = read_jsonl(context.output_dir / "httpx.json")
    assert stored[0]["scope_status"] == ScopeStatus.IN_SCOPE.value
    assert stored[0]["final_url"] == landing


@pytest.mark.asyncio
async def test_oos_redirect_is_observation_not_alive_target(
    tmp_path: Path, settings: Settings
) -> None:
    """Authorized host → OOS: record observation, never request the destination."""
    context = _context(tmp_path)
    plugin = HttpxPlugin(settings)
    hosts = context.output_dir / "resolved.txt"
    write_lines(hosts, [SEED], base_dir=context.output_dir)
    seed_url = f"https://{SEED}/"
    oos_url = f"https://{OOS}/sso"
    requested: list[str] = []
    pages = {
        SEED: {
            "input": SEED,
            "host": SEED,
            "url": seed_url,
            "status_code": 302,
            "location": oos_url,
        },
        # Deliberately no entry for oos_url. If the plugin ever asked for it,
        # `requested` below would catch it regardless of what a stub returned.
    }
    plugin._execute_self_output = _httpx_stub(pages, requested)  # type: ignore[method-assign]
    await plugin.run(context, hosts)

    # The assertion that matters: the request was never attempted, not just
    # that its result didn't end up in alive.txt.
    assert requested == [SEED]
    assert oos_url not in requested

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
    assert stored[0]["final_url"] == oos_url
    # `url` reflects the request httpx actually made (the origin) — the OOS
    # destination named by `final_url` was never fetched.
    assert oos_url not in stored[0]["url"]

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
    # tech/title on this record describe the origin's own (never-OOS) 302
    # response, so they're legitimate SEED intel and are kept.
    context.httpx_results[0]["tech"] = ["nginx:1.25.0"]
    assert _collect_techs(context) == [
        {"host": SEED, "url": seed_url, "name": "nginx", "version": "1.25.0"}
    ]


@pytest.mark.asyncio
async def test_redirect_chain_stops_at_first_oos_hop_never_requests_hop_after(
    tmp_path: Path, settings: Settings
) -> None:
    """origin → in-scope hop1 → OOS hop2 → hop3: stop at hop2, hop3 never evaluated."""
    context = _context(tmp_path)
    plugin = HttpxPlugin(settings)
    hosts = context.output_dir / "resolved.txt"
    write_lines(hosts, [SEED], base_dir=context.output_dir)
    seed_url = f"https://{SEED}/"
    hop1 = f"https://{IN_SCOPE_DEST}/step1"
    hop2 = f"https://{OOS}/step2"
    hop3 = f"https://{OOS}/step3-should-never-be-fetched"
    requested: list[str] = []
    pages = {
        SEED: {"input": SEED, "host": SEED, "url": seed_url, "status_code": 302, "location": hop1},
        hop1: {
            "input": hop1,
            "host": IN_SCOPE_DEST,
            "url": hop1,
            "status_code": 302,
            "location": hop2,
        },
        hop2: {"input": hop2, "host": OOS, "url": hop2, "status_code": 302, "location": hop3},
        # hop3 intentionally absent — Hydra reaching for it would be the bug.
    }
    plugin._execute_self_output = _httpx_stub(pages, requested)  # type: ignore[method-assign]
    await plugin.run(context, hosts)

    assert requested == [SEED, hop1]
    assert hop2 not in requested
    assert hop3 not in requested

    obs = read_jsonl(context.output_dir / "httpx_redirects.jsonl")
    assert len(obs) == 1
    assert obs[0]["final_url"] == hop2
    assert hop3 not in obs[0]["redirect_chain"]

    alive = read_lines(context.output_dir / "alive.txt")
    assert all(OOS not in line for line in alive)


@pytest.mark.asyncio
async def test_browser_navigation_guard_fails_closed_on_exception(
    tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug while evaluating navigation authorization must block, not fall open."""
    import modules.browser_probe as browser_probe

    context = _context(tmp_path)

    def _boom(url: str, ctx: object) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr(browser_probe, "allow_browser_navigation", _boom)

    calls: dict[str, object] = {"abort": None, "continued": False}

    class FakeRequest:
        url = f"https://{SEED}/"
        resource_type = "document"

        def is_navigation_request(self) -> bool:
            return True

    class FakeRoute:
        request = FakeRequest()

        async def abort(self, reason: str) -> None:
            calls["abort"] = reason

        async def continue_(self) -> None:
            calls["continued"] = True

    handlers: dict[str, object] = {}

    class FakeContext:
        async def route(self, pattern: str, handler: object) -> None:
            handlers["guard"] = handler

        async def route_web_socket(self, pattern: str, handler: object) -> None:
            handlers["websocket_guard"] = handler

    blocked_counts: dict[str, int] = {}
    await browser_probe._install_scope_request_guard(FakeContext(), context, blocked_counts)
    await handlers["guard"](FakeRoute())

    assert calls["abort"] == "blockedbyclient"
    assert calls["continued"] is False
    assert blocked_counts.get("document") == 1


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
