"""Static confirmation (Part 2.1): katana, hakrawler, and nuclei must never
invoke their subprocess without `-proxy <ScopeEnforcingProxy>` in argv.

`docs/ARCHITECTURE_AUDIT_2.md` traced all three and found every one already
wraps its single `_execute`/`_execute_self_output` call inside
`async with self._crawler_confinement(context) as proxy:` with no alternate
code path. This file is the missing static/runtime proof of that claim: it
inspects the *actual argv* built right before the subprocess layer would run
it — not the source code by inspection, and not what the tool reports having
done — by patching the execution layer to capture argv instead of spawning a
real subprocess, so this runs without any of the three binaries installed.

If a future edit adds a second call site, an early return before the
confinement block, or a retry path that skips it, this fails.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from modules.hakrawler import HakrawlerPlugin
from modules.katana import KatanaPlugin
from modules.nuclei import NucleiPlugin
from utils.files import write_lines

SEED_URL = "https://app.proxy-flag-test.internal/"


def _context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    write_lines(output_dir / "alive.txt", [SEED_URL], base_dir=output_dir)
    context = PipelineContext(
        targets=[DomainTarget(domain="proxy-flag-test.internal")],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(["proxy-flag-test.internal"]),
    )
    context.alive_urls = [SEED_URL]
    context.httpx_results = [{"url": SEED_URL, "input": SEED_URL}]
    return context


def _proxy_value(args: list[str]) -> str:
    assert "-proxy" in args, f"-proxy flag missing from argv: {args}"
    return args[args.index("-proxy") + 1]


@pytest.mark.asyncio
async def test_katana_always_receives_proxy_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, list[str]] = {}

    async def fake_execute_self_output(
        self: BaseToolPlugin, context: PipelineContext, args: list[str], output_path: Path, **_kw
    ) -> PluginResult:
        captured["args"] = args
        output_path.write_text("", encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=0)

    monkeypatch.setattr(BaseToolPlugin, "_execute_self_output", fake_execute_self_output)

    settings = Settings(project_root=tmp_path, enable_katana=True)
    plugin = KatanaPlugin(settings)
    context = _context(tmp_path)

    await plugin.run(context, tmp_path / "unused_input.txt")

    assert "args" in captured, "katana never reached the subprocess execution layer"
    proxy_url = _proxy_value(captured["args"])
    assert proxy_url.startswith("http://127.0.0.1:")


@pytest.mark.asyncio
async def test_hakrawler_always_receives_proxy_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, list[str]] = {}

    async def fake_execute(
        self: BaseToolPlugin, context: PipelineContext, args: list[str], output_path: Path, **_kw
    ) -> PluginResult:
        captured["args"] = args
        output_path.write_text("", encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=0)

    monkeypatch.setattr(BaseToolPlugin, "_execute", fake_execute)

    settings = Settings(project_root=tmp_path, enable_hakrawler=True)
    plugin = HakrawlerPlugin(settings)
    context = _context(tmp_path)

    await plugin.run(context, tmp_path / "unused_input.txt")

    assert "args" in captured, "hakrawler never reached the subprocess execution layer"
    proxy_url = _proxy_value(captured["args"])
    assert proxy_url.startswith("http://127.0.0.1:")


@pytest.mark.asyncio
async def test_nuclei_always_receives_proxy_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, list[str]] = {}

    async def fake_execute_self_output(
        self: BaseToolPlugin, context: PipelineContext, args: list[str], output_path: Path, **_kw
    ) -> PluginResult:
        captured["args"] = args
        output_path.write_text("", encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=0)

    monkeypatch.setattr(BaseToolPlugin, "_execute_self_output", fake_execute_self_output)

    settings = Settings(project_root=tmp_path, enable_nuclei=True)
    plugin = NucleiPlugin(settings)
    context = _context(tmp_path)

    await plugin.run(context, tmp_path / "unused_input.txt")

    assert "args" in captured, "nuclei never reached the subprocess execution layer"
    proxy_url = _proxy_value(captured["args"])
    assert proxy_url.startswith("http://127.0.0.1:")


@pytest.mark.asyncio
async def test_katana_never_calls_execute_if_confinement_proxy_fails_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the confinement proxy itself can't start, the subprocess must
    never run unconfined as a fallback — it must fail instead of silently
    skipping confinement."""
    execute_mock = AsyncMock()
    monkeypatch.setattr(BaseToolPlugin, "_execute_self_output", execute_mock)

    async def broken_start(self: object) -> None:
        raise RuntimeError("simulated bind failure")

    monkeypatch.setattr("core.collection.crawler_proxy.ScopeEnforcingProxy.start", broken_start)

    settings = Settings(project_root=tmp_path, enable_katana=True)
    plugin = KatanaPlugin(settings)
    context = _context(tmp_path)

    with pytest.raises(RuntimeError, match="simulated bind failure"):
        await plugin.run(context, tmp_path / "unused_input.txt")

    execute_mock.assert_not_called()
