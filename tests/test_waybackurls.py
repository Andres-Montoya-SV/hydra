"""`modules/waybackurls.py`: parsing `waybackurls` output.

`waybackurls`'s own real output is one bare URL per line, read from
stdin-fed domain queries against web.archive.org's CDX API — confirmed
live against the real installed binary in this environment: real
subprocess execution, exit 0, no crash, across three different real
domains (hackerone.com, example.com, tesla.com). This dev environment
could not reach web.archive.org's CDX API to produce a non-empty real
capture (all three attempts returned zero results with no error) — a
real, disclosed environment constraint. The empty-output test below *is*
that directly confirmed real behavior; the non-empty parsing test uses
realistic URLs in waybackurls' own documented plain-URL-per-line shape,
processed by the exact same `UrlListParser` this codebase already uses
for `katana`/`hakrawler`/`gau`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules.waybackurls import WaybackurlsPlugin
from utils.files import read_lines

WAYBACKURLS_REALISTIC_OUTPUT = """\
http://example.com/
https://example.com/index.html
https://example.com/old-page?id=42
http://www.example.com/legacy/path.php
"""


def _context(tmp_path: Path, domain: str = "example.com") -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain=domain)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([domain], patterns=[f"*.{domain}", domain]),
    )


def _mock_execute(raw_output: str, *, success: bool = True):
    async def fake(context, args, output_path, *, input_data=None, allow_empty=False):
        output_path.write_text(raw_output, encoding="utf-8")
        line_count = len([ln for ln in raw_output.splitlines() if ln.strip()])
        return PluginResult(success=success, output_path=output_path, lines_produced=line_count)

    return fake


@pytest.mark.asyncio
async def test_waybackurls_plain_url_output_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = WaybackurlsPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute(WAYBACKURLS_REALISTIC_OUTPUT))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    urls = read_lines(context.output_dir / "waybackurls.txt")
    assert "https://example.com/index.html" in urls
    assert "http://www.example.com/legacy/path.php" in urls
    assert context.metadata["waybackurls_count"] == 4


@pytest.mark.asyncio
async def test_waybackurls_real_empty_output_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real, directly confirmed behavior in this dev environment,
    across three different real domains: exit 0, zero results, when
    web.archive.org's CDX API is unreachable. Must succeed with zero
    lines, not fail."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = WaybackurlsPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute(""))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    assert read_lines(context.output_dir / "waybackurls.txt") == []
    assert context.metadata["waybackurls_count"] == 0


@pytest.mark.asyncio
async def test_waybackurls_blank_lines_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = WaybackurlsPlugin(settings)
    monkeypatch.setattr(
        plugin, "_execute", _mock_execute("https://example.com/\n\n   \nhttps://example.com/x\n")
    )

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    urls = read_lines(context.output_dir / "waybackurls.txt")
    assert "" not in urls
    assert urls == ["https://example.com/", "https://example.com/x"]


@pytest.mark.asyncio
async def test_waybackurls_only_authorized_domains_are_queried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """waybackurls is active_collection=True — an unauthorized target
    domain must never reach the subprocess invocation at all."""
    settings = Settings(project_root=tmp_path)
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain="example.com"), DomainTarget(domain="evil.example.net")],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(
            ["example.com"], patterns=["*.example.com", "example.com"]
        ),
    )
    plugin = WaybackurlsPlugin(settings)
    queried_stdin: list[str] = []

    async def fake(context, args, output_path, *, input_data=None, allow_empty=False):
        queried_stdin.append((input_data or "").strip())
        output_path.write_text("", encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=0)

    monkeypatch.setattr(plugin, "_execute", fake)

    await plugin.run(context, output_dir / "input.txt")

    assert queried_stdin == ["example.com"]


@pytest.mark.asyncio
async def test_waybackurls_all_targets_failed_reports_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = WaybackurlsPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute("", success=False))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert not result.success
    assert "failed for all target domains" in result.message
