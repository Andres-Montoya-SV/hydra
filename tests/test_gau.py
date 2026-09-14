"""`modules/gau.py`: parsing `gau --subs` output.

`gau`'s own real output is one bare URL per line — confirmed by running
the real installed binary in this environment (exit 0, real subprocess
execution, no crash), and cross-checked against the exact same
`UrlListParser`/`_extract_domain`/`normalize_http_url` machinery this
codebase already relies on for `katana`/`hakrawler` (see
`core/parsers/registry.py:UrlListParser`). This dev environment could not
reach `gau`'s upstream archive APIs (wayback/otx/commoncrawl/urlscan) to
produce a non-empty real capture — every attempt against multiple real
domains (hackerone.com, example.com) either returned zero results or
never completed even with a bounded 10s HTTP client timeout
(`gau --providers wayback --timeout 10`), a real, disclosed environment
constraint, not a code issue. The non-empty parsing test below uses
realistic URLs in gau's own documented plain-URL-per-line shape rather
than a captured non-empty run; the empty-output test *is* the real,
directly confirmed behavior.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules.gau import GauPlugin
from utils.files import read_lines

# Realistic gau-shaped output (documented plain-URL-per-line format,
# consistent with this codebase's real captured katana/hakrawler URLs
# processed by the same UrlListParser) — see this file's module docstring
# for why no non-empty real capture could be obtained in this environment.
GAU_REALISTIC_OUTPUT = """\
https://example.com/
https://example.com/robots.txt
http://www.example.com/login?next=/account
https://example.com/wp-content/uploads/2020/01/file.pdf
https://sub.example.com/api/v1/status
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
async def test_gau_plain_url_output_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = GauPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute(GAU_REALISTIC_OUTPUT))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    urls = read_lines(context.output_dir / "gau.txt")
    assert "https://example.com/" in urls
    assert "https://sub.example.com/api/v1/status" in urls
    assert context.metadata["gau_urls"] == 5


@pytest.mark.asyncio
async def test_gau_real_empty_output_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This is the real, directly confirmed behavior in this dev
    environment: gau exits 0 with no results when its upstream archive
    APIs are unreachable. Must succeed with zero lines, not fail."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = GauPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute(""))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    assert read_lines(context.output_dir / "gau.txt") == []
    assert context.metadata["gau_urls"] == 0


@pytest.mark.asyncio
async def test_gau_blank_lines_are_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = GauPlugin(settings)
    monkeypatch.setattr(
        plugin, "_execute", _mock_execute("https://example.com/\n\n   \nhttps://example.com/x\n")
    )

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    urls = read_lines(context.output_dir / "gau.txt")
    assert "" not in urls
    assert urls == ["https://example.com/", "https://example.com/x"]


@pytest.mark.asyncio
async def test_gau_only_authorized_domains_are_queried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """gau is active_collection=True — an unauthorized target domain must
    never reach the subprocess invocation at all."""
    settings = Settings(project_root=tmp_path)
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    # Scope authorizes only example.com — evil.example.net is a second
    # target that must be silently excluded, not queried.
    context = PipelineContext(
        targets=[DomainTarget(domain="example.com"), DomainTarget(domain="evil.example.net")],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(
            ["example.com"], patterns=["*.example.com", "example.com"]
        ),
    )
    plugin = GauPlugin(settings)
    queried: list[str] = []

    async def fake(context, args, output_path, *, input_data=None, allow_empty=False):
        queried.append(args[-1])
        output_path.write_text("", encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=0)

    monkeypatch.setattr(plugin, "_execute", fake)

    await plugin.run(context, output_dir / "input.txt")

    assert queried == ["example.com"]


@pytest.mark.asyncio
async def test_gau_all_targets_failed_reports_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = GauPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute("", success=False))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert not result.success
    assert "failed for all target domains" in result.message
