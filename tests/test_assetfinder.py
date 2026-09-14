"""`modules/assetfinder.py`: parsing real `assetfinder --subs-only` output.

Real captured output — `assetfinder --subs-only hackerone.com`, run live
against the real installed binary (2026-09-14). One hostname per line,
genuine duplicates across assetfinder's own data sources (the real
binary's own behavior, not a test artifact) — the plugin/parser must
survive duplicates without corrupting the merged subdomain list.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules.assetfinder import AssetfinderPlugin
from utils.files import read_lines

# Real captured output — `assetfinder --subs-only hackerone.com`,
# 2026-09-14. Includes real cross-source duplicates.
ASSETFINDER_HACKERONE_REAL_OUTPUT = """\
hackerone.com
api.hackerone.com
docs.hackerone.com
mta-sts.forwarding.hackerone.com
gslink.hackerone.com
mta-sts.managed.hackerone.com
mta-sts.hackerone.com
a.ns.hackerone.com
b.ns.hackerone.com
support.hackerone.com
www.hackerone.com
api.hackerone.com
docs.hackerone.com
hackerone.com
www.hackerone.com
api.hackerone.com
hackerone.com
www.hackerone.com
websockets.hackerone.com
design.hackerone.com
"""


def _context(tmp_path: Path, domain: str = "hackerone.com") -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(targets=[DomainTarget(domain=domain)], output_dir=output_dir)


def _mock_execute(raw_output: str):
    async def fake(context, args, output_path, *, input_data=None, allow_empty=False):
        output_path.write_text(raw_output, encoding="utf-8")
        line_count = len([ln for ln in raw_output.splitlines() if ln.strip()])
        return PluginResult(success=True, output_path=output_path, lines_produced=line_count)

    return fake


@pytest.mark.asyncio
async def test_assetfinder_real_output_all_hostnames_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """assetfinder's own output is already a plain hostname-per-line list
    (unlike amass) — the plugin passes every discovered hostname through,
    deduplicated by `write_lines` (confirmed: 20 real raw lines, 13 unique
    real hostnames — matches exactly, not approximately)."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AssetfinderPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute(ASSETFINDER_HACKERONE_REAL_OUTPUT))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    raw = read_lines(context.output_dir / "assetfinder.txt")
    assert "hackerone.com" in raw
    assert "gslink.hackerone.com" in raw
    assert "websockets.hackerone.com" in raw
    assert "design.hackerone.com" in raw
    assert len(raw) == 13  # unique real hostnames (write_lines dedupes)
    merged = read_lines(context.output_dir / "subdomains.txt")
    assert set(merged) >= {
        "hackerone.com",
        "api.hackerone.com",
        "docs.hackerone.com",
        "gslink.hackerone.com",
        "websockets.hackerone.com",
    }


@pytest.mark.asyncio
async def test_assetfinder_empty_output_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A domain with genuinely no passive assetfinder hits — must not
    crash and must report success with zero lines, not a failure."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AssetfinderPlugin(settings)
    monkeypatch.setattr(plugin, "_execute", _mock_execute(""))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    assert read_lines(context.output_dir / "assetfinder.txt") == []


@pytest.mark.asyncio
async def test_assetfinder_whitespace_only_lines_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed/noisy output (blank lines) must not become empty-string
    "subdomains" in the merged list."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AssetfinderPlugin(settings)
    monkeypatch.setattr(
        plugin, "_execute", _mock_execute("api.hackerone.com\n\n   \nhackerone.com\n")
    )

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    merged = read_lines(context.output_dir / "subdomains.txt")
    assert "" not in merged
    assert set(merged) == {"api.hackerone.com", "hackerone.com"}


@pytest.mark.asyncio
async def test_assetfinder_all_targets_failed_reports_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AssetfinderPlugin(settings)

    async def fake_fail(context, args, output_path, *, input_data=None, allow_empty=False):
        return PluginResult(success=False, output_path=None, message="Exit code 1")

    monkeypatch.setattr(plugin, "_execute", fake_fail)

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert not result.success
    assert "failed for all target domains" in result.message
