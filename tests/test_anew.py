"""`modules/anew.py`: parsing real `anew` output.

`anew <file>` reads candidate lines from stdin, appends any line not
already present in `<file>` to it, and prints *only the new lines* to
stdout — one per line, in input order, deduplicated. Captured live against
the real installed `anew` binary (2026-09-14):

    $ printf "a.example.com\\nb.example.com\\n" > seen.txt
    $ printf "a.example.com\\nc.example.com\\nb.example.com\\nd.example.com\\n" | anew seen.txt
    c.example.com
    d.example.com
    $ cat seen.txt
    a.example.com
    b.example.com
    c.example.com
    d.example.com

Also confirmed live: empty stdin exits 0 with empty stdout and leaves the
file unchanged — the real shape of the "no new entries" case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.models import DomainTarget, PipelineContext
from modules.anew import AnewPlugin
from utils.files import read_lines, write_lines


def _context(tmp_path: Path) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(targets=[DomainTarget(domain="example.com")], output_dir=output_dir)


def _mock_run_tool(return_code: int, stdout: str):
    async def fake(context, args, *, input_data=None, timeout=None):
        return return_code, stdout, ""

    return fake


@pytest.mark.asyncio
async def test_anew_real_output_only_new_lines_merged_in_input_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact real captured scenario: 2 already-seen entries, 4
    candidates (2 duplicates, 2 new) -> subdomains.txt gains exactly the
    2 new ones, in the real order anew printed them."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["a.example.com", "b.example.com"], base_dir=context.output_dir)

    plugin = AnewPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", _mock_run_tool(0, "c.example.com\nd.example.com\n"))

    result = await plugin.run(context, input_path)

    assert result.success
    assert result.lines_produced == 2
    merged = read_lines(context.output_dir / "subdomains.txt")
    assert merged == ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]
    assert context.subdomains == merged


@pytest.mark.asyncio
async def test_anew_real_empty_stdout_when_nothing_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real, confirmed-live behavior: every candidate already seen -> empty
    stdout, exit 0. Must not crash and must not touch subdomains.txt."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["a.example.com", "b.example.com"], base_dir=context.output_dir)

    plugin = AnewPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", _mock_run_tool(0, ""))

    result = await plugin.run(context, input_path)

    assert result.success
    assert result.lines_produced == 0
    assert context.metadata["anew_new_entries"] == 0


@pytest.mark.asyncio
async def test_anew_duplicate_new_lines_from_stdout_are_deduplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive: anew's own dedup should already prevent this, but a
    duplicate appearing twice in stdout (e.g. a future anew version, or a
    malformed capture) must not double-count or corrupt the merge."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, [], base_dir=context.output_dir)

    plugin = AnewPlugin(settings)
    monkeypatch.setattr(
        plugin, "_run_tool", _mock_run_tool(0, "dup.example.com\ndup.example.com\n")
    )

    result = await plugin.run(context, input_path)

    assert result.success
    assert result.lines_produced == 1
    assert read_lines(context.output_dir / "subdomains.txt") == ["dup.example.com"]


@pytest.mark.asyncio
async def test_anew_nonzero_exit_reports_failure_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["a.example.com"], base_dir=context.output_dir)

    plugin = AnewPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", _mock_run_tool(1, ""))

    result = await plugin.run(context, input_path)

    assert not result.success
    assert "Exit code 1" in result.message


@pytest.mark.asyncio
async def test_anew_subprocess_exception_reports_failure_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed/unavailable-binary case: _run_tool raising must be caught,
    not propagate and crash the pipeline."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["a.example.com"], base_dir=context.output_dir)

    async def raising(*args, **kwargs):
        raise RuntimeError("binary not found")

    plugin = AnewPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", raising)

    result = await plugin.run(context, input_path)

    assert not result.success
    assert "binary not found" in result.message
