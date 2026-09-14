"""`modules/unfurl.py`: parsing real `unfurl domains` output.

Real captured output, run live against the real installed `unfurl` binary
(2026-09-14):

    $ printf "https://api.hackerone.com/v1/reports?page=2\\n\\
    http://www.hackerone.com/path\\n\\
    https://api.hackerone.com:8443/other\\n\\
    not-a-url\\n\\
    https://docs.hackerone.com/\\n" | unfurl domains
    api.hackerone.com
    www.hackerone.com
    api.hackerone.com
    not-a-url
    docs.hackerone.com

Confirms two real behaviors the plugin's own dedup (`sorted(set(...))`)
must handle: a repeated host (api.hackerone.com, once plain and once with
an explicit port) prints twice, and a non-URL line is echoed back
unchanged rather than dropped or erroring — unfurl's own real tolerance
for malformed input.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.unfurl import UnfurlPlugin
from utils.files import read_lines, write_lines

# Real captured unfurl output for the 5 input lines in this file's
# docstring, 2026-09-14.
UNFURL_REAL_STDOUT = (
    "api.hackerone.com\nwww.hackerone.com\napi.hackerone.com\nnot-a-url\ndocs.hackerone.com\n"
)


def _context(
    tmp_path: Path, alive_urls: list[str], domain: str = "hackerone.com"
) -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain=domain)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([domain], patterns=[f"*.{domain}", domain]),
    )
    write_lines(output_dir / "alive.txt", alive_urls, base_dir=output_dir)
    return context


def _mock_run_tool(return_code: int, stdout: str):
    async def fake(context, args, *, input_data=None, timeout=None):
        return return_code, stdout, ""

    return fake


@pytest.mark.asyncio
async def test_unfurl_real_output_deduplicated_and_sorted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real captured stdout has a duplicate (api.hackerone.com twice)
    and a non-URL passthrough line (unfurl's own real tolerance) — the
    plugin must dedupe and sort, keeping the non-URL line rather than
    treating it as an error."""
    settings = Settings(project_root=tmp_path)
    context = _context(
        tmp_path,
        [
            "https://api.hackerone.com/v1/reports?page=2",
            "http://www.hackerone.com/path",
            "https://api.hackerone.com:8443/other",
            "not-a-url",
            "https://docs.hackerone.com/",
        ],
    )
    plugin = UnfurlPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", _mock_run_tool(0, UNFURL_REAL_STDOUT))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    domains = read_lines(context.output_dir / "unfurl_domains.txt")
    assert domains == sorted(
        {"api.hackerone.com", "www.hackerone.com", "not-a-url", "docs.hackerone.com"}
    )
    assert context.metadata["unfurl_domains"] == 4


@pytest.mark.asyncio
async def test_unfurl_no_alive_urls_skips_cleanly(tmp_path: Path) -> None:
    """No upstream HTTP results yet (a real, common pipeline state, not an
    error) — must skip, not fail or crash."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, [])
    plugin = UnfurlPlugin(settings)

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.skipped
    assert not result.success


@pytest.mark.asyncio
async def test_unfurl_empty_stdout_produces_empty_domains_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, ["https://api.hackerone.com/"])
    plugin = UnfurlPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", _mock_run_tool(0, ""))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    assert read_lines(context.output_dir / "unfurl_domains.txt") == []
    assert context.metadata["unfurl_domains"] == 0


@pytest.mark.asyncio
async def test_unfurl_blank_lines_in_stdout_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, ["https://api.hackerone.com/", "https://docs.hackerone.com/"])
    plugin = UnfurlPlugin(settings)
    monkeypatch.setattr(
        plugin, "_run_tool", _mock_run_tool(0, "api.hackerone.com\n\n   \ndocs.hackerone.com\n")
    )

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    domains = read_lines(context.output_dir / "unfurl_domains.txt")
    assert "" not in domains
    assert domains == ["api.hackerone.com", "docs.hackerone.com"]


@pytest.mark.asyncio
async def test_unfurl_nonzero_exit_reports_failure_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, ["https://api.hackerone.com/"])
    plugin = UnfurlPlugin(settings)
    monkeypatch.setattr(plugin, "_run_tool", _mock_run_tool(1, ""))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert not result.success
    assert "Exit code 1" in result.message
