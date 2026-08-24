"""Follow-up DNS must not overwrite seed artifacts. Exercises _maybe_collect_followups()."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from core.runner import PipelineRunner
from utils.files import read_jsonl, read_lines, write_jsonl, write_lines

SEED = "seed.example"
FOLLOW = "followup.example"


@pytest.mark.asyncio
async def test_maybe_collect_followups_preserves_seed_dns_artifacts(
    tmp_path: Path, settings: Settings
) -> None:
    settings.enable_followup_collection = True
    settings.max_discovery_depth = 1
    settings.max_followup_indicators = 10
    settings.enable_wildcard_check = False
    output_dir = tmp_path / "run"
    output_dir.mkdir()

    seed_record = {"host": SEED, "a": ["203.0.113.10"], "status_code": "NOERROR"}
    write_lines(output_dir / "resolved.txt", [SEED], base_dir=output_dir)
    write_jsonl(output_dir / "dnsx_records.jsonl", [seed_record], base_dir=output_dir)
    write_jsonl(
        output_dir / "ctlogs.jsonl",
        [
            {
                "id": 1,
                "common_name": SEED,
                "name_value": f"{SEED}\n{FOLLOW}",
                "issuer_name": "Test CA",
                "serial_number": "aa11",
                "fingerprint_sha256": "a" * 64,
                "query_domain": SEED,
            }
        ],
        base_dir=output_dir,
    )

    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED],
        resolved=[SEED],
        output_dir=output_dir,
        run_id="followup-dns",
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED, FOLLOW]),
        metadata={"dns_probes": 1, "http_probes": 0},
    )

    runner = PipelineRunner(settings)
    dnsx = runner.tool_manager.get_plugin("dnsx")
    assert dnsx is not None

    async def stub_dnsx(ctx: PipelineContext, input_path: Path) -> PluginResult:
        gated = dnsx._authorized_input(ctx, input_path)
        hosts = read_lines(gated)
        suffix = str(ctx.metadata.get("dnsx_output_suffix") or "")
        records_path = dnsx._output_path(ctx, f"dnsx_records{suffix}.jsonl")
        resolved_path = dnsx._output_path(ctx, f"resolved{suffix}.txt")
        write_jsonl(
            records_path,
            [{"host": host, "a": ["198.51.100.7"], "status_code": "NOERROR"} for host in hosts],
            base_dir=ctx.output_dir,
        )
        write_lines(resolved_path, hosts, base_dir=ctx.output_dir)
        if not suffix:
            ctx.resolved = hosts
        return PluginResult(success=True, output_path=resolved_path, lines_produced=len(hosts))

    dnsx.run = stub_dnsx  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: name == "dnsx"  # type: ignore[method-assign]
    runner.tool_manager.ensure_mandatory_tools = AsyncMock()

    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")

    resolved = set(read_lines(output_dir / "resolved.txt"))
    assert SEED in resolved
    assert FOLLOW in resolved
    assert context.resolved
    assert SEED in context.resolved
    assert FOLLOW in context.resolved

    canonical = read_jsonl(output_dir / "dnsx_records.jsonl")
    hosts = {str(rec.get("host")) for rec in canonical}
    assert SEED in hosts
    assert FOLLOW in hosts
    seed_rows = [rec for rec in canonical if rec.get("host") == SEED]
    assert seed_rows
    assert seed_rows[0].get("a") == ["203.0.113.10"]

    follow_sidecar = output_dir / "dnsx_records_followup_1.jsonl"
    follow_resolved = output_dir / "resolved_followup_1.txt"
    assert follow_sidecar.exists()
    assert FOLLOW in {str(rec.get("host")) for rec in read_jsonl(follow_sidecar)}
    assert FOLLOW in read_lines(follow_resolved)
    assert SEED not in read_lines(follow_resolved) or True

    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")
    assert set(read_lines(output_dir / "resolved.txt")) == resolved


@pytest.mark.asyncio
async def test_crashed_followup_does_not_clobber_canonical_seed(
    tmp_path: Path, settings: Settings
) -> None:
    settings.enable_followup_collection = True
    settings.max_discovery_depth = 1
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    write_lines(output_dir / "resolved.txt", [SEED], base_dir=output_dir)
    write_jsonl(
        output_dir / "dnsx_records.jsonl",
        [{"host": SEED, "a": ["203.0.113.10"]}],
        base_dir=output_dir,
    )
    write_jsonl(
        output_dir / "ctlogs.jsonl",
        [
            {
                "id": 2,
                "name_value": f"{SEED}\n{FOLLOW}",
                "fingerprint_sha256": "b" * 64,
                "query_domain": SEED,
            }
        ],
        base_dir=output_dir,
    )
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        resolved=[SEED],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED, FOLLOW]),
        metadata={"dns_probes": 1, "http_probes": 0},
    )
    runner = PipelineRunner(settings)
    dnsx = runner.tool_manager.get_plugin("dnsx")
    assert dnsx is not None

    async def crashing_dnsx(ctx: PipelineContext, input_path: Path) -> PluginResult:
        dnsx._authorized_input(ctx, input_path)
        raise RuntimeError("collector interrupted")

    dnsx.run = crashing_dnsx  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: name == "dnsx"  # type: ignore[method-assign]

    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")

    assert read_lines(output_dir / "resolved.txt") == [SEED]
    assert read_jsonl(output_dir / "dnsx_records.jsonl")[0]["host"] == SEED
    assert json.dumps(read_jsonl(output_dir / "dnsx_records.jsonl")).count(FOLLOW) == 0
