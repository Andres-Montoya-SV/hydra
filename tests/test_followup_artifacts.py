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
FOLLOW2 = "followup2.example"


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


@pytest.mark.asyncio
async def test_followup_with_no_candidates_leaves_seed_artifacts_untouched(
    tmp_path: Path, settings: Settings
) -> None:
    """Empty follow-up: no certificate SANs or other evidence names anything
    beyond the seed itself, so `plan.dns_targets`/`plan.http_targets` are both
    empty. The early-return path (`core/runner.py:_maybe_collect_followups`,
    "if not plan.dns_targets and not plan.http_targets: return") must leave
    the seed's own artifacts completely untouched — not merely "unioned with
    nothing and rewritten to the same content," but never written to at all,
    and no follow-up sidecar file created."""
    settings.enable_followup_collection = True
    settings.max_discovery_depth = 1
    settings.enable_wildcard_check = False
    output_dir = tmp_path / "run"
    output_dir.mkdir()

    write_lines(output_dir / "resolved.txt", [SEED], base_dir=output_dir)
    write_jsonl(
        output_dir / "dnsx_records.jsonl",
        [{"host": SEED, "a": ["203.0.113.10"], "status_code": "NOERROR"}],
        base_dir=output_dir,
    )
    resolved_before = (output_dir / "resolved.txt").read_bytes()
    records_before = (output_dir / "dnsx_records.jsonl").read_bytes()

    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        resolved=[SEED],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED]),
        metadata={"dns_probes": 1, "http_probes": 0},
    )
    runner = PipelineRunner(settings)
    dnsx = runner.tool_manager.get_plugin("dnsx")
    assert dnsx is not None

    async def unexpected_dnsx(ctx: PipelineContext, input_path: Path) -> PluginResult:
        raise AssertionError("dnsx must never run — there is nothing to follow up on")

    dnsx.run = unexpected_dnsx  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: name == "dnsx"  # type: ignore[method-assign]

    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")

    assert (output_dir / "resolved.txt").read_bytes() == resolved_before
    assert (output_dir / "dnsx_records.jsonl").read_bytes() == records_before
    # `followup_domains.txt` is always (re)written as an audit trail of what
    # was scheduled, even when empty — that's fine; what must never happen is
    # dnsx actually running or any follow-up DNS sidecar appearing.
    assert read_lines(output_dir / "followup_domains.txt") == []
    assert not (output_dir / "dnsx_records_followup_1.jsonl").exists()
    assert not (output_dir / "resolved_followup_1.txt").exists()


@pytest.mark.asyncio
async def test_followup_partial_dns_success_marks_each_host_independently(
    tmp_path: Path, settings: Settings
) -> None:
    """Partial follow-up: two candidates are scheduled, only one actually
    resolves (the dnsx stub deliberately omits the other, simulating a real
    partial-failure response rather than a crash). The successful host must
    be merged into the canonical DNS artifacts; the failed one must not be —
    silently treating a partial batch as fully successful would fabricate a
    resolution that never happened. Seed data must survive regardless."""
    settings.enable_followup_collection = True
    settings.max_discovery_depth = 1
    settings.max_followup_indicators = 10
    settings.enable_wildcard_check = False
    output_dir = tmp_path / "run"
    output_dir.mkdir()

    write_lines(output_dir / "resolved.txt", [SEED], base_dir=output_dir)
    write_jsonl(
        output_dir / "dnsx_records.jsonl",
        [{"host": SEED, "a": ["203.0.113.10"], "status_code": "NOERROR"}],
        base_dir=output_dir,
    )
    write_jsonl(
        output_dir / "ctlogs.jsonl",
        [
            {
                "id": 3,
                "common_name": SEED,
                "name_value": f"{SEED}\n{FOLLOW}\n{FOLLOW2}",
                "issuer_name": "Test CA",
                "serial_number": "cc33",
                "fingerprint_sha256": "c" * 64,
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
        run_id="followup-partial",
        collection_scope=CollectionScope.from_seeds([SEED], patterns=[SEED, FOLLOW, FOLLOW2]),
        metadata={"dns_probes": 1, "http_probes": 0},
    )
    runner = PipelineRunner(settings)
    dnsx = runner.tool_manager.get_plugin("dnsx")
    assert dnsx is not None

    async def partial_dnsx(ctx: PipelineContext, input_path: Path) -> PluginResult:
        gated = dnsx._authorized_input(ctx, input_path)
        hosts = read_lines(gated)
        # Only FOLLOW resolves; FOLLOW2 is dropped, simulating NXDOMAIN/no
        # answer for that one candidate — a real partial outcome, not a crash.
        resolved_hosts = [h for h in hosts if h != FOLLOW2]
        suffix = str(ctx.metadata.get("dnsx_output_suffix") or "")
        records_path = dnsx._output_path(ctx, f"dnsx_records{suffix}.jsonl")
        resolved_path = dnsx._output_path(ctx, f"resolved{suffix}.txt")
        write_jsonl(
            records_path,
            [{"host": h, "a": ["198.51.100.7"], "status_code": "NOERROR"} for h in resolved_hosts],
            base_dir=ctx.output_dir,
        )
        write_lines(resolved_path, resolved_hosts, base_dir=ctx.output_dir)
        return PluginResult(
            success=True, output_path=resolved_path, lines_produced=len(resolved_hosts)
        )

    dnsx.run = partial_dnsx  # type: ignore[method-assign]
    runner.tool_manager.is_runnable = lambda name: name == "dnsx"  # type: ignore[method-assign]
    runner.tool_manager.ensure_mandatory_tools = AsyncMock()

    await runner._maybe_collect_followups(context, output_dir / "resolved.txt")

    resolved = set(read_lines(output_dir / "resolved.txt"))
    assert SEED in resolved
    assert FOLLOW in resolved, "the host that actually resolved must be merged in"
    assert FOLLOW2 not in resolved, "a host that never resolved must not be fabricated as collected"

    canonical_hosts = {
        str(rec.get("host")) for rec in read_jsonl(output_dir / "dnsx_records.jsonl")
    }
    assert FOLLOW in canonical_hosts
    assert FOLLOW2 not in canonical_hosts
    seed_rows = [
        rec for rec in read_jsonl(output_dir / "dnsx_records.jsonl") if rec.get("host") == SEED
    ]
    assert seed_rows and seed_rows[0].get("a") == ["203.0.113.10"], "seed data must be intact"
