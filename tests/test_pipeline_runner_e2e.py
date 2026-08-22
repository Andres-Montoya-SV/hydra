"""Production-path virusbarrier E2E: PipelineRunner.run → collectors → SQLite → CLI.

Stubs live at the plugin boundary and write the same artifact names production uses.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.intel.cli import cmd_investigate
from core.intel.model import CollectionStatus, EntityType, RelationshipType, ScopeStatus
from core.intel.scope import authorize_plugin_input
from core.models import ToolStatus
from core.plugin_base import PluginResult
from core.runner import PipelineRunner
from core.store import AssetStore
from utils.files import read_jsonl, read_lines, write_jsonl, write_lines

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SEED = CASE["seed"]
SANS = list(CASE["sans"])
SIBLINGS = [name for name in SANS if name != SEED]
FINGERPRINT = CASE["fingerprint_sha256"]
IP = CASE["ipv4"]
RUN_ID = "virusbarrier-runner"


def _ready(plugin, status: ToolStatus = ToolStatus.READY):
    info = plugin.build_tool_info()
    info.status = status
    return info


@pytest.mark.asyncio
async def test_pipeline_runner_virusbarrier_production_path(tmp_path: Path, capsys) -> None:
    scope_path = tmp_path / "scope.txt"
    shutil.copy2(FIXTURE / "scope.txt", scope_path)
    settings = Settings(
        project_root=tmp_path,
        scope_file=scope_path,
        enable_whois=False,
        enable_asn_lookup=False,
        enable_wildcard_check=False,
        enable_soft404_check=False,
        enable_vuln_match=False,
        enable_security_headers=False,
        enable_naabu=False,
        enable_ctlogs=True,
        enable_followup_collection=True,
        enable_amass=False,
        enable_assetfinder=False,
        enable_katana=False,
        enable_gau=False,
        enable_waybackurls=False,
        enable_nuclei=False,
        enable_param_fuzz=False,
        enable_cloud_bucket_enum=False,
        enable_threat_intel=False,
        enable_browser_probe=False,
    )
    runner = PipelineRunner(settings)
    http_probed: list[str] = []
    dns_inputs: list[str] = []
    authorized_bodies: list[str] = []

    async def fake_validate(context):
        for plugin in runner.tool_manager.get_all_plugins():
            status = (
                ToolStatus.READY
                if plugin.name in {"subfinder", "ctlogs", "dnsx", "httpx"}
                else ToolStatus.SKIPPED
            )
            context.tool_states[plugin.name] = _ready(plugin, status)
        return True

    runner.tool_manager.validate_tools = fake_validate  # type: ignore[method-assign]
    runner.tool_manager.ensure_mandatory_tools = AsyncMock()
    runner.tool_manager.is_runnable = (  # type: ignore[method-assign]
        lambda name: name in {"subfinder", "ctlogs", "dnsx", "httpx"}
    )

    subfinder = runner.tool_manager.get_plugin("subfinder")
    ctlogs = runner.tool_manager.get_plugin("ctlogs")
    dnsx = runner.tool_manager.get_plugin("dnsx")
    httpx = runner.tool_manager.get_plugin("httpx")
    assert subfinder and ctlogs and dnsx and httpx

    async def stub_subfinder(context, input_path):
        write_lines(context.output_dir / "subfinder.txt", [SEED], base_dir=context.output_dir)
        write_lines(context.output_dir / "subdomains.txt", [SEED], base_dir=context.output_dir)
        context.subdomains = [SEED]
        return PluginResult(
            success=True,
            output_path=context.output_dir / "subdomains.txt",
            lines_produced=1,
        )

    async def stub_ctlogs(context, input_path):
        shutil.copy2(FIXTURE / "ctlogs.jsonl", context.output_dir / "ctlogs.jsonl")
        write_lines(context.output_dir / "ctlogs_domains.txt", [SEED], base_dir=context.output_dir)
        merged = list(dict.fromkeys(read_lines(context.output_dir / "subdomains.txt") + [SEED]))
        write_lines(context.output_dir / "subdomains.txt", merged, base_dir=context.output_dir)
        context.subdomains = merged
        return PluginResult(
            success=True,
            output_path=context.output_dir / "ctlogs.jsonl",
            lines_produced=1,
        )

    async def stub_dnsx(context, input_path):
        gated = authorize_plugin_input(context, input_path, "dnsx")
        body = gated.read_text(encoding="utf-8")
        dns_inputs.append(body)
        authorized_bodies.append(body)
        hosts = read_lines(gated)
        suffix = str(context.metadata.get("dnsx_output_suffix") or "")
        records_path = context.output_dir / f"dnsx_records{suffix}.jsonl"
        resolved_path = context.output_dir / f"resolved{suffix}.txt"
        write_jsonl(
            records_path,
            [{"host": host, "a": [IP], "status_code": "NOERROR"} for host in hosts],
            base_dir=context.output_dir,
        )
        write_lines(resolved_path, hosts, base_dir=context.output_dir)
        if not suffix:
            context.resolved = hosts
        return PluginResult(success=True, output_path=resolved_path, lines_produced=len(hosts))

    async def stub_httpx(context, input_path):
        gated = authorize_plugin_input(context, input_path, "httpx")
        body = gated.read_text(encoding="utf-8")
        authorized_bodies.append(body)
        hosts = read_lines(gated)
        http_probed.extend(hosts)
        suffix = str(context.metadata.get("httpx_output_suffix") or "")
        json_path = context.output_dir / f"httpx{suffix}.json"
        if suffix:
            write_jsonl(json_path, [], base_dir=context.output_dir)
            return PluginResult(success=True, output_path=json_path, lines_produced=0)
        shutil.copy2(FIXTURE / "httpx.json", json_path)
        write_lines(
            context.output_dir / "alive.txt", [f"https://{SEED}/"], base_dir=context.output_dir
        )
        context.httpx_results = read_jsonl(json_path)
        return PluginResult(success=True, output_path=json_path, lines_produced=1)

    subfinder.run = stub_subfinder  # type: ignore[method-assign]
    ctlogs.run = stub_ctlogs  # type: ignore[method-assign]
    dnsx.run = stub_dnsx  # type: ignore[method-assign]
    httpx.run = stub_httpx  # type: ignore[method-assign]

    context = await runner.run(domain=SEED, run_id=RUN_ID)
    assert context.finalized
    assert context.errors == [] or all("unexpect" not in e.lower() for e in context.errors)

    combined_auth = "\n".join(authorized_bodies)
    for name in SIBLINGS:
        assert name not in combined_auth
        assert name not in http_probed
        for chunk in dns_inputs:
            assert name not in chunk
    assert SEED in http_probed

    output_dir = context.output_dir
    for path in output_dir.glob("authorized_*"):
        body = path.read_text(encoding="utf-8")
        for name in SIBLINGS:
            assert name not in body
    for name in SIBLINGS:
        assert name not in read_lines(output_dir / "resolved.txt")
        assert name not in {str(r.get("host")) for r in read_jsonl(output_dir / "dnsx_records.jsonl")}
        assert name not in {
            str(r.get("input") or r.get("host") or "")
            for r in read_jsonl(output_dir / "httpx.json")
        }

    seed_dns = read_jsonl(output_dir / "dnsx_records.jsonl")
    assert any(rec.get("host") == SEED for rec in seed_dns)

    db_path = tmp_path / "output" / "recon.db"
    store = AssetStore(db_path)
    conn = store.intel_connection()
    domains = conn.execute(
        "SELECT key, scope_status, collection_status FROM intel_entities "
        "WHERE run_id=? AND entity_type='DOMAIN'",
        (context.run_id,),
    ).fetchall()
    by_key = {row["key"]: row for row in domains}
    assert set(SANS) <= set(by_key)
    assert by_key[SEED]["collection_status"] == CollectionStatus.COLLECTED.value
    for name in SIBLINGS:
        assert by_key[name]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value
        assert by_key[name]["collection_status"] == CollectionStatus.NOT_ALLOWED.value

    certs = conn.execute(
        "SELECT entity_id, data_json FROM intel_entities WHERE run_id=? AND entity_type=?",
        (context.run_id, EntityType.CERTIFICATE.value),
    ).fetchall()
    assert certs
    assert any(FINGERPRINT in (row["entity_id"] + (row["data_json"] or "")) for row in certs)

    rel_types = {
        row["relationship_type"]
        for row in conn.execute(
            "SELECT relationship_type FROM intel_relationships WHERE run_id=?",
            (context.run_id,),
        )
    }
    assert RelationshipType.SHARES_CERTIFICATE.value in rel_types
    blob = json.dumps([dict(row) for row in conn.execute(
        "SELECT source_entity, relationship_type, target_entity, data_json "
        "FROM intel_relationships WHERE run_id=?",
        (context.run_id,),
    )]).lower()
    assert "actor:" not in blob
    assert "owner:" not in blob
    conn.close()

    assert cmd_investigate(db_path, SEED, context.run_id, None) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert SEED in out
    assert "SHARES_CERTIFICATE" in out
    assert FINGERPRINT in out
    assert "explanations" in payload
    assert "actor" not in out.lower()
    assert "owned by" not in out.lower()
