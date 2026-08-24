"""True PipelineRunner control-loop E2E: seed → CT → DNS → HTTP → intel → follow-up.

Stubs live at the plugin boundary and write production artifact names.
This test fails if follow-up DNS or HTTP is skipped.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.intel.cli import cmd_evidence, cmd_investigate, cmd_relationships
from core.intel.model import CollectionStatus, RelationshipType, ScopeStatus
from core.intel.scope import authorize_plugin_input
from core.models import ToolStatus
from core.plugin_base import PluginResult
from core.runner import PipelineRunner
from core.store import AssetStore
from utils.files import read_lines, write_jsonl, write_lines

SEED = "seed.example.com"
WWW = "www.seed.example.com"
OOS = "malicious-or-unrelated.example.net"
IP_SEED = "203.0.113.10"
IP_WWW = "203.0.113.11"
FINGERPRINT = "ab" * 32
RUN_ID = "asi-loop"


def _ready(plugin, status: ToolStatus = ToolStatus.READY):
    info = plugin.build_tool_info()
    info.status = status
    return info


def _loop_settings(tmp_path: Path) -> Settings:
    scope_path = tmp_path / "scope.txt"
    scope_path.write_text(f"{SEED}\n*.{SEED}\n", encoding="utf-8")
    return Settings(
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


def _install_loop_stubs(runner: PipelineRunner) -> dict[str, list[str]]:
    traces = {"dns_inputs": [], "http_inputs": []}

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
            success=True, output_path=context.output_dir / "subdomains.txt", lines_produced=1
        )

    async def stub_ctlogs(context, input_path):
        write_jsonl(
            context.output_dir / "ctlogs.jsonl",
            [
                {
                    "id": 1,
                    "common_name": SEED,
                    "name_value": f"{SEED}\n{WWW}\n{OOS}",
                    "issuer_name": "Test CA",
                    "serial_number": "aa11",
                    "fingerprint_sha256": FINGERPRINT,
                    "query_domain": SEED,
                }
            ],
            base_dir=context.output_dir,
        )
        write_lines(
            context.output_dir / "ctlogs_domains.txt",
            [SEED, WWW, OOS],
            base_dir=context.output_dir,
        )
        merged = list(dict.fromkeys(read_lines(context.output_dir / "subdomains.txt") + [SEED, WWW, OOS]))
        write_lines(context.output_dir / "subdomains.txt", merged, base_dir=context.output_dir)
        context.subdomains = merged
        return PluginResult(
            success=True, output_path=context.output_dir / "ctlogs.jsonl", lines_produced=1
        )

    async def stub_dnsx(context, input_path):
        gated = authorize_plugin_input(context, input_path, "dnsx")
        traces["dns_inputs"].append(gated.read_text(encoding="utf-8"))
        hosts = read_lines(gated)
        assert OOS not in hosts
        suffix = str(context.metadata.get("dnsx_output_suffix") or "")
        records_path = context.output_dir / f"dnsx_records{suffix}.jsonl"
        resolved_path = context.output_dir / f"resolved{suffix}.txt"
        records = []
        for host in hosts:
            ip = IP_WWW if host == WWW else IP_SEED
            records.append({"host": host, "a": [ip], "status_code": "NOERROR"})
        write_jsonl(records_path, records, base_dir=context.output_dir)
        write_lines(resolved_path, hosts, base_dir=context.output_dir)
        if not suffix:
            context.resolved = hosts
        return PluginResult(success=True, output_path=resolved_path, lines_produced=len(hosts))

    async def stub_httpx(context, input_path):
        gated = authorize_plugin_input(context, input_path, "httpx")
        traces["http_inputs"].append(gated.read_text(encoding="utf-8"))
        hosts = read_lines(gated)
        assert OOS not in hosts
        suffix = str(context.metadata.get("httpx_output_suffix") or "")
        json_path = context.output_dir / f"httpx{suffix}.json"
        alive_path = context.output_dir / f"alive{suffix}.txt"
        records = []
        alive = []
        for host in hosts:
            url = f"https://{host}/"
            records.append(
                {
                    "input": host,
                    "url": url,
                    "status_code": 200,
                    "a": [IP_WWW if host == WWW else IP_SEED],
                    "tls": {
                        "fingerprint_hash": {"sha256": FINGERPRINT},
                        "subject_an": [SEED, WWW, OOS],
                    },
                }
            )
            alive.append(url)
        write_jsonl(json_path, records, base_dir=context.output_dir)
        write_lines(alive_path, alive, base_dir=context.output_dir)
        if not suffix:
            context.alive_urls = alive
            context.httpx_results = records
        return PluginResult(success=True, output_path=json_path, lines_produced=len(alive))

    subfinder.run = stub_subfinder  # type: ignore[method-assign]
    ctlogs.run = stub_ctlogs  # type: ignore[method-assign]
    dnsx.run = stub_dnsx  # type: ignore[method-assign]
    httpx.run = stub_httpx  # type: ignore[method-assign]
    return traces


@pytest.mark.asyncio
async def test_pipeline_runner_authorized_followup_loop(tmp_path: Path, capsys) -> None:
    settings = _loop_settings(tmp_path)
    runner = PipelineRunner(settings)
    traces = _install_loop_stubs(runner)

    context = await runner.run(domain=SEED, run_id=RUN_ID)
    assert context.finalized
    assert not traces["dns_inputs"] or WWW in "\n".join(traces["dns_inputs"])
    assert len(traces["dns_inputs"]) >= 2, "follow-up DNS must run"
    assert len(traces["http_inputs"]) >= 2, "follow-up HTTP must run"
    assert WWW in "\n".join(traces["dns_inputs"])
    assert WWW in "\n".join(traces["http_inputs"])
    assert OOS not in "\n".join(traces["dns_inputs"])
    assert OOS not in "\n".join(traces["http_inputs"])

    output_dir = context.output_dir
    resolved = read_lines(output_dir / "resolved.txt")
    alive = read_lines(output_dir / "alive.txt")
    assert SEED in resolved
    assert WWW in resolved
    assert OOS not in resolved
    assert any(SEED in line for line in alive)
    assert any(WWW in line for line in alive)
    assert not any(OOS in line for line in alive)
    assert (output_dir / "resolved_seed.txt").exists()
    assert (output_dir / "alive_seed.txt").exists()
    assert (output_dir / "authorized_alive.txt").exists()
    assert OOS not in read_lines(output_dir / "authorized_alive.txt")

    db_path = tmp_path / "output" / "recon.db"
    store = AssetStore(db_path)
    conn = store.intel_connection()
    domains = {
        row["key"]: row
        for row in conn.execute(
            "SELECT key, scope_status, collection_status FROM intel_entities "
            "WHERE run_id=? AND entity_type='DOMAIN'",
            (context.run_id,),
        )
    }
    assert domains[SEED]["collection_status"] == CollectionStatus.COLLECTED.value
    assert domains[WWW]["collection_status"] == CollectionStatus.COLLECTED.value
    assert domains[OOS]["scope_status"] == ScopeStatus.OUT_OF_SCOPE.value
    assert domains[OOS]["collection_status"] == CollectionStatus.NOT_ALLOWED.value

    obs_keys = {
        row["key"]
        for row in conn.execute(
            "SELECT e.key FROM intel_observations o "
            "JOIN intel_entities e ON e.entity_id=o.entity_id AND e.run_id=o.run_id "
            "WHERE o.run_id=?",
            (context.run_id,),
        )
    }
    assert OOS in obs_keys or OOS in domains

    rel_types = {
        row["relationship_type"]
        for row in conn.execute(
            "SELECT relationship_type FROM intel_relationships WHERE run_id=?",
            (context.run_id,),
        )
    }
    assert RelationshipType.SAN_CONTAINS.value in rel_types
    evidence_count = conn.execute(
        "SELECT COUNT(*) AS c FROM intel_evidence WHERE run_id=?",
        (context.run_id,),
    ).fetchone()["c"]
    assert evidence_count > 0
    conn.close()

    assert cmd_investigate(db_path, SEED, context.run_id, None) == 0
    investigate = capsys.readouterr().out
    assert SEED in investigate
    assert "SAN_CONTAINS" in investigate or "certificate" in investigate.lower()
    assert cmd_relationships(db_path, SEED, context.run_id) == 0
    relationships = json.loads(capsys.readouterr().out)
    assert relationships["relationships"]
    assert relationships["relationships"][0]["relationship_id"]
    assert relationships["relationships"][0]["confidence_band"]
    assert cmd_evidence(db_path, SEED, context.run_id) == 0

    assets = json.loads((output_dir / "assets.json").read_text(encoding="utf-8"))
    intel_rels = (assets.get("intelligence") or {}).get("relationships") or []
    cli_ids = {item["relationship_id"] for item in relationships["relationships"]}
    json_ids = {item["relationship_id"] for item in intel_rels}
    assert cli_ids & json_ids or intel_rels
    md = (tmp_path / "reports" / "overview.md").read_text(encoding="utf-8")
    html = (output_dir / "summary.html").read_text(encoding="utf-8")
    blob = md + html + json.dumps(intel_rels)
    assert "SAN_CONTAINS" in blob or "SHARES_CERTIFICATE" in blob or "PRESENTS_CERTIFICATE" in blob
