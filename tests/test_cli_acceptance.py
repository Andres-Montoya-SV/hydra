"""Phase 14: actual app.py CLI dispatch, not a copied-artifact finalize.

Network collectors are stubbed at the plugin class boundary. Authorization,
artifact union, SQLite, and query commands are the production path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("rich")

from core.intel.scope import authorize_plugin_input
from core.models import ToolStatus
from core.plugin_base import PluginResult
from modules.ctlogs import CtlogsPlugin
from modules.dnsx import DnsxPlugin
from modules.httpx import HttpxPlugin
from modules.subfinder import SubfinderPlugin
from utils.files import read_lines, write_jsonl, write_lines

SEED = "virusbarrier.xyz"
WWW = "www.virusbarrier.xyz"
OOS = "virusinspector.top"
IP_SEED = "34.75.127.116"
IP_WWW = "34.75.127.117"
FINGERPRINT = "7d1e4c8a9b2f0e6d5c4b3a29180766554433221100ffeeddccbbaa9988776655"
RUN_ID = "cli-accept"


def _env_lines(scope_file: Path) -> str:
    return "\n".join(
        [
            "ENABLE_WHOIS=false",
            "ENABLE_ASN_LOOKUP=false",
            "ENABLE_WILDCARD_CHECK=false",
            "ENABLE_SOFT404_CHECK=false",
            "ENABLE_VULN_MATCH=false",
            "ENABLE_SECURITY_HEADERS=false",
            "ENABLE_NAABU=false",
            "ENABLE_PORT_VERIFY=false",
            "ENABLE_AMASS=false",
            "ENABLE_ASSETFINDER=false",
            "ENABLE_KATANA=false",
            "ENABLE_GAU=false",
            "ENABLE_WAYBACKURLS=false",
            "ENABLE_NUCLEI=false",
            "ENABLE_PARAM_FUZZ=false",
            "ENABLE_CLOUD_BUCKET_ENUM=false",
            "ENABLE_THREAT_INTEL=false",
            "ENABLE_BROWSER_PROBE=false",
            "ENABLE_CTLOGS=true",
            "ENABLE_FOLLOWUP_COLLECTION=true",
            "MAX_DISCOVERY_DEPTH=1",
            f"SCOPE_FILE={scope_file}",
            "LOG_LEVEL=WARNING",
            "HYDRA_NO_BANNER=1",
        ]
    )


def _install_class_stubs(monkeypatch) -> dict[str, list[str]]:
    traces = {"dns_inputs": [], "http_inputs": []}

    async def stub_subfinder(self, context, input_path):
        write_lines(context.output_dir / "subfinder.txt", [SEED], base_dir=context.output_dir)
        write_lines(context.output_dir / "subdomains.txt", [SEED], base_dir=context.output_dir)
        context.subdomains = [SEED]
        return PluginResult(
            success=True, output_path=context.output_dir / "subdomains.txt", lines_produced=1
        )

    async def stub_ctlogs(self, context, input_path):
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
        merged = list(
            dict.fromkeys(read_lines(context.output_dir / "subdomains.txt") + [SEED, WWW, OOS])
        )
        write_lines(context.output_dir / "subdomains.txt", merged, base_dir=context.output_dir)
        context.subdomains = merged
        return PluginResult(
            success=True, output_path=context.output_dir / "ctlogs.jsonl", lines_produced=1
        )

    async def stub_dnsx(self, context, input_path):
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

    async def stub_httpx(self, context, input_path):
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

    monkeypatch.setattr(SubfinderPlugin, "run", stub_subfinder)
    monkeypatch.setattr(CtlogsPlugin, "run", stub_ctlogs)
    monkeypatch.setattr(DnsxPlugin, "run", stub_dnsx)
    monkeypatch.setattr(HttpxPlugin, "run", stub_httpx)
    return traces


def _patch_tool_manager(monkeypatch) -> None:
    from core.dependencies.service import DependencyService
    from core.tool_manager import ToolManager

    async def fake_validate(self, context):
        for plugin in self.get_all_plugins():
            info = plugin.build_tool_info()
            info.status = (
                ToolStatus.READY
                if plugin.name in {"subfinder", "ctlogs", "dnsx", "httpx"}
                else ToolStatus.SKIPPED
            )
            context.tool_states[plugin.name] = info
        return True

    async def fake_analyze(self, force_refresh: bool = False):
        return {}

    monkeypatch.setattr(ToolManager, "validate_tools", fake_validate)
    monkeypatch.setattr(ToolManager, "ensure_mandatory_tools", AsyncMock())
    monkeypatch.setattr(
        ToolManager,
        "is_runnable",
        lambda self, name: name in {"subfinder", "ctlogs", "dnsx", "httpx"},
    )
    monkeypatch.setattr(DependencyService, "analyze_all", fake_analyze)
    monkeypatch.setattr(
        "ui.dependency_report.render_dependency_report", lambda *args, **kwargs: None
    )


def _invoke(monkeypatch, argv: list[str]) -> int:
    import app as hydra_app

    monkeypatch.setattr(sys, "argv", argv)
    return hydra_app.main()


def test_app_py_run_then_investigate_relationships_evidence_diff(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    import app as hydra_app

    scope_path = tmp_path / "scope.txt"
    scope_path.write_text(f"{SEED}\n*.{SEED}\n", encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text(_env_lines(scope_path), encoding="utf-8")
    (tmp_path / "output").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "reports").mkdir()

    monkeypatch.setattr(hydra_app, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("HYDRA_NO_BANNER", "1")
    for key, value in {
        "ENABLE_WHOIS": "false",
        "ENABLE_ASN_LOOKUP": "false",
        "ENABLE_WILDCARD_CHECK": "false",
        "ENABLE_SOFT404_CHECK": "false",
        "ENABLE_VULN_MATCH": "false",
        "ENABLE_SECURITY_HEADERS": "false",
        "ENABLE_NAABU": "false",
        "ENABLE_PORT_VERIFY": "false",
        "ENABLE_CTLOGS": "true",
        "ENABLE_FOLLOWUP_COLLECTION": "true",
        "SCOPE_FILE": str(scope_path),
        "LOG_LEVEL": "WARNING",
    }.items():
        monkeypatch.setenv(key, value)

    traces = _install_class_stubs(monkeypatch)
    _patch_tool_manager(monkeypatch)

    rc = _invoke(
        monkeypatch,
        [
            "app.py",
            "--env",
            str(env_path),
            "--no-banner",
            "run",
            "--no-ui",
            "-d",
            SEED,
            "--run-id",
            RUN_ID,
        ],
    )
    capsys.readouterr()
    assert rc == 0
    assert len(traces["dns_inputs"]) >= 2, "CLI run must execute follow-up DNS"
    assert len(traces["http_inputs"]) >= 2, "CLI run must execute follow-up HTTP"
    assert WWW in "\n".join(traces["dns_inputs"])
    assert OOS not in "\n".join(traces["dns_inputs"])

    output_dir = tmp_path / "output" / RUN_ID
    resolved = read_lines(output_dir / "resolved.txt")
    alive = read_lines(output_dir / "alive.txt")
    assert SEED in resolved
    assert WWW in resolved
    assert OOS not in resolved
    assert any(SEED in line for line in alive)
    assert any(WWW in line for line in alive)
    assert not any(OOS in line for line in alive)

    db_path = tmp_path / "output" / "recon.db"
    assert db_path.exists()

    rc = _invoke(
        monkeypatch,
        ["app.py", "--env", str(env_path), "--no-banner", "investigate", SEED, "--run-id", RUN_ID],
    )
    investigate = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(investigate)
    assert payload.get("run_id") == RUN_ID
    assert "SAN_CONTAINS" in investigate or "certificate" in investigate.lower()

    rc = _invoke(
        monkeypatch,
        [
            "app.py",
            "--env",
            str(env_path),
            "--no-banner",
            "relationships",
            SEED,
            "--run-id",
            RUN_ID,
        ],
    )
    rel_out = capsys.readouterr().out
    assert rc == 0
    relationships = json.loads(rel_out)
    assert relationships["relationships"]
    assert relationships["relationships"][0]["relationship_id"]
    assert relationships["relationships"][0]["confidence_band"]
    assert relationships["relationships"][0]["explanation"]

    rc = _invoke(
        monkeypatch,
        ["app.py", "--env", str(env_path), "--no-banner", "evidence", SEED, "--run-id", RUN_ID],
    )
    evidence_out = capsys.readouterr().out
    assert rc == 0
    evidence = json.loads(evidence_out)
    assert evidence.get("evidence")

    rc = _invoke(
        monkeypatch,
        ["app.py", "--env", str(env_path), "--no-banner", "diff", SEED],
    )
    diff_out = capsys.readouterr().out
    assert rc in {0, 1}
    diff_payload = json.loads(diff_out)
    assert "error" in diff_payload or "previous_run_id" in diff_payload
