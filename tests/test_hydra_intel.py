"""Tests for CVE correlation, security headers, scope, webhooks, HTML glossary."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import PipelineContext
from core.parsers.registry import SecurityHeadersParser, VulnMatchParser
from core.reporter import ReportGenerator
from core.scope import host_in_scope, load_scope_patterns, out_of_scope_targets
from core.webhook import diff_has_changes, format_diff_message, notify_scan_diff
from modules.security_headers import SecurityHeadersPlugin, missing_security_headers
from modules.vuln_match import VulnMatchPlugin, parse_tech_name_version, severity_from_score
from utils.files import read_jsonl


def test_parse_tech_and_severity() -> None:
    assert parse_tech_name_version("Bookly:27.8") == ("Bookly", "27.8")
    assert parse_tech_name_version("WordPress") == ("WordPress", None)
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.5) == "high"
    assert severity_from_score(5.0) == "medium"


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.mark.asyncio
async def test_vuln_match_bookly_cve_fixture(settings: Settings, tmp_path: Path) -> None:
    settings.enable_vuln_match = True
    output_dir = tmp_path / "Users" / "testuser" / "secret-project" / "output" / "run1"
    output_dir.mkdir(parents=True)
    context = PipelineContext(
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(
            ["www.metaversejustice.com", "metaversejustice.com"]
        ),
    )
    context.httpx_results = [
        {
            "host": "www.metaversejustice.com",
            "input": "www.metaversejustice.com",
            "url": "https://www.metaversejustice.com/",
            "tech": ["Bookly:27.8", "WordPress"],
        }
    ]
    osv_body = json.dumps(
        {
            "vulns": [
                {
                    "id": "GHSA-bookly-demo",
                    "aliases": ["CVE-2026-13395"],
                    "summary": "Bookly 27.8 advisory from fixture",
                    "severity": [{"type": "CVSS_V3", "score": "8.1"}],
                }
            ]
        }
    ).encode()

    with patch("modules.vuln_match.open_url", return_value=_FakeResp(osv_body)):
        result = await VulnMatchPlugin(settings).run(context, output_dir / "alive.txt")

    assert result.success
    rows = read_jsonl(output_dir / "vuln_match.jsonl")
    assert rows
    assert rows[0]["identifier"] == "CVE-2026-13395"
    assert rows[0]["technology"] == "Bookly"
    assert rows[0]["raw_artifact"] == "vuln_match_raw.txt"
    blob = (output_dir / "vuln_match.jsonl").read_text(encoding="utf-8")
    assert "/Users/testuser/secret-project" not in blob

    hosts, _ = VulnMatchParser().parse(output_dir)
    assert hosts
    assert any(f.template_id == "vuln-match" for f in hosts[0].findings)
    assert "CVE-2026-13395" in hosts[0].findings[0].name


@pytest.mark.asyncio
async def test_security_headers_missing_and_complete(settings: Settings, tmp_path: Path) -> None:
    settings.enable_security_headers = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds(
            ["www.metaversejustice.com", "metaversejustice.com"]
        ),
    )
    context.httpx_results = [
        {
            "host": "missing.example",
            "url": "https://missing.example/",
            "header": {"server": "nginx"},
        },
        {
            "host": "complete.example",
            "url": "https://complete.example/",
            "header": {
                "Strict-Transport-Security": "max-age=63072000",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
        },
    ]
    await SecurityHeadersPlugin(settings).run(context, output_dir / "alive.txt")
    rows = read_jsonl(output_dir / "security_headers.jsonl")
    missing_host = [r for r in rows if r["host"] == "missing.example" and r["missing"]]
    assert len(missing_host) >= 4
    complete = [r for r in rows if r["host"] == "complete.example"]
    assert complete and complete[0]["missing"] is False
    assert complete[0]["security_headers_score"] == 100
    # One raw file per host (security_headers_raw/<host>.txt), not a single
    # shared file — each host's rows point at its own artifact.
    missing_rows = [r for r in rows if r["host"] == "missing.example"]
    assert all(
        r.get("raw_artifact") == "security_headers_raw/missing.example.txt" for r in missing_rows
    )
    assert complete[0].get("raw_artifact") == "security_headers_raw/complete.example.txt"

    hosts, _ = SecurityHeadersParser().parse(output_dir)
    missing = next(h for h in hosts if h.domain == "missing.example")
    assert any(f.template_id == "missing-security-header" for f in missing.findings)
    complete_h = next(h for h in hosts if h.domain == "complete.example")
    assert complete_h.security_headers_score == 100
    assert not complete_h.findings


def test_frame_ancestors_satisfies_xfo() -> None:
    missing = missing_security_headers(
        {"content-security-policy": "frame-ancestors 'none'", "x-content-type-options": "nosniff"}
    )
    assert "x-frame-options" not in missing


def test_scope_exact_and_reject(tmp_path: Path) -> None:
    path = tmp_path / "scope.txt"
    path.write_text(
        "metaversejustice.com\nwww.metaversejustice.com\n"
        "metaversephone.com\nwww.metaversephone.com\n",
        encoding="utf-8",
    )
    patterns = load_scope_patterns(path)
    assert host_in_scope("www.metaversejustice.com", patterns)
    assert host_in_scope("metaversejustice.com", patterns)
    assert host_in_scope("api.metaversejustice.com", patterns)
    assert not host_in_scope("evil.example", patterns)
    rejected = out_of_scope_targets(["evil.com", "www.metaversejustice.com"], patterns)
    assert rejected == ["evil.com"]


def test_webhook_silent_without_url_and_posts_on_diff() -> None:
    diff = {
        "new_hosts": ["a.example"],
        "removed_hosts": [],
        "new_http": [],
        "removed_http": [],
    }
    assert diff_has_changes(diff)
    assert "new hosts" in format_diff_message(diff)
    assert notify_scan_diff(None, diff) is False
    assert notify_scan_diff("https://hooks.example/x", {"new_hosts": []}) is False

    with patch("core.webhook.open_url", return_value=_FakeResp(b"ok")) as mocked:
        assert notify_scan_diff("https://hooks.example/x", diff) is True
        mocked.assert_called_once()


def test_html_executive_and_glossary(settings: Settings, tmp_path: Path) -> None:
    from core.assets import Finding, Host, InfrastructureGraph

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    host = Host(domain="example.com")
    host.findings.append(
        Finding(
            host="example.com",
            template_id="tarpit-detected",
            severity="info",
            name="Tarpit suspected",
            source="tarpit_check",
            description="canaries open",
        )
    )

    class _FakeStore:
        def get_hosts(self, run_id: str, *, limit: int = 0, offset: int = 0):
            return [host]

        def get_graph(self, run_id: str):
            return InfrastructureGraph()

        def query_hosts_by_risk(self, run_id: str, min_score: int = 25):
            return [host]

    context = PipelineContext(output_dir=output_dir, run_id="r1")
    (output_dir / "tarpit_check.jsonl").write_text(
        json.dumps(
            {
                "host": "example.com",
                "tarpit_suspected": True,
                "raw_artifact": "tarpit_check_raw/example.com.txt",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    raw_dir = output_dir / "tarpit_check_raw"
    raw_dir.mkdir()
    (raw_dir / "example.com.txt").write_text("CANARY PORT 6 open\nnmap -sV -Pn\n", encoding="utf-8")
    reporter = ReportGenerator(settings)
    reporter._write_html_summary(context, reporter.build_summary(context), store=_FakeStore())
    html = (output_dir / "summary.html").read_text(encoding="utf-8")
    assert "executive-summary" in html
    assert "Resumen ejecutivo" in html
    assert "tarpit-detected" in html
    assert "Por qué importa" in html
    assert "unused canary ports" in html
    assert "<details class='evidence'>" in html
    assert "Evidencia cruda" in html
    assert "CANARY PORT 6 open" in html


@pytest.mark.asyncio
async def test_http_intel_plugins_skipped_when_httpx_empty(
    settings: Settings, tmp_path: Path
) -> None:
    """Empty httpx_results must warn and list both plugins in tools_skipped."""
    from core.models import ToolStatus
    from core.runner import PipelineRunner

    settings.enable_vuln_match = True
    settings.enable_security_headers = True
    runner = PipelineRunner(settings)
    context = PipelineContext(output_dir=tmp_path)
    context.httpx_results = []
    reason = "no httpx results available for technology correlation"
    await runner._run_httpx_dependent_plugin(
        context, "vuln_match", tmp_path / "alive.txt", skip_reason=reason
    )
    await runner._run_httpx_dependent_plugin(
        context, "security_headers", tmp_path / "alive.txt", skip_reason=reason
    )
    summary = ReportGenerator(settings).build_summary(context)
    listed = set(summary.tools_run) | set(summary.tools_failed) | set(summary.tools_skipped)
    assert "vuln_match" in summary.tools_skipped
    assert "security_headers" in summary.tools_skipped
    assert "vuln_match" in listed
    assert "security_headers" in listed
    assert "vuln_match skipped: no httpx results available for technology correlation" in (
        context.warnings
    )
    assert "security_headers skipped: no httpx results available for technology correlation" in (
        context.warnings
    )
    assert context.tool_states["vuln_match"].status == ToolStatus.SKIPPED
    assert context.tool_states["security_headers"].status == ToolStatus.SKIPPED


def test_httpx_cache_copies_json_sibling(settings: Settings, project_root: Path) -> None:
    """Legacy cache stored alive.txt only; siblings must still restore httpx.json."""
    from core.runner import PipelineRunner
    from core.store import AssetStore
    from modules.httpx import HttpxPlugin

    runner = PipelineRunner(settings)
    runner._store = AssetStore(project_root / "output" / "recon.db")
    prior = project_root / "output" / "prior"
    prior.mkdir(parents=True)
    (prior / "alive.txt").write_text("https://www.example.com\n", encoding="utf-8")
    (prior / "httpx.json").write_text(
        json.dumps(
            {
                "url": "https://www.example.com",
                "host": "www.example.com",
                "tech": ["nginx"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    current = project_root / "output" / "current"
    current.mkdir()
    context = PipelineContext(
        output_dir=current,
        collection_scope=CollectionScope.from_seeds(["example.com", "www.example.com"]),
    )
    input_path = current / "resolved.txt"
    input_path.write_text("example.com\n", encoding="utf-8")
    plugin = HttpxPlugin(settings)
    cache_key, input_hash = runner._cache_key(plugin, input_path)
    runner._store.set_cache_entry(
        cache_key,
        tool="httpx",
        input_hash=input_hash,
        artifact_path=str(prior / "alive.txt"),
        lines_produced=1,
        ttl_seconds=3600,
    )
    result = runner._load_cached_result(context, plugin, input_path)
    assert result is not None
    assert (current / "httpx.json").exists()
    assert context.httpx_results
    assert context.httpx_results[0]["host"] == "www.example.com"
