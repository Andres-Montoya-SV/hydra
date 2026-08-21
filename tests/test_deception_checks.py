"""Regression tests for tarpit / wildcard-DNS / soft-404 / cloaking Findings."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from config.settings import Settings
from core.assets import Host
from core.confidence import score_subdomain
from core.intelligence.engine import IntelligenceEngine
from core.models import DomainTarget, PipelineContext
from core.parsers.registry import (
    BrowserProbeParser,
    Soft404CheckParser,
    TarpitCheckParser,
    WildcardCheckParser,
)
from modules.soft404_check import Soft404CheckPlugin, _is_soft_404
from modules.wildcard_check import WildcardCheckPlugin, _parse_resolved_hosts
from utils.files import read_jsonl, write_jsonl

# ---------------------------------------------------------------------------
# Task 1 — tarpit Finding (already wired; lock the contract)
# ---------------------------------------------------------------------------


def test_tarpit_suspected_host_has_exactly_one_tarpit_detected_finding(
    tmp_path: Path,
) -> None:
    write_jsonl(
        tmp_path / "tarpit_check.jsonl",
        [
            {
                "host": "www.metaversejustice.com",
                "tarpit_suspected": True,
                "canary_ports": [6, 9999, 23456, 54321],
                "canary_open_ports": [6, 9999, 23456, 54321],
                "probe_technique": "nmap -sV -Pn",
                "raw_artifact": "/tmp/tarpit_check_raw/www.metaversejustice.com.txt",
            }
        ],
    )
    hosts, _ = TarpitCheckParser().parse(tmp_path)
    host = hosts[0]
    assert host.tarpit_suspected is True
    assert len(host.findings) == 1
    assert host.findings[0].template_id == "tarpit-detected"
    assert host.findings[0].severity == "info"
    assert "4/4" in host.findings[0].description
    assert "nmap -sV" in host.findings[0].description


def test_tarpit_parser_skips_hosts_with_probe_error(tmp_path: Path) -> None:
    """A failed canary probe must not become a confident 'not a tarpit' Host."""
    write_jsonl(
        tmp_path / "tarpit_check.jsonl",
        [
            {
                "host": "www.metaversejustice.com",
                "tarpit_suspected": False,
                "canary_ports": [6, 9999, 23456, 54321],
                "canary_open_ports": [],
                "probe_error": "nmap probe failed: no valid ipv4 or ipv6 targets were found",
                "probe_technique": "nmap -sV -Pn",
            }
        ],
    )
    hosts, warnings = TarpitCheckParser().parse(tmp_path)
    assert hosts == []
    assert any("inconclusive" in w.lower() or "failed" in w.lower() for w in warnings)


# ---------------------------------------------------------------------------
# Task 2a — Wildcard DNS
# ---------------------------------------------------------------------------


def test_wildcard_parser_flags_root_and_creates_finding(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "wildcard_check.jsonl",
        [
            {
                "root_domain": "example.com",
                "wildcard_dns_detected": True,
                "canary_hosts": [
                    "zqxvwabc12345.example.com",
                    "zqxvwxyz98765.example.com",
                    "zqxvwqqq11111.example.com",
                ],
                "canary_resolved": [
                    "zqxvwabc12345.example.com",
                    "zqxvwxyz98765.example.com",
                ],
            }
        ],
    )
    hosts, warnings = WildcardCheckParser().parse(tmp_path)
    assert not warnings
    host = hosts[0]
    assert host.dns_wildcard is True
    assert len(host.findings) == 1
    assert host.findings[0].template_id == "wildcard-dns-detected"
    assert host.findings[0].severity == "info"
    assert "2/3" in host.findings[0].description


def test_wildcard_parser_does_not_flag_normal_root(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "wildcard_check.jsonl",
        [
            {
                "root_domain": "example.com",
                "wildcard_dns_detected": False,
                "canary_hosts": ["zqxvwabc.example.com", "zqxvwxyz.example.com"],
                "canary_resolved": [],
            }
        ],
    )
    hosts, _ = WildcardCheckParser().parse(tmp_path)
    assert hosts[0].dns_wildcard is False
    assert hosts[0].findings == []


def test_parse_resolved_hosts_requires_address_records() -> None:
    json_stdout = (
        '{"host":"zqxvwabc.example.com","a":["1.2.3.4"]}\n'
        '{"host":"zqxvwxyz.example.com","aaaa":[]}\n'
        '{"host":"zqxvwqqq.example.com"}\n'
    )
    resolved = _parse_resolved_hosts(json_stdout)
    assert resolved == {"zqxvwabc.example.com"}

    plain = "zqxvwabc.example.com [1.2.3.4]\nzqxvwxyz.example.com\n"
    assert _parse_resolved_hosts(plain) == {"zqxvwabc.example.com"}


@pytest.mark.asyncio
async def test_wildcard_check_plugin_detects_when_canaries_resolve(
    settings: Settings, tmp_path: Path
) -> None:
    settings.enable_wildcard_check = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(
        output_dir=output_dir,
        targets=[DomainTarget(domain="www.example.com", source="cli")],
    )
    context.resolved_binaries["dnsx"] = Path("/usr/bin/dnsx")
    plugin = WildcardCheckPlugin(settings)

    async def fake_run_command(args, **kwargs):
        # Emit resolutions for whatever canaries were written
        canary_file = Path(args[args.index("-l") + 1])
        hosts = [line.strip() for line in canary_file.read_text().splitlines() if line.strip()]
        stdout = "\n".join(f'{{"host":"{h}","a":["9.9.9.9"]}}' for h in hosts) + "\n"
        return 0, stdout, ""

    with patch("modules.wildcard_check.run_command", new=fake_run_command):
        result = await plugin.run(context, output_dir / "targets.txt")

    assert result.success is True
    assert context.metadata["wildcard_dns_detected"] is True
    assert "example.com" in context.metadata["wildcard_dns_roots"]
    records = read_jsonl(output_dir / "wildcard_check.jsonl")
    assert records[0]["wildcard_dns_detected"] is True
    assert (output_dir / "wildcard_check_raw.txt").exists()


@pytest.mark.asyncio
async def test_wildcard_check_plugin_clean_when_canaries_do_not_resolve(
    settings: Settings, tmp_path: Path
) -> None:
    settings.enable_wildcard_check = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(
        output_dir=output_dir,
        targets=[DomainTarget(domain="example.com", source="cli")],
    )
    context.resolved_binaries["dnsx"] = Path("/usr/bin/dnsx")
    plugin = WildcardCheckPlugin(settings)

    async def fake_run_command(args, **kwargs):
        return 0, "", ""

    with patch("modules.wildcard_check.run_command", new=fake_run_command):
        result = await plugin.run(context, output_dir / "targets.txt")

    assert result.success is True
    assert context.metadata["wildcard_dns_detected"] is False
    assert context.metadata["wildcard_dns_roots"] == []
    assert read_jsonl(output_dir / "wildcard_check.jsonl")[0]["wildcard_dns_detected"] is False


def test_wildcard_demotes_passive_only_subdomain_confidence() -> None:
    root = Host(domain="example.com", dns_wildcard=True)
    child = Host(domain="api.example.com")
    child.add_source("subfinder")
    child.dns_resolved = True

    hosts = {root.domain: root, child.domain: child}
    IntelligenceEngine().process(hosts)

    enriched = hosts["api.example.com"]
    assert enriched.dns_wildcard is True
    assert enriched.confidence_score <= 25
    assert any("wildcard" in w.lower() for w in enriched.warnings)


def test_wildcard_does_not_demote_ctlogs_confirmed_subdomain() -> None:
    Host(domain="example.com", dns_wildcard=True)
    child = Host(domain="api.example.com")
    child.add_source("subfinder")
    child.add_source("ctlogs")
    child.dns_resolved = True

    _, score = score_subdomain(child)
    # Independently confirmed via CT — not forced to UNKNOWN/15
    assert score >= 50


# ---------------------------------------------------------------------------
# Task 2b — Soft-404
# ---------------------------------------------------------------------------


def test_soft404_parser_flags_host_and_creates_finding(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "soft404_check.jsonl",
        [
            {
                "host": "example.com",
                "soft_404_detected": True,
                "canary_url": "https://example.com/zzqq-abc-nonexistent-path-4821",
                "canary_status": 200,
                "canary_body_hash": "abcd" * 16,
                "root_status": 200,
            }
        ],
    )
    hosts, _ = Soft404CheckParser().parse(tmp_path)
    host = hosts[0]
    assert host.soft_404_detected is True
    assert len(host.findings) == 1
    assert host.findings[0].template_id == "soft-404-detected"
    assert host.findings[0].severity == "info"


def test_soft404_parser_does_not_flag_normal_host(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "soft404_check.jsonl",
        [
            {
                "host": "example.com",
                "soft_404_detected": False,
                "canary_url": "https://example.com/zzqq-abc-nonexistent-path-4821",
                "canary_status": 404,
            }
        ],
    )
    hosts, _ = Soft404CheckParser().parse(tmp_path)
    assert hosts[0].soft_404_detected is False
    assert hosts[0].findings == []


def test_is_soft_404_requires_200_and_similar_body() -> None:
    body = b"<html>homepage</html>" * 20
    assert _is_soft_404(200, body, 200, body) is True
    assert _is_soft_404(200, body, 404, body) is False
    assert _is_soft_404(200, body, 200, b"totally different page content here!!") is False
    # Near-identical size counts
    assert _is_soft_404(200, body, 200, body + b"x" * 10) is True


@pytest.mark.asyncio
async def test_soft404_plugin_detects_matching_canary(settings: Settings, tmp_path: Path) -> None:
    settings.enable_soft404_check = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir)
    context.httpx_results = [{"url": "https://example.com/", "input": "example.com"}]
    plugin = Soft404CheckPlugin(settings)

    body = b"<html>same catch-all page</html>" * 30

    def fake_get(url, *, timeout, proxy_url=None, **kwargs):
        from core.response_diff import ResponseSnapshot

        return ResponseSnapshot(200, body)

    with patch("modules.soft404_check.http_get", side_effect=fake_get):
        result = await plugin.run(context, output_dir / "alive.txt")

    assert result.success is True
    assert "example.com" in context.metadata["soft_404_detected_hosts"]
    record = read_jsonl(output_dir / "soft404_check.jsonl")[0]
    assert record["soft_404_detected"] is True
    assert record["raw_artifact"]


@pytest.mark.asyncio
async def test_soft404_plugin_clean_when_canary_is_404(settings: Settings, tmp_path: Path) -> None:
    settings.enable_soft404_check = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir)
    context.httpx_results = [{"url": "https://example.com/", "input": "example.com"}]
    plugin = Soft404CheckPlugin(settings)

    def fake_get(url, *, timeout, proxy_url=None, **kwargs):
        from core.response_diff import ResponseSnapshot

        if "nonexistent" in url or "zzqq-" in url:
            return ResponseSnapshot(404, b"Not Found")
        return ResponseSnapshot(200, b"<html>real homepage</html>" * 30)

    with patch("modules.soft404_check.http_get", side_effect=fake_get):
        result = await plugin.run(context, output_dir / "alive.txt")

    assert result.success is True
    assert context.metadata["soft_404_detected_hosts"] == []
    assert read_jsonl(output_dir / "soft404_check.jsonl")[0]["soft_404_detected"] is False


# ---------------------------------------------------------------------------
# Task 3 — Browser Probe cloaking Finding
# ---------------------------------------------------------------------------


def test_browser_probe_parser_creates_medium_cloaking_finding(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "browser_probe.jsonl",
        [
            {
                "host": "savvyshopguide.com",
                "httpx_final_url": "https://savvyshopguide.com/",
                "browser_final_url": "https://payload.example/landing",
                "redirect_chain": [
                    "https://savvyshopguide.com/",
                    "https://payload.example/landing",
                ],
                "cloaking_suspected": True,
                "raw_artifact": str(tmp_path / "browser_probe_raw" / "savvyshopguide.com.html"),
            }
        ],
    )
    hosts, _ = BrowserProbeParser().parse(tmp_path)
    assert len(hosts[0].findings) == 1
    finding = hosts[0].findings[0]
    assert finding.template_id == "cloaking-detected"
    assert finding.severity == "medium"
    assert "payload.example" in finding.description


def test_browser_probe_parser_silent_when_destinations_match(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "browser_probe.jsonl",
        [
            {
                "host": "example.com",
                "httpx_final_url": "https://example.com/",
                "browser_final_url": "https://example.com/",
                "redirect_chain": ["https://example.com/"],
                "cloaking_suspected": False,
                "raw_artifact": None,
            }
        ],
    )
    hosts, _ = BrowserProbeParser().parse(tmp_path)
    assert hosts == []
