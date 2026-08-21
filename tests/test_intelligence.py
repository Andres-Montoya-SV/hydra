"""Tests for intelligence engine and parsers."""

from __future__ import annotations

import json
from pathlib import Path

from core.assets import URL, Host, HttpService, Port
from core.confidence import score_port
from core.intelligence.engine import IntelligenceEngine
from core.intelligence.risk import score_host
from core.parsers.crawlers import parse_crawler_output
from core.parsers.registry import AssetfinderParser, DnsxParser, HttpxParser, SubdomainParser
from core.provenance import record_observation
from core.registry import HostRegistry


class TestParsers:
    def test_subfinder_parser(self, tmp_path: Path) -> None:
        subs = tmp_path / "subdomains.txt"
        subs.write_text("api.example.com\nwww.example.com\n", encoding="utf-8")
        hosts, _ = SubdomainParser().parse(tmp_path)
        assert len(hosts) == 2
        assert hosts[0].provenance[0].tool == "subfinder"

    def test_subdomain_parser_prefers_raw_tool_artifact(self, tmp_path: Path) -> None:
        (tmp_path / "subdomains.txt").write_text(
            "api.example.com\nwww.example.com\n", encoding="utf-8"
        )
        (tmp_path / "assetfinder.txt").write_text(
            "api.example.com\ncdn.example.com\n", encoding="utf-8"
        )
        hosts, _ = AssetfinderParser().parse(tmp_path)
        domains = {host.domain for host in hosts}
        assert domains == {"api.example.com", "cdn.example.com"}
        assert all(host.provenance[0].tool == "assetfinder" for host in hosts)

    def test_httpx_parser(self, tmp_path: Path) -> None:
        httpx_json = tmp_path / "httpx.json"
        record = {
            "url": "https://api.example.com",
            "input": "api.example.com",
            "status_code": 200,
            "title": "API",
            "tech": ["nginx"],
            "header": {"server": "nginx"},
        }
        httpx_json.write_text(json.dumps(record) + "\n", encoding="utf-8")
        hosts, _ = HttpxParser().parse(tmp_path)
        assert len(hosts) == 1
        assert hosts[0].http_services[0].technologies[0].name == "nginx"
        assert hosts[0].http_services[0].technologies[0].confidence == 95

    def test_dnsx_parser_enriches_extended_records(self, tmp_path: Path) -> None:
        dnsx_json = tmp_path / "dnsx_records.jsonl"
        record = {
            "host": "api.example.com",
            "a": ["104.16.1.1"],
            "mx": ["10 mail.example.com."],
            "txt": ["v=spf1 +all"],
            "caa": ["0 issue letsencrypt.org"],
            "srv": ["10 service.example.com."],
            "ptr": ["reverse.example.com."],
            "ttl": 300,
        }
        dnsx_json.write_text(json.dumps(record) + "\n", encoding="utf-8")
        hosts, _ = DnsxParser().parse(tmp_path)
        host = hosts[0]
        types = {rec.record_type for rec in host.dns_records}
        assert {"A", "MX", "TXT", "CAA", "SRV", "PTR"} <= types
        assert any("weak-spf" in rec.security_tags for rec in host.dns_records)
        assert any(rec.priority == 10 for rec in host.dns_records if rec.record_type == "MX")

    def test_crawler_parser_extracts_api_params_and_tokens(self, tmp_path: Path) -> None:
        crawl = tmp_path / "katana.jsonl"
        crawl.write_text(
            json.dumps({"url": "https://api.example.com/v1/users?id=1&api_key=secretvalue"}) + "\n",
            encoding="utf-8",
        )
        hosts, _ = parse_crawler_output(crawl, source="katana")
        host = hosts[0]
        assert host.urls[0].endpoint_type == "api"
        assert "id" in host.urls[0].parameters
        assert host.findings[0].template_id == "katana-secret-in-url"


class TestHostRegistry:
    def test_merge_and_provenance(self) -> None:
        registry = HostRegistry("test", Path("."))
        h1 = Host(domain="api.example.com")
        h1.add_provenance(
            record_observation(
                tool="subfinder",
                field="hostname",
                value="api.example.com",
                confidence=80,
            )
        )
        h2 = Host(domain="api.example.com")
        h2.dns_resolved = True
        h2.add_provenance(
            record_observation(
                tool="dnsx",
                field="dns_resolved",
                value="true",
                confidence=90,
            )
        )
        registry.merge(h1)
        registry.merge(h2)
        host = registry.get("api.example.com")
        assert host is not None
        assert host.dns_resolved
        assert len(host.provenance) == 2

    def test_cross_source_correlation_dedupes_hosts(self, tmp_path: Path) -> None:
        (tmp_path / "subfinder.txt").write_text(
            "API.example.com.\nwww.example.com\n", encoding="utf-8"
        )
        (tmp_path / "assetfinder.txt").write_text(
            "api.example.com\ncdn.example.com\n", encoding="utf-8"
        )
        (tmp_path / "amass.txt").write_text("api.example.com\nshop.example.com\n", encoding="utf-8")
        registry = HostRegistry("test", tmp_path)
        registry.ingest_all(["subfinder", "assetfinder", "amass"])

        assert len(registry) == 4
        host = registry.get("api.example.com")
        assert host is not None
        assert set(host.discovery_sources) == {"subfinder", "assetfinder", "amass"}
        assert registry.correlated_hosts["api.example.com"] == [
            "amass",
            "assetfinder",
            "subfinder",
        ]

    def test_host_merge_idempotent_ports(self) -> None:
        from core.assets import Port

        h = Host(domain="x.example.com")
        h.ports.append(Port(host="x.example.com", port=443))
        h2 = Host(domain="x.example.com")
        h2.ports.append(Port(host="x.example.com", port=443))
        h.merge_from(h2)
        assert len(h.ports) == 1

    def test_intelligence_scores_security_relevance(self) -> None:
        host = Host(domain="admin-api.example.com", ips=["104.16.1.1"], dns_resolved=True)
        host.http_services.append(
            HttpService(
                url="https://admin-api.example.com",
                host="admin-api.example.com",
                title="Admin GraphQL",
                security_headers={},
                tls_version="tls1.0",
            )
        )
        host.urls.append(
            URL(
                url="https://admin-api.example.com/graphql?token=abc123456",
                host="admin-api.example.com",
                source="katana",
                endpoint_type="graphql",
                secrets=["token=abc123456"],
            )
        )
        result = IntelligenceEngine().process({host.domain: host})
        enriched = result.hosts[host.domain]
        assert enriched.cloud_provider == "Cloudflare"
        assert enriched.risk_score >= 40


class TestTarpitDetection:
    """A canary probe proved www.metaversejustice.com (DreamHost shared
    hosting) fabricates 'open' TCP handshakes for arbitrary, unassigned
    ports — 6, 9999, 23456, and 54321 (none of which can run a real
    service) all came back 'open' against nmap -sV. Once a host is flagged
    tarpit_suspected, its port data must never inflate confidence or risk,
    even though the raw naabu/nmap observations themselves are preserved.
    """

    def test_score_port_heavily_discounts_verified_open_when_tarpit_suspected(self) -> None:
        host = Host(domain="www.metaversejustice.com", tarpit_suspected=True)
        port = Port(
            host=host.domain,
            port=3389,
            verification_state="verified_open",
            validated=True,
        )
        confidence, score = score_port(port, host)
        assert score < 50
        assert confidence.value in {"unknown", "low"}

    def test_score_port_behaves_normally_when_not_tarpit_suspected(self) -> None:
        host = Host(domain="example.com", tarpit_suspected=False)
        port = Port(
            host=host.domain,
            port=443,
            verification_state="verified_open",
            validated=True,
        )
        confidence, score = score_port(port, host)
        assert score == 100
        assert confidence.value == "high"

    def test_score_host_excludes_port_signal_when_tarpit_suspected(self) -> None:
        host = Host(domain="www.metaversejustice.com", tarpit_suspected=True)
        # Sensitive ports that would normally add a large risk delta.
        for port_number in (3389, 5432, 6379, 9200, 27017):
            host.ports.append(Port(host=host.domain, port=port_number))
        score_host(host)
        assert host.risk_score == 0
        assert any("tarpit" in reason.lower() for reason in host.risk_reasons)

    def test_score_host_still_scores_ports_when_not_tarpit_suspected(self) -> None:
        host = Host(domain="example.com", tarpit_suspected=False)
        host.ports.append(Port(host=host.domain, port=3389))
        score_host(host)
        assert host.risk_score > 0
        assert any("3389" in reason for reason in host.risk_reasons)

    def test_host_merge_from_propagates_tarpit_suspected_flag(self) -> None:
        host = Host(domain="www.metaversejustice.com")
        canary = Host(
            domain="www.metaversejustice.com",
            tarpit_suspected=True,
            tarpit_canary_ports=[6, 9999, 23456, 54321],
        )
        host.merge_from(canary)
        assert host.tarpit_suspected is True
        assert host.tarpit_canary_ports == [6, 9999, 23456, 54321]
