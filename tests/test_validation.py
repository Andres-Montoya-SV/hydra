"""Tests for validation and confidence."""

from __future__ import annotations

from core.assets import Host, Port
from core.confidence import score_subdomain, update_host_confidence
from core.validation.engine import detect_cdn_waf, validate_dns_resolution, validate_naabu_ports


class TestValidation:
    def test_naabu_suspicious_count(self) -> None:
        ports = [Port(host=f"h{i % 3}.example.com", port=i) for i in range(600)]
        warnings = validate_naabu_ports(Host(domain="x"), ports)
        assert any("600" in w for w in warnings)

    def test_dns_resolution_ratio(self) -> None:
        warnings, ratio = validate_dns_resolution(["a.com", "b.com", "c.com", "d.com"], ["a.com"])
        assert ratio == 0.25
        assert warnings

    def test_detect_cloudflare(self) -> None:
        cdn, waf = detect_cdn_waf({"server": "cloudflare", "cf-ray": "abc"}, "cloudflare")
        assert cdn == "cloudflare"


class TestConfidence:
    def test_unresolved_subdomain_low(self) -> None:
        host = Host(domain="sub.example.com")
        host.add_source("subfinder")
        conf, _ = score_subdomain(host)
        assert conf == __import__("core.assets", fromlist=["Confidence"]).Confidence.LOW

    def test_resolved_and_http_high(self) -> None:
        from core.assets import Confidence, HttpService

        host = Host(domain="api.example.com", dns_resolved=True)
        host.http_services.append(
            HttpService(url="https://api.example.com", host="api.example.com", status_code=200)
        )
        update_host_confidence(host)
        assert host.confidence == Confidence.HIGH
