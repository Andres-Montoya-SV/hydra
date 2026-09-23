"""`core/parsers/registry.py`'s three new parsers
(`TheHarvesterParser`/`SslyzeParser`/`Wafw00fParser`) — confirms each
plugin's own findings JSONL lands in the EXISTING `core.assets.Host`/
`Finding` model correctly, the same way `SecurityHeadersParser` already
does for `modules/security_headers.py` (`tests/test_hydra_intel.py`),
never a new parallel data shape.
"""

from __future__ import annotations

from pathlib import Path

from core.parsers.registry import PARSER_REGISTRY, SslyzeParser, TheHarvesterParser, Wafw00fParser
from utils.files import write_jsonl


class TestTheHarvesterParser:
    def test_email_and_person_records_become_findings_on_the_right_host(
        self, tmp_path: Path
    ) -> None:
        write_jsonl(
            tmp_path / "theharvester_findings.jsonl",
            [
                {
                    "host": "example.com",
                    "type": "email",
                    "value": "julia@example.com",
                    "sources": ["duckduckgo"],
                    "template_id": "email-exposure",
                    "severity": "info",
                },
                {
                    "host": "example.com",
                    "type": "person",
                    "value": "Julia Smith",
                    "sources": ["yahoo"],
                    "template_id": "personnel-exposure",
                    "severity": "info",
                },
            ],
        )

        hosts, warnings = TheHarvesterParser().parse(tmp_path)

        assert warnings == []
        assert len(hosts) == 1
        host = hosts[0]
        assert host.domain == "example.com"
        assert len(host.findings) == 2
        assert {f.template_id for f in host.findings} == {"email-exposure", "personnel-exposure"}
        assert all(f.source == "theharvester" for f in host.findings)
        email_finding = next(f for f in host.findings if f.template_id == "email-exposure")
        assert "julia@example.com" in email_finding.name

    def test_missing_artifact_produces_no_hosts(self, tmp_path: Path) -> None:
        hosts, warnings = TheHarvesterParser().parse(tmp_path)
        assert hosts == []
        assert warnings == []


class TestSslyzeParser:
    def test_tls_findings_land_on_the_correct_host_with_the_real_template_ids(
        self, tmp_path: Path
    ) -> None:
        write_jsonl(
            tmp_path / "sslyze_findings.jsonl",
            [
                {
                    "host": "example.com",
                    "template_id": "tls-missing-hsts",
                    "severity": "low",
                    "name": "No Strict-Transport-Security header",
                    "description": "No Strict-Transport-Security header",
                },
                {
                    "host": "example.com",
                    "template_id": "tls-heartbleed",
                    "severity": "critical",
                    "name": "Vulnerable to Heartbleed (CVE-2014-0160)",
                    "description": "Vulnerable to Heartbleed (CVE-2014-0160)",
                },
            ],
        )

        hosts, warnings = SslyzeParser().parse(tmp_path)

        assert warnings == []
        assert len(hosts) == 1
        host = hosts[0]
        assert {f.template_id for f in host.findings} == {"tls-missing-hsts", "tls-heartbleed"}
        heartbleed = next(f for f in host.findings if f.template_id == "tls-heartbleed")
        assert heartbleed.severity == "critical"
        assert heartbleed.source == "sslyze"


class TestWafw00fParser:
    def test_a_detection_sets_the_existing_host_level_waf_fields(self, tmp_path: Path) -> None:
        """Confirms this parser feeds `Host.is_waf`/`.waf_provider` — the
        SAME fields `core.validation.engine.detect_cdn_waf`'s passive
        heuristic already populates via `HttpxParser` — never a new,
        parallel data shape."""
        write_jsonl(
            tmp_path / "wafw00f_findings.jsonl",
            [
                {
                    "url": "https://example.com",
                    "firewall": "Cloudflare",
                    "manufacturer": "Cloudflare Inc.",
                }
            ],
        )

        hosts, warnings = Wafw00fParser().parse(tmp_path)

        assert warnings == []
        assert len(hosts) == 1
        host = hosts[0]
        assert host.domain == "example.com"
        assert host.is_waf is True
        assert host.waf_provider == "Cloudflare"
        # Metadata, never a standalone Finding for a plain WAF detection.
        assert host.findings == []

    def test_missing_artifact_produces_no_hosts(self, tmp_path: Path) -> None:
        hosts, warnings = Wafw00fParser().parse(tmp_path)
        assert hosts == []
        assert warnings == []


class TestAllThreeAreRegistered:
    def test_registered_under_their_own_tool_names(self) -> None:
        assert PARSER_REGISTRY["theharvester"].__class__ is TheHarvesterParser
        assert PARSER_REGISTRY["sslyze"].__class__ is SslyzeParser
        assert PARSER_REGISTRY["wafw00f"].__class__ is Wafw00fParser
