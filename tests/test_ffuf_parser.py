"""`core/parsers/registry.py::FfufParser` — confirms hidden-endpoint
findings land in the EXISTING `core.assets.Host`/`Finding` model (unlike
modules/dnstwist.py's deliberately-separate typosquat table, an ffuf hit
is a real finding about the target's own infrastructure)."""

from __future__ import annotations

from pathlib import Path

from core.parsers.registry import PARSER_REGISTRY, FfufParser
from utils.files import write_jsonl


class TestFfufParser:
    def test_a_critical_finding_lands_on_the_right_host(self, tmp_path: Path) -> None:
        write_jsonl(
            tmp_path / "ffuf_findings.jsonl",
            [
                {
                    "host": "example.com",
                    "url": "https://example.com/.git/config",
                    "path": "/.git/config",
                    "status": 200,
                    "length": 92,
                    "words": 12,
                    "severity": "critical",
                    "confidence_score": 90,
                    "template_id": "hidden-endpoint-discovered",
                    "name": "Hidden endpoint discovered: /.git/config",
                    "description": "ffuf found an unlinked, brute-forced endpoint...",
                }
            ],
        )

        hosts, warnings = FfufParser().parse(tmp_path)

        assert warnings == []
        assert len(hosts) == 1
        host = hosts[0]
        assert host.domain == "example.com"
        assert len(host.findings) == 1
        finding = host.findings[0]
        assert finding.template_id == "hidden-endpoint-discovered"
        assert finding.severity == "critical"
        assert finding.source == "ffuf"
        assert finding.confidence_score == 90
        assert finding.url == "https://example.com/.git/config"

    def test_missing_artifact_produces_no_hosts(self, tmp_path: Path) -> None:
        hosts, warnings = FfufParser().parse(tmp_path)
        assert hosts == []
        assert warnings == []

    def test_registered_under_its_own_tool_name(self) -> None:
        assert PARSER_REGISTRY["ffuf"].__class__ is FfufParser
