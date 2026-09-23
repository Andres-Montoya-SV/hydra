"""`core/parsers/registry.py::SubTakeoverParser` — confirms confirmed
subdomain-takeover findings land in the EXISTING `core.assets.Host`/
`Finding` model, the same shape every other Finding-producing parser
already uses, never a new parallel data shape."""

from __future__ import annotations

from pathlib import Path

from core.parsers.registry import PARSER_REGISTRY, SubTakeoverParser
from utils.files import write_jsonl


class TestSubTakeoverParser:
    def test_a_confirmed_finding_lands_on_the_right_host(self, tmp_path: Path) -> None:
        write_jsonl(
            tmp_path / "sub_takeover.jsonl",
            [
                {
                    "host": "assets.example.com",
                    "cname": "assets.example.com.s3.amazonaws.com",
                    "service": "AWS/S3",
                    "template_id": "subdomain-takeover",
                    "severity": "high",
                    "name": "Possible subdomain takeover via AWS/S3",
                    "description": "assets.example.com has a CNAME to ...",
                    "confidence_score": 95,
                    "url": "https://assets.example.com",
                    "confirmed_stage2": True,
                    "stage2_method": "http_fingerprint",
                }
            ],
        )

        hosts, warnings = SubTakeoverParser().parse(tmp_path)

        assert warnings == []
        assert len(hosts) == 1
        host = hosts[0]
        assert host.domain == "assets.example.com"
        assert len(host.findings) == 1
        finding = host.findings[0]
        assert finding.template_id == "subdomain-takeover"
        assert finding.severity == "high"
        assert finding.source == "sub_takeover"
        assert finding.confidence_score == 95
        assert finding.url == "https://assets.example.com"

    def test_nxdomain_confirmed_finding_has_no_url(self, tmp_path: Path) -> None:
        write_jsonl(
            tmp_path / "sub_takeover.jsonl",
            [
                {
                    "host": "old.example.com",
                    "cname": "old-app.azurewebsites.net",
                    "service": "Microsoft Azure",
                    "template_id": "subdomain-takeover",
                    "severity": "high",
                    "name": "Possible subdomain takeover via Microsoft Azure",
                    "description": "...",
                    "confidence_score": 95,
                    "url": None,
                    "confirmed_stage2": True,
                    "stage2_method": "dns_nxdomain_confirmed",
                }
            ],
        )

        hosts, _warnings = SubTakeoverParser().parse(tmp_path)
        assert hosts[0].findings[0].url is None

    def test_missing_artifact_produces_no_hosts(self, tmp_path: Path) -> None:
        hosts, warnings = SubTakeoverParser().parse(tmp_path)
        assert hosts == []
        assert warnings == []

    def test_registered_under_its_own_tool_name(self) -> None:
        assert PARSER_REGISTRY["sub_takeover"].__class__ is SubTakeoverParser
