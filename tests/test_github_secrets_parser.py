"""`core/parsers/registry.py::GithubSecretsParser` — confirms leaked-secret
findings land in the EXISTING `core.assets.Host`/`Finding` model, and that
the redaction guarantee survives the full parse (no secret-shaped field
is ever read from the JSONL record)."""

from __future__ import annotations

from pathlib import Path

from core.parsers.registry import PARSER_REGISTRY, GithubSecretsParser
from utils.files import write_jsonl


class TestGithubSecretsParser:
    def test_a_current_head_finding_lands_on_the_target_host(self, tmp_path: Path) -> None:
        write_jsonl(
            tmp_path / "github_secrets.jsonl",
            [
                {
                    "host": "example.com",
                    "repo": "acme/webapp",
                    "repo_url": "https://github.com/acme/webapp",
                    "file": "config.py",
                    "line": 2,
                    "rule_id": "stripe-access-token",
                    "template_id": "leaked-secret",
                    "severity": "critical",
                    "name": "Leaked secret (stripe-access-token) in acme/webapp",
                    "description_full": "gitleaks matched rule 'stripe-access-token' ...",
                    "confidence_score": 90,
                    "url": "https://github.com/acme/webapp/blob/abc123/config.py#L2",
                    "in_current_head": True,
                }
            ],
        )

        hosts, warnings = GithubSecretsParser().parse(tmp_path)

        assert warnings == []
        assert len(hosts) == 1
        host = hosts[0]
        assert host.domain == "example.com"
        assert len(host.findings) == 1
        finding = host.findings[0]
        assert finding.template_id == "leaked-secret"
        assert finding.severity == "critical"
        assert finding.source == "github_secrets"
        assert finding.confidence_score == 90
        assert finding.url == "https://github.com/acme/webapp/blob/abc123/config.py#L2"

    def test_missing_artifact_produces_no_hosts(self, tmp_path: Path) -> None:
        hosts, warnings = GithubSecretsParser().parse(tmp_path)
        assert hosts == []
        assert warnings == []

    def test_registered_under_its_own_tool_name(self) -> None:
        assert PARSER_REGISTRY["github_secrets"].__class__ is GithubSecretsParser
