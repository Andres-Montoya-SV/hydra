"""`modules/sslyze.py` — the TLS/certificate posture plugin.

`tests/fixtures/sslyze_real_output.json` is a real, trimmed capture (one
`server_scan_result`, shortened certificate chains) from an actual
`sslyze --certinfo --heartbleed --robot --http_headers --json_out=...
example.com` run during this task's own development — not a guessed
schema. The synthetic edge cases below (heartbleed/robot vulnerable, weak
protocol, untrusted/expired certificate) are clearly labeled as such:
`example.com` itself was not vulnerable to any of them, so exercising
those code paths needs deliberately modified values layered onto the
real, confirmed field shapes — never a different, invented shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.sslyze import SslyzePlugin, parse_sslyze_results

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _real_fixture() -> dict:
    with open(FIXTURES_DIR / "sslyze_real_output.json", encoding="utf-8") as f:
        return json.load(f)


def _server_result(host: str = "example.com", **scan_overrides: object) -> dict:
    """A minimal, schema-accurate server_scan_result — the same
    `{"status", "error_reason", "error_trace", "result"}` shape every
    real scan command uses (confirmed against the real fixture), built
    small for a single edge case rather than cloning the whole real
    capture per test."""
    scan_result = {
        "certificate_info": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "heartbleed": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "robot": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "http_headers": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "ssl_2_0_cipher_suites": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "ssl_3_0_cipher_suites": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "tls_1_0_cipher_suites": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
        "tls_1_1_cipher_suites": {"status": "NOT_SCHEDULED", "error_reason": None, "result": None},
    }
    scan_result.update(scan_overrides)
    return {
        "server_location": {"hostname": host, "port": 443},
        "scan_result": scan_result,
    }


class TestParseSslyzeResultsAgainstTheRealFixture:
    def test_the_real_example_com_capture_flags_missing_hsts(self) -> None:
        findings = parse_sslyze_results(_real_fixture())
        assert len(findings) == 1
        assert findings[0]["host"] == "example.com"
        assert findings[0]["template_id"] == "tls-missing-hsts"
        assert findings[0]["severity"] == "low"


class TestNeverTrustsAResultFromAScanThatDidNotComplete:
    """The real bug this module's own docstring documents: `http_headers`
    (and every other scan command) has `status: "NOT_SCHEDULED"` with
    `result: null` unless explicitly requested — a parser reading
    `result` without checking `status` first could misread that as
    "checked, nothing found." """

    def test_not_scheduled_http_headers_produces_no_finding_even_with_a_populated_result(
        self,
    ) -> None:
        data = {
            "server_scan_results": [
                _server_result(
                    http_headers={
                        "status": "NOT_SCHEDULED",
                        "error_reason": None,
                        # Deliberately populated to prove the parser
                        # checks status FIRST, not merely "is result
                        # present" — a real NOT_SCHEDULED result is
                        # always null in practice, this is an adversarial
                        # test of the gate itself.
                        "result": {"strict_transport_security_header": None},
                    }
                )
            ]
        }
        assert parse_sslyze_results(data) == []

    def test_error_status_on_heartbleed_is_never_treated_as_vulnerable(self) -> None:
        data = {
            "server_scan_results": [
                _server_result(
                    heartbleed={
                        "status": "ERROR",
                        "error_reason": "connection reset",
                        "result": None,
                    }
                )
            ]
        }
        assert parse_sslyze_results(data) == []


class TestVulnerabilityFindings:
    """Synthetic edge cases — example.com itself was not vulnerable to
    any of these, so real values are deliberately overridden onto the
    real, confirmed schema shape to exercise each code path."""

    def test_heartbleed_vulnerable(self) -> None:
        data = {
            "server_scan_results": [
                _server_result(
                    heartbleed={
                        "status": "COMPLETED",
                        "error_reason": None,
                        "result": {"is_vulnerable_to_heartbleed": True},
                    }
                )
            ]
        }
        findings = parse_sslyze_results(data)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "tls-heartbleed"
        assert findings[0]["severity"] == "critical"

    def test_robot_vulnerable(self) -> None:
        data = {
            "server_scan_results": [
                _server_result(
                    robot={
                        "status": "COMPLETED",
                        "error_reason": None,
                        "result": {"robot_result": "VULNERABLE_STRONG_ORACLE"},
                    }
                )
            ]
        }
        findings = parse_sslyze_results(data)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "tls-robot"
        assert findings[0]["severity"] == "high"

    def test_robot_inconsistent_result_is_neither_vulnerable_nor_safe(self) -> None:
        """UNKNOWN_INCONSISTENT_RESULTS is a real sslyze enum value
        (confirmed from the installed package) — never claimed vulnerable
        (it isn't confirmed), and never silently treated as clean either
        (no finding either way is the honest non-claim)."""
        data = {
            "server_scan_results": [
                _server_result(
                    robot={
                        "status": "COMPLETED",
                        "error_reason": None,
                        "result": {"robot_result": "UNKNOWN_INCONSISTENT_RESULTS"},
                    }
                )
            ]
        }
        assert parse_sslyze_results(data) == []

    def test_weak_protocol_supported(self) -> None:
        data = {
            "server_scan_results": [
                _server_result(
                    tls_1_0_cipher_suites={
                        "status": "COMPLETED",
                        "error_reason": None,
                        "result": {"is_tls_version_supported": True, "tls_version_used": "TLS_1_0"},
                    }
                )
            ]
        }
        findings = parse_sslyze_results(data)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "tls-weak-protocol"

    def test_weak_protocol_not_supported_is_not_flagged(self) -> None:
        data = {
            "server_scan_results": [
                _server_result(
                    tls_1_0_cipher_suites={
                        "status": "COMPLETED",
                        "error_reason": None,
                        "result": {"is_tls_version_supported": False},
                    }
                )
            ]
        }
        assert parse_sslyze_results(data) == []


class TestScopeEnforcement:
    """Proves this active plugin re-authorizes every host before handing
    it to the real `sslyze` subprocess — the same class of test every
    other active plugin already has, not skipped because it "obviously"
    works the same way."""

    def _context(self, tmp_path: Path) -> PipelineContext:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        # `_alive_urls()` (modules/_base.py) reads this file from disk —
        # not an in-memory `context.alive_urls` list — and re-checks
        # scope authorization itself before returning anything
        # ("discovery is not authorization", that helper's own
        # docstring). Both the mixed-scope URLs go in the same file the
        # real pipeline would have written.
        (output_dir / "alive.txt").write_text(
            "https://example.com\nhttps://evil-out-of-scope.example\n", encoding="utf-8"
        )
        return PipelineContext(
            targets=[DomainTarget(domain="example.com")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["example.com"]),
        )

    @pytest.mark.asyncio
    async def test_an_out_of_scope_host_never_reaches_the_real_tool_invocation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(project_root=tmp_path, enable_sslyze=True)
        context = self._context(tmp_path)
        plugin = SslyzePlugin(settings)

        captured_args: list[str] = []

        async def fake_run_tool(self_, ctx, args, *, timeout=None):  # noqa: ANN001
            captured_args.extend(args)
            (tmp_path / "run" / "sslyze.json").write_text(
                json.dumps({"server_scan_results": []}), encoding="utf-8"
            )
            return 0, "", ""

        import modules.sslyze as sslyze_module

        monkeypatch.setattr(sslyze_module.SslyzePlugin, "_run_tool", fake_run_tool)
        await plugin.run(context, tmp_path / "unused")

        joined = " ".join(captured_args)
        assert "example.com" in joined
        assert "evil-out-of-scope.example" not in joined
