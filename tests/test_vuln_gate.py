"""Productization Phase 11d: the image vulnerability gate (scripts/vuln_gate.py)."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("vuln_gate", _ROOT / "scripts" / "vuln_gate.py")
if _spec is None or _spec.loader is None:
    raise ImportError("scripts/vuln_gate.py not found")
vuln_gate = importlib.util.module_from_spec(_spec)
sys.modules["vuln_gate"] = vuln_gate
_spec.loader.exec_module(vuln_gate)

TODAY = date(2026, 10, 1)


def _match(
    vuln: str, severity: str, package: str, path: str, fixed: list[str] | None
) -> dict[str, Any]:
    return {
        "vulnerability": {
            "id": vuln,
            "severity": severity,
            "fix": {"state": "fixed", "versions": fixed} if fixed else {"state": "not-fixed"},
        },
        "artifact": {"name": package, "version": "1.0", "locations": [{"path": path}]},
    }


def _exception(vuln: str, package: str, path: str, expires: str = "2026-11-15") -> dict[str, str]:
    return {
        "vulnerability": vuln,
        "package": package,
        "location": path,
        "reason": "upstream tool release pending",
        "expires": expires,
    }


def _verdict(matches: list[dict[str, Any]], exceptions: list[dict[str, str]]) -> Any:
    return vuln_gate.evaluate(
        vuln_gate.parse_findings({"matches": matches}),
        vuln_gate.parse_allowlist({"exceptions": exceptions}),
        TODAY,
    )


class TestGate:
    def test_a_fixable_critical_or_high_blocks(self) -> None:
        verdict = _verdict(
            [
                _match("CVE-1", "Critical", "openssl", "/usr/lib/x", ["3.5.8"]),
                _match("CVE-2", "High", "x/net", "/usr/local/bin/naabu", ["0.56.0"]),
            ],
            [],
        )
        assert not verdict.passed and len(verdict.blocking) == 2

    def test_unfixed_and_lower_severities_never_block(self) -> None:
        verdict = _verdict(
            [
                _match("CVE-3", "Critical", "glibc", "/lib", None),
                _match("CVE-4", "Medium", "x/text", "/usr/local/bin/dnsx", ["0.39.0"]),
            ],
            [],
        )
        assert verdict.passed and verdict.counts == {"Critical (no fix)": 1, "Medium": 1}

    def test_an_exception_covers_exactly_one_finding(self) -> None:
        verdict = _verdict(
            [
                _match("CVE-2", "High", "x/net", "/usr/local/bin/naabu", ["0.56.0"]),
                _match("CVE-2", "High", "x/net", "/usr/local/bin/katana", ["0.56.0"]),
            ],
            [_exception("CVE-2", "x/net", "/usr/local/bin/naabu")],
        )
        assert [f.location for f in verdict.blocking] == ["/usr/local/bin/katana"]
        assert len(verdict.allowed) == 1

    def test_an_expired_exception_blocks_again(self) -> None:
        verdict = _verdict(
            [_match("CVE-2", "High", "x/net", "/usr/local/bin/naabu", ["0.56.0"])],
            [_exception("CVE-2", "x/net", "/usr/local/bin/naabu", expires="2026-09-30")],
        )
        assert not verdict.passed and len(verdict.expired) == 1

    def test_a_stale_exception_is_reported_not_fatal(self) -> None:
        verdict = _verdict([], [_exception("CVE-9", "x/net", "/usr/local/bin/naabu")])
        assert verdict.passed and len(verdict.stale) == 1
        assert "stale exception" in vuln_gate.render(verdict)

    def test_an_exception_needs_a_reason(self) -> None:
        entry = _exception("CVE-2", "x/net", "/bin")
        entry["reason"] = " "
        with pytest.raises(ValueError, match="reason"):
            vuln_gate.parse_allowlist({"exceptions": [entry]})


class TestCli:
    def test_exit_codes(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        report = tmp_path / "grype.json"
        allowlist = tmp_path / "allow.json"
        report.write_text(
            json.dumps({"matches": [_match("CVE-1", "High", "pcre2", "/lib", ["10.46"])]})
        )
        allowlist.write_text(json.dumps({"exceptions": []}))
        assert vuln_gate.main([str(report), "--allowlist", str(allowlist)]) == 1
        allowlist.write_text(
            json.dumps({"exceptions": [_exception("CVE-1", "pcre2", "/lib", "2999-01-01")]})
        )
        assert vuln_gate.main([str(report), "--allowlist", str(allowlist)]) == 0
        assert "BLOCKING High CVE-1 pcre2" in capsys.readouterr().out


class TestTheRepositoryAllowlist:
    def test_every_entry_is_reasoned_and_dated(self) -> None:
        raw = json.loads((_ROOT / "security" / "vulnerability-allowlist.json").read_text())
        exceptions = vuln_gate.parse_allowlist(raw)
        assert exceptions, "the allowlist exists and is non-empty while the tool refresh is pending"
        assert len({e.key for e in exceptions}) == len(exceptions)  # no duplicates
