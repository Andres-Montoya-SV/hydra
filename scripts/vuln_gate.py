"""Productization Phase 11d: the container image vulnerability gate.

CI scans the built image (Syft builds the SBOM, Grype matches it) and runs:

    python scripts/vuln_gate.py <grype.json> [--allowlist security/vulnerability-allowlist.json]

The gate fails (exit 1) when a **Critical or High** finding **has a fix**
and is not covered by a reviewed allowlist entry. It also fails when an
entry has passed its expiry date.

Allowlist entries match one finding exactly, by vulnerability id, package
and location. Each carries a reason and an `expires` date (YYYY-MM-DD):
an exception is a dated decision, not a permanent silence. Entries that no
longer match anything are reported, without failing, so they can be
removed once the fix ships.

Findings without a fix, and Medium or lower, are counted in the report
but don't fail the build.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

GATED_SEVERITIES = frozenset({"Critical", "High"})
DEFAULT_ALLOWLIST = Path("security/vulnerability-allowlist.json")


@dataclass(frozen=True)
class Finding:
    vulnerability: str
    severity: str
    package: str
    version: str
    location: str
    fixed_in: tuple[str, ...]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.vulnerability, self.package, self.location)


@dataclass(frozen=True)
class AllowedException:
    vulnerability: str
    package: str
    location: str
    reason: str
    expires: date

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.vulnerability, self.package, self.location)


@dataclass(frozen=True)
class Verdict:
    blocking: tuple[Finding, ...]
    expired: tuple[AllowedException, ...]
    allowed: tuple[Finding, ...]
    stale: tuple[AllowedException, ...]
    counts: dict[str, int]

    @property
    def passed(self) -> bool:
        return not self.blocking and not self.expired


def _location(match: dict[str, Any]) -> str:
    locations = match["artifact"].get("locations") or [{}]
    return str(locations[0].get("path", ""))


def parse_findings(report: dict[str, Any]) -> list[Finding]:
    findings = []
    for match in report.get("matches", []):
        vulnerability = match["vulnerability"]
        fix = vulnerability.get("fix") or {}
        findings.append(
            Finding(
                vulnerability=vulnerability["id"],
                severity=vulnerability.get("severity", "Unknown"),
                package=match["artifact"]["name"],
                version=match["artifact"].get("version", ""),
                location=_location(match),
                fixed_in=tuple(fix.get("versions") or ()) if fix.get("state") == "fixed" else (),
            )
        )
    return findings


def parse_allowlist(raw: dict[str, Any]) -> list[AllowedException]:
    entries = []
    for entry in raw.get("exceptions", []):
        if not entry.get("reason", "").strip():
            raise ValueError(f"allowlist entry without a reason: {entry}")
        entries.append(
            AllowedException(
                vulnerability=entry["vulnerability"],
                package=entry["package"],
                location=entry["location"],
                reason=entry["reason"],
                expires=date.fromisoformat(entry["expires"]),
            )
        )
    return entries


def evaluate(findings: list[Finding], exceptions: list[AllowedException], today: date) -> Verdict:
    gated = [f for f in findings if f.severity in GATED_SEVERITIES and f.fixed_in]
    by_key = {e.key: e for e in exceptions}
    blocking, allowed, expired = [], [], {}
    for finding in gated:
        exception = by_key.get(finding.key)
        if exception is None:
            blocking.append(finding)
        elif exception.expires < today:
            expired[exception.key] = exception
        else:
            allowed.append(finding)
    matched = {f.key for f in gated}
    counts: dict[str, int] = {}
    for finding in findings:
        label = f"{finding.severity}{'' if finding.fixed_in else ' (no fix)'}"
        counts[label] = counts.get(label, 0) + 1
    return Verdict(
        blocking=tuple(blocking),
        expired=tuple(expired.values()),
        allowed=tuple(allowed),
        stale=tuple(e for e in exceptions if e.key not in matched),
        counts=counts,
    )


def render(verdict: Verdict) -> str:
    lines = ["Findings: " + ", ".join(f"{k} {v}" for k, v in sorted(verdict.counts.items()))]
    lines.append(f"Allowed by a current exception: {len(verdict.allowed)}")
    for f in verdict.blocking:
        lines.append(
            f"BLOCKING {f.severity} {f.vulnerability} {f.package} {f.version} at {f.location} "
            f"(fixed in {', '.join(f.fixed_in)})"
        )
    for e in verdict.expired:
        lines.append(
            f"EXPIRED exception {e.vulnerability} {e.package} at {e.location} ({e.expires})"
        )
    for e in verdict.stale:
        lines.append(f"stale exception (no longer found, remove it): {e.vulnerability} {e.package}")
    lines.append("PASS" if verdict.passed else "FAIL")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="grype -o json output")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    args = parser.parse_args(argv)
    findings = parse_findings(json.loads(args.report.read_text(encoding="utf-8")))
    exceptions = parse_allowlist(json.loads(args.allowlist.read_text(encoding="utf-8")))
    verdict = evaluate(findings, exceptions, date.today())
    print(render(verdict))
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
