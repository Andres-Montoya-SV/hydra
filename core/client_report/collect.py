"""Gathers everything the client report needs from a run's already-
persisted artifacts (docs/CLIENT_REPORT.md: 'generado directamente desde
los datos ya persistidos de una corrida'). Reads per-tool JSONL artifacts
through the SAME `core.parsers.registry` parser classes the main pipeline
uses — not the SQLite `findings` table, which an unrelated existing
cross-tool merge step can de-duplicate more aggressively than intended
for entries that share a template_id on one host (verified against a real
run: `security_headers.jsonl` has 10 rows for 5 missing headers × 2 URL
variants, but only 2 of those 10 survive into `findings` — parsing the
tool's own artifact directly recovers the full, correct set this report
needs to consolidate honestly).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.assets import Finding
from core.intel.cli import default_db
from core.parsers.registry import PARSER_REGISTRY

if TYPE_CHECKING:
    from config.settings import Settings
    from core.store import AssetStore

# Tools whose parsed output can contain client-facing findings. Excludes
# collection-only tools (subfinder, dnsx, httpx, ...) that never produce a
# Finding, and excludes nothing else — scan-quality-only template_ids
# (tarpit/wildcard/soft-404) are filtered later, by template_id, in
# core.client_report.dedup, not by omitting their tool here (their host-
# level `warnings`/`soft_404_detected` flags still feed the "known
# limitations" section from summary.json).
_FINDING_TOOL_NAMES = (
    "vuln_match",
    "security_headers",
    "param_fuzz",
    "cloud_bucket_enum",
    "browser_probe",
    "nuclei",
    "threat_intel",
)


@dataclass
class RunReportData:
    """Everything collect() gathered for one run, before consolidation."""

    run_id: str
    targets: list[str]
    started_at: str | None
    finished_at: str | None
    duration_seconds: float | None
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    vuln_check_failed: list[dict[str, Any]] = field(default_factory=list)
    wildcard_dns_detected: bool = False
    wildcard_dns_roots: list[str] = field(default_factory=list)
    soft_404_hosts: list[str] = field(default_factory=list)
    param_fuzz_baseline_invalid_hosts: list[dict[str, Any]] = field(default_factory=list)


class RunNotFoundError(Exception):
    """Raised when the run's output directory or database cannot be found."""


def collect(settings: Settings, store: AssetStore, run_id: str) -> RunReportData:
    db_path = default_db(settings.project_root, settings.output_directory)
    run_dir = db_path.parent / run_id
    if not run_dir.is_dir():
        raise RunNotFoundError(f"Run directory not found: {run_dir}")

    run_row = store.get_run(run_id)
    targets = run_row["targets"] if run_row else []
    started_at = run_row["started_at"] if run_row else None
    finished_at = run_row["finished_at"] if run_row else None

    summary = _read_json(run_dir / "summary.json")
    metadata = _read_json(run_dir / "metadata.json")

    findings: list[Finding] = []
    for tool_name in _FINDING_TOOL_NAMES:
        parser = PARSER_REGISTRY.get(tool_name)
        if parser is None:
            continue
        hosts, _errors = parser.parse(run_dir)
        for host in hosts:
            findings.extend(host.findings)

    return RunReportData(
        run_id=run_id,
        targets=[str(t) for t in targets],
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=_as_float(summary.get("duration_seconds")),
        findings=findings,
        warnings=[str(w) for w in (summary.get("warnings") or [])],
        vuln_check_failed=list(metadata.get("vuln_match_check_failed") or []),
        wildcard_dns_detected=bool(summary.get("wildcard_dns_detected")),
        wildcard_dns_roots=[str(r) for r in (summary.get("wildcard_dns_roots") or [])],
        soft_404_hosts=[
            str(item.get("domain"))
            for item in (summary.get("soft_404_detected_hosts") or [])
            if isinstance(item, dict) and item.get("domain")
        ],
        param_fuzz_baseline_invalid_hosts=list(
            summary.get("param_fuzz_baseline_invalid_hosts") or []
        ),
    )


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _as_float(value: object) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    return None
