"""ui/tables.py::verification_summary_line / build_verification_panel —
the CLI-visible verification summary (design Part 3, item 4). Must render
identically whether counts come from a real AssetStore-backed run (Rich
panel) or the plain --no-ui text path (app.py::cmd_run), and must show
zero noise for a clean run with no flags at all.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.assets import ScanRun
from core.models import PipelineContext
from core.store import AssetStore
from core.verification.model import ContradictionSeverity, VerificationFinding
from ui.tables import build_verification_panel, verification_summary_line


class TestVerificationSummaryLine:
    def test_matches_the_documented_example(self) -> None:
        line = verification_summary_line(
            {"confirmed": 2, "pending": 0, "invalidated": 1, "total": 3}
        )
        assert (
            line
            == "Verification: 2 confirmed, 0 pending, 1 finding invalidated and excluded from report"
        )

    def test_pluralizes_multiple_invalidated_findings(self) -> None:
        line = verification_summary_line(
            {"confirmed": 0, "pending": 0, "invalidated": 2, "total": 2}
        )
        assert "2 findings invalidated" in line

    def test_zero_findings_reads_cleanly(self) -> None:
        line = verification_summary_line(
            {"confirmed": 0, "pending": 0, "invalidated": 0, "total": 0}
        )
        assert (
            line
            == "Verification: 0 confirmed, 0 pending, 0 findings invalidated and excluded from report"
        )


def _seed_store(tmp_path: Path, run_id: str, findings: list[VerificationFinding]) -> AssetStore:
    store = AssetStore(tmp_path / "recon.db")
    store.create_run(ScanRun(run_id=run_id, started_at="2026-01-01T00:00:00Z", targets=[]))
    if findings:
        store.record_verification_findings(run_id, findings)
    return store


class TestBuildVerificationPanel:
    def test_no_store_shows_not_available(self) -> None:
        context = PipelineContext(output_dir=Path("."), started_at=datetime.utcnow())
        context.run_id = "run1"
        table = build_verification_panel(context, None)
        rendered = _render(table)
        assert "not available" in rendered

    def test_no_run_id_shows_not_available(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        context = PipelineContext(output_dir=Path("."), started_at=datetime.utcnow())
        table = build_verification_panel(context, store)
        rendered = _render(table)
        assert "not available" in rendered

    def test_clean_run_shows_zero_counts_no_findings_listed(self, tmp_path: Path) -> None:
        store = _seed_store(tmp_path, "run1", [])
        context = PipelineContext(output_dir=Path("."), started_at=datetime.utcnow())
        context.run_id = "run1"
        table = build_verification_panel(context, store)
        rendered = _render(table)
        assert "0 confirmed, 0 pending, 0 findings invalidated" in rendered

    def test_invalidated_finding_is_listed_with_host_and_claim(self, tmp_path: Path) -> None:
        finding = VerificationFinding(
            claim="mta1.stripchat.com: resolved",
            evidence="NODATA record wrongly counted resolved",
            raw_artifact="dnsx_records.jsonl",
            severity=ContradictionSeverity.INVALIDATES,
            detector="detect_dnsx_nodata_as_resolved",
            host="mta1.stripchat.com",
        )
        store = _seed_store(tmp_path, "run1", [finding])
        context = PipelineContext(output_dir=Path("."), started_at=datetime.utcnow())
        context.run_id = "run1"
        table = build_verification_panel(context, store)
        rendered = _render(table)
        assert "1 finding invalidated and excluded from report" in rendered
        assert "mta1.stripchat.com" in rendered
        assert "resolved" in rendered

    def test_downgraded_only_finding_is_not_listed_individually(self, tmp_path: Path) -> None:
        """Only INVALIDATES findings get their own listed row — a
        DOWNGRADES_CONFIDENCE finding is already visible in the report
        itself (reduced confidence + note), not repeated here."""
        finding = VerificationFinding(
            claim="api.stripchat.com:37 open (naabu)",
            evidence="nmap reports filtered for the same port",
            raw_artifact="port_verify.jsonl",
            severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
            detector="detect_naabu_nmap_port_disagreement",
            host="api.stripchat.com",
        )
        store = _seed_store(tmp_path, "run1", [finding])
        context = PipelineContext(output_dir=Path("."), started_at=datetime.utcnow())
        context.run_id = "run1"
        table = build_verification_panel(context, store)
        rendered = _render(table)
        assert "1 confirmed, 0 pending, 0 findings invalidated" in rendered
        assert "api.stripchat.com" not in rendered


def _render(renderable: object) -> str:
    from rich.console import Console

    console = Console(width=200, record=True, force_terminal=False)
    console.print(renderable)
    return console.export_text()
