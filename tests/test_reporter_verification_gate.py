"""core/reporter.py's B.3 report-grounding gate (design Part 3): a
High-Priority Infrastructure host or Intelligence Relationship this run's
own verification_flags proved INVALIDATES must be excluded from the normal
report and moved to a new "Contradicted / Unverifiable Findings" section;
a DOWNGRADES_CONFIDENCE one stays in place with a reduced confidence_score
and a visible note. A clean run (no flags at all) must render identically
to before this gate existed — zero new noise.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from config.settings import Settings
from core.assets import Host, RiskLevel, ScanRun
from core.models import PipelineContext
from core.reporter import ReportGenerator
from core.store import AssetStore
from core.verification.model import ContradictionSeverity, VerificationFinding


def _make_context(tmp_path: Path, run_id: str = "run1") -> PipelineContext:
    output_dir = tmp_path / "output" / run_id
    output_dir.mkdir(parents=True)
    context = PipelineContext(output_dir=output_dir, started_at=datetime.utcnow())
    context.run_id = run_id
    return context


def _seed_store(tmp_path: Path, run_id: str, *hosts: Host) -> AssetStore:
    store = AssetStore(tmp_path / "output" / "recon.db")
    store.create_run(ScanRun(run_id=run_id, started_at="2026-01-01T00:00:00Z", targets=[]))
    store.persist_registry(run_id, {h.domain: h for h in hosts})
    return store


def _high_risk_host(domain: str, *, confidence_score: int = 80) -> Host:
    return Host(
        domain=domain,
        hostname=domain,
        risk_level=RiskLevel.HIGH,
        risk_score=70,
        confidence_score=confidence_score,
        risk_reasons=["exposed admin panel"],
    )


class TestInvalidatedHostExcludedFromReport:
    def test_json_excludes_it_and_lists_it_as_contradicted(self, tmp_path: Path) -> None:
        run_id = "run1"
        host = _high_risk_host("mta1.stripchat.com")
        store = _seed_store(tmp_path, run_id, host)
        store.record_verification_findings(
            run_id,
            [
                VerificationFinding(
                    claim="mta1.stripchat.com: resolved",
                    evidence="dnsx record has status_code='NOERROR' with only an soa record",
                    raw_artifact="dnsx_records.jsonl",
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="detect_dnsx_nodata_as_resolved",
                    host="mta1.stripchat.com",
                )
            ],
        )
        context = _make_context(tmp_path, run_id)
        reporter = ReportGenerator(Settings(project_root=tmp_path))
        reporter.generate(context, store=store)

        summary_data = json.loads((context.output_dir / "summary.json").read_text())
        high_priority_domains = {h["domain"] for h in summary_data.get("high_priority", [])}
        assert "mta1.stripchat.com" not in high_priority_domains

        contradicted = summary_data.get("contradicted_findings", [])
        assert len(contradicted) == 1
        assert contradicted[0]["host"] == "mta1.stripchat.com"
        assert contradicted[0]["raw_artifact"] == "dnsx_records.jsonl"
        assert summary_data["verification"] == {
            "confirmed": 0,
            "pending": 0,
            "invalidated": 1,
            "total": 1,
        }

    def test_markdown_keeps_other_high_priority_hosts_when_one_is_excluded(
        self, tmp_path: Path
    ) -> None:
        """Two high-priority hosts, only one invalidated — the section must
        still print, keeping the untainted host and excluding only the
        invalidated one."""
        run_id = "run1"
        bad_host = _high_risk_host("mta1.stripchat.com")
        good_host = _high_risk_host("creator.stripchat.com")
        store = _seed_store(tmp_path, run_id, bad_host, good_host)
        store.record_verification_findings(
            run_id,
            [
                VerificationFinding(
                    claim="mta1.stripchat.com: resolved",
                    evidence="NODATA record wrongly counted resolved",
                    raw_artifact="dnsx_records.jsonl",
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="detect_dnsx_nodata_as_resolved",
                    host="mta1.stripchat.com",
                )
            ],
        )
        context = _make_context(tmp_path, run_id)
        settings = Settings(project_root=tmp_path)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)

        md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        high_priority_section = md.split("## High-Priority Infrastructure")[1].split("##")[0]
        assert "mta1.stripchat.com" not in high_priority_section
        assert "creator.stripchat.com" in high_priority_section

    def test_markdown_excludes_it_and_shows_contradicted_section(self, tmp_path: Path) -> None:
        run_id = "run1"
        host = _high_risk_host("mta1.stripchat.com")
        store = _seed_store(tmp_path, run_id, host)
        store.record_verification_findings(
            run_id,
            [
                VerificationFinding(
                    claim="mta1.stripchat.com: resolved",
                    evidence="NODATA record wrongly counted resolved",
                    raw_artifact="dnsx_records.jsonl",
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="detect_dnsx_nodata_as_resolved",
                    host="mta1.stripchat.com",
                )
            ],
        )
        context = _make_context(tmp_path, run_id)
        settings = Settings(project_root=tmp_path)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)

        md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        # The only host in this run is the invalidated one — once excluded,
        # nothing is left for the High-Priority Infrastructure section at
        # all, so it must not even print its own header (same behavior as
        # "no high-risk hosts this run" today).
        assert "## High-Priority Infrastructure" not in md
        assert "## ⚠ Contradicted / Unverifiable Findings" in md
        contradicted_section = md.split("## ⚠ Contradicted / Unverifiable Findings")[1]
        assert "mta1.stripchat.com" in contradicted_section
        assert "NODATA record wrongly counted resolved" in contradicted_section
        assert "dnsx_records.jsonl" in contradicted_section

    def test_html_excludes_it_and_shows_contradicted_section(self, tmp_path: Path) -> None:
        run_id = "run1"
        host = _high_risk_host("mta1.stripchat.com")
        store = _seed_store(tmp_path, run_id, host)
        store.record_verification_findings(
            run_id,
            [
                VerificationFinding(
                    claim="mta1.stripchat.com: resolved",
                    evidence="NODATA record wrongly counted resolved",
                    raw_artifact="dnsx_records.jsonl",
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="detect_dnsx_nodata_as_resolved",
                    host="mta1.stripchat.com",
                )
            ],
        )
        context = _make_context(tmp_path, run_id)
        reporter = ReportGenerator(Settings(project_root=tmp_path))
        reporter.generate(context, store=store)

        html = (context.output_dir / "summary.html").read_text(encoding="utf-8")
        assets_table = html.split("<table id='assets'>")[1].split("</table>")[0]
        assert "mta1.stripchat.com" not in assets_table
        assert "Contradicted / Unverifiable Findings" in html
        contradicted_section = html.split("Contradicted / Unverifiable Findings")[1]
        assert "mta1.stripchat.com" in contradicted_section
        assert "dnsx_records.jsonl" in contradicted_section


class TestDowngradedHostStaysWithReducedConfidence:
    def test_json_reduces_confidence_and_adds_note(self, tmp_path: Path) -> None:
        run_id = "run1"
        host = _high_risk_host("api.stripchat.com", confidence_score=80)
        store = _seed_store(tmp_path, run_id, host)
        store.record_verification_findings(
            run_id,
            [
                VerificationFinding(
                    claim="api.stripchat.com:37 open (naabu)",
                    evidence="nmap (second opinion) reports filtered for the same port",
                    raw_artifact="port_verify.jsonl",
                    severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
                    detector="detect_naabu_nmap_port_disagreement",
                    host="api.stripchat.com",
                )
            ],
        )
        context = _make_context(tmp_path, run_id)
        reporter = ReportGenerator(Settings(project_root=tmp_path))
        reporter.generate(context, store=store)

        summary_data = json.loads((context.output_dir / "summary.json").read_text())
        entry = next(h for h in summary_data["high_priority"] if h["domain"] == "api.stripchat.com")
        assert entry["confidence_score"] == 55  # 80 - 25 flat penalty
        assert "nmap (second opinion)" in entry["verification_note"]
        assert "contradicted_findings" not in summary_data
        assert summary_data["verification"] == {
            "confirmed": 1,
            "pending": 0,
            "invalidated": 0,
            "total": 1,
        }

    def test_markdown_shows_reduced_confidence_and_note(self, tmp_path: Path) -> None:
        run_id = "run1"
        host = _high_risk_host("api.stripchat.com", confidence_score=80)
        store = _seed_store(tmp_path, run_id, host)
        store.record_verification_findings(
            run_id,
            [
                VerificationFinding(
                    claim="api.stripchat.com:37 open (naabu)",
                    evidence="nmap (second opinion) reports filtered for the same port",
                    raw_artifact="port_verify.jsonl",
                    severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
                    detector="detect_naabu_nmap_port_disagreement",
                    host="api.stripchat.com",
                )
            ],
        )
        context = _make_context(tmp_path, run_id)
        settings = Settings(project_root=tmp_path)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)

        md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        assert "api.stripchat.com" in md
        assert "55%" in md
        assert "confidence reduced" in md
        assert "## ⚠ Contradicted / Unverifiable Findings" not in md


class TestCleanRunHasNoVerificationNoise:
    def test_json_has_zeroed_verification_counts_and_no_contradicted_key(
        self, tmp_path: Path
    ) -> None:
        run_id = "run1"
        host = _high_risk_host("clean.example.com")
        store = _seed_store(tmp_path, run_id, host)
        context = _make_context(tmp_path, run_id)
        reporter = ReportGenerator(Settings(project_root=tmp_path))
        reporter.generate(context, store=store)

        summary_data = json.loads((context.output_dir / "summary.json").read_text())
        assert summary_data["verification"] == {
            "confirmed": 0,
            "pending": 0,
            "invalidated": 0,
            "total": 0,
        }
        assert "contradicted_findings" not in summary_data
        entry = next(h for h in summary_data["high_priority"] if h["domain"] == "clean.example.com")
        assert entry["confidence_score"] == 80
        assert "verification_note" not in entry

    def test_markdown_and_html_have_no_contradicted_section(self, tmp_path: Path) -> None:
        run_id = "run1"
        host = _high_risk_host("clean.example.com")
        store = _seed_store(tmp_path, run_id, host)
        context = _make_context(tmp_path, run_id)
        settings = Settings(project_root=tmp_path)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)

        md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        html = (context.output_dir / "summary.html").read_text(encoding="utf-8")
        assert "Contradicted" not in md
        assert "Contradicted" not in html
        assert "clean.example.com" in md
        assert "clean.example.com" in html


class TestRelationshipExcludedWhenHostInvalidated:
    """Reuses the real virusbarrier.xyz certificate-sharing fixture from
    test_virusbarrier_e2e.py (SEED + SIBLINGS, a real SHARES_CERTIFICATE
    relationship produced by the actual finalize path) rather than
    hand-crafting intel_entities/intel_relationships rows — the same
    "reuse the real fixture" discipline this whole project follows."""

    def test_relationship_naming_an_invalidated_host_is_excluded_from_markdown(
        self, tmp_path: Path
    ) -> None:
        from tests.test_virusbarrier_e2e import RUN_ID, SEED, _run_production_finalize

        _registry, db_path, context = _run_production_finalize(tmp_path)
        store = AssetStore(db_path)
        store.record_verification_findings(
            RUN_ID,
            [
                VerificationFinding(
                    claim=f"{SEED}: certificate-sharing relationship is legitimate",
                    evidence="synthetic test contradiction",
                    raw_artifact=None,
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="test_synthetic_detector",
                    host=SEED,
                )
            ],
        )
        settings = Settings(project_root=tmp_path)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)

        md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        if "## Intelligence Relationships" in md:
            rel_section = md.split("## Intelligence Relationships")[1].split("##")[0]
            assert SEED not in rel_section
        assert "## ⚠ Contradicted / Unverifiable Findings" in md
        assert SEED in md.split("## ⚠ Contradicted / Unverifiable Findings")[1]

    def test_relationship_naming_an_invalidated_host_is_excluded_from_html(
        self, tmp_path: Path
    ) -> None:
        from tests.test_virusbarrier_e2e import RUN_ID, SEED, _run_production_finalize

        _registry, db_path, context = _run_production_finalize(tmp_path)
        store = AssetStore(db_path)
        store.record_verification_findings(
            RUN_ID,
            [
                VerificationFinding(
                    claim=f"{SEED}: certificate-sharing relationship is legitimate",
                    evidence="synthetic test contradiction",
                    raw_artifact=None,
                    severity=ContradictionSeverity.INVALIDATES,
                    detector="test_synthetic_detector",
                    host=SEED,
                )
            ],
        )
        settings = Settings(project_root=tmp_path)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)

        html = (context.output_dir / "summary.html").read_text(encoding="utf-8")
        if "Intelligence Correlation" in html:
            correlation_section = html.split("Intelligence Correlation")[1].split("<h2>")[0]
            assert SEED not in correlation_section
        assert "Contradicted / Unverifiable Findings" in html
