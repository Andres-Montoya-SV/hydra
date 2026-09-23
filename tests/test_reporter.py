"""Tests for report generation."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from config.settings import Settings
from core.models import DomainTarget, PipelineContext, ToolInfo, ToolStatus
from core.reporter import ReportGenerator
from utils.security import escape_html


class TestReporter:
    def test_escape_html_prevents_xss(self) -> None:
        assert "&lt;script&gt;" in escape_html("<script>")

    def test_build_summary(self, settings: Settings) -> None:
        context = PipelineContext(
            output_dir=settings.project_root / "output" / "test",
            targets=[DomainTarget("example.com")],
            subdomains=["sub.example.com"],
            resolved=["sub.example.com"],
            alive_urls=["https://sub.example.com"],
            started_at=datetime.utcnow(),
        )
        context.tool_states["httpx"] = ToolInfo(
            name="httpx",
            display_name="httpx",
            required=True,
            enabled=True,
            status=ToolStatus.COMPLETED,
        )
        reporter = ReportGenerator(settings)
        summary = reporter.build_summary(context)
        assert summary.targets_count == 1
        assert summary.alive_count == 1
        assert summary.output_dir == str(Path("output") / "test")
        assert str(settings.project_root) not in summary.output_dir

    def test_html_report_escapes_content(self, settings: Settings, tmp_path: Path) -> None:
        context = PipelineContext(
            output_dir=tmp_path / "run",
            httpx_results=[{"url": "<script>", "title": "<img onerror=1>", "status_code": 200}],
            started_at=datetime.utcnow(),
        )
        context.output_dir.mkdir(parents=True)
        reporter = ReportGenerator(settings)
        reporter._write_html_summary(context, reporter.build_summary(context))
        html = (context.output_dir / "summary.html").read_text(encoding="utf-8")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_and_summary_surface_param_fuzz_baseline_invalid(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        context = PipelineContext(
            output_dir=tmp_path / "run",
            started_at=datetime.utcnow(),
        )
        context.output_dir.mkdir(parents=True)
        context.metadata["param_fuzz_baseline_invalid_hosts"] = [
            {
                "host": "example.com",
                "url": "https://example.com/",
                "baseline_status": 429,
                "reason": "baseline returned HTTP 429 — target is rate-limiting or blocking requests",
                "baseline_invalid": True,
            }
        ]
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=None)
        summary = (context.output_dir / "summary.json").read_text(encoding="utf-8")
        assert "param_fuzz_baseline_invalid_hosts" in summary
        assert "429" in summary
        html = (context.output_dir / "summary.html").read_text(encoding="utf-8")
        assert "Parameter Discovery Skipped" in html
        assert "example.com" in html
        assert "rate-limiting" in html
        md = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        assert "Parameter Discovery Skipped" in md
        assert "example.com" in md


class TestTyposquatBrandProtectionSection:
    """modules/dnstwist.py's findings get their own, clearly-separated
    report section — never mixed into the Assets/Hosts tables, which
    would let a reader mistake a registered lookalike for a real
    subdomain of the target."""

    def _store_with_candidate(self, tmp_path: Path, run_id: str):
        from core.assets import ScanRun
        from core.store import AssetStore

        store = AssetStore(tmp_path / "run.db")
        store.create_run(ScanRun(run_id=run_id, started_at="2026-09-23T00:00:00Z"))
        store.persist_registry(run_id, {}, clusters=[], graph=None, intel=None)
        store.record_typosquat_candidates(
            run_id,
            [
                {
                    "target_domain": "example.com",
                    "candidate_domain": "exampler.com",
                    "fuzzer": "addition",
                    "dns_a": ["203.0.113.5"],
                    "dns_mx": ["mx.some-host.test"],
                    "has_mx": True,
                    "whois_created": "2020-01-01",
                    "whois_registrar": "Namecheap",
                    "severity": "high",
                    "risk_reason": "MX record configured",
                    "confidence_score": 80,
                }
            ],
        )
        store.finish_run(run_id, host_count=0, alive_count=0, warnings=[], errors=[])
        return store

    def test_markdown_report_labels_it_as_not_target_infrastructure(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        run_id = "test-typosquat-md"
        store = self._store_with_candidate(tmp_path, run_id)
        context = PipelineContext(
            output_dir=tmp_path / "run",
            targets=[DomainTarget("example.com")],
            run_id=run_id,
            started_at=datetime.utcnow(),
        )
        context.output_dir.mkdir(parents=True)
        reporter = ReportGenerator(settings)
        reporter._write_markdown_overview(context, reporter.build_summary(context), store=store)
        overview = (settings.project_root / settings.reports_directory / "overview.md").read_text(
            encoding="utf-8"
        )
        assert "Brand Protection" in overview
        assert "NOT part of your own infrastructure" in overview
        assert "exampler.com" in overview

    def test_html_report_includes_the_section_with_the_disclaimer(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        run_id = "test-typosquat-html"
        store = self._store_with_candidate(tmp_path, run_id)
        context = PipelineContext(
            output_dir=tmp_path / "run",
            targets=[DomainTarget("example.com")],
            run_id=run_id,
            started_at=datetime.utcnow(),
        )
        context.output_dir.mkdir(parents=True)
        reporter = ReportGenerator(settings)
        reporter._write_html_summary(context, reporter.build_summary(context), store=store)
        html = (context.output_dir / "summary.html").read_text(encoding="utf-8")
        assert "Brand Protection" in html
        assert "NOT a vulnerability in your systems" in html
        assert "exampler.com" in html

    def test_summary_json_keeps_it_in_its_own_key_not_mixed_with_hosts(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        run_id = "test-typosquat-json"
        store = self._store_with_candidate(tmp_path, run_id)
        context = PipelineContext(
            output_dir=tmp_path / "run",
            targets=[DomainTarget("example.com")],
            run_id=run_id,
            started_at=datetime.utcnow(),
        )
        context.output_dir.mkdir(parents=True)
        reporter = ReportGenerator(settings)
        reporter.generate(context, store=store)
        import json

        summary_data = json.loads((context.output_dir / "summary.json").read_text(encoding="utf-8"))
        assert "typosquat_candidates" in summary_data
        assert summary_data["typosquat_candidates"][0]["candidate_domain"] == "exampler.com"
        high_priority_domains = {h["domain"] for h in summary_data.get("high_priority", [])}
        assert "exampler.com" not in high_priority_domains
