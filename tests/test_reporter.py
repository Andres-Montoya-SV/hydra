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
