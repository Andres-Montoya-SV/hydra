"""core/client_report/render_docx.py — behavior when python-docx is NOT
installed. Deliberately has no `pytest.importorskip("docx")` guard: this
file's whole point is to run in an environment where the optional
dependency is absent and confirm the failure is clean, not a crash.
"""

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.client_report.cli import cmd_client_report
from core.client_report.collect import RunReportData
from core.store import AssetStore


def _simulate_docx_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def _fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "docx" or name.startswith("docx."):
            raise ImportError("simulated: python-docx not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)


class TestRenderDocxWithoutPythonDocxInstalled:
    def test_raises_a_clear_docx_render_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _simulate_docx_not_installed(monkeypatch)
        from core.client_report.render_docx import DocxRenderError, render_docx

        data = RunReportData(
            run_id="run1",
            targets=["x.test"],
            started_at=None,
            finished_at=None,
            duration_seconds=None,
        )
        with pytest.raises(DocxRenderError, match="python-docx is not installed"):
            render_docx(data, [])

    def test_cli_reports_the_error_cleanly_and_does_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        output_dir = tmp_path / "output"
        output_dir.mkdir(parents=True)
        run_dir = output_dir / "run1"
        run_dir.mkdir()
        store = AssetStore(output_dir / "recon.db")
        store.create_run(
            ScanRun(run_id="run1", started_at="2026-01-01T00:00:00Z", targets=["x.test"])
        )
        (run_dir / "vuln_match.jsonl").write_text("", encoding="utf-8")

        _simulate_docx_not_installed(monkeypatch)
        settings = Settings(project_root=tmp_path)
        rc = cmd_client_report(settings, "run1", output_format="docx")
        assert rc == 1
