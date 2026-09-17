"""core/client_report/collect.py — gathering a run's persisted artifacts
for the client report. Focuses on the edge cases not already exercised
end-to-end by tests/test_client_report_cli.py: malformed/missing
summary.json or metadata.json must never crash collection.
"""

from __future__ import annotations

from pathlib import Path

from config.settings import Settings
from core.assets import ScanRun
from core.client_report.collect import collect
from core.store import AssetStore

RUN_ID = "run1"


def _bare_run(tmp_path: Path) -> tuple[Settings, AssetStore]:
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = output_dir / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    store = AssetStore(output_dir / "recon.db")
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    settings = Settings(project_root=tmp_path)
    return settings, store


class TestMissingOrMalformedArtifacts:
    def test_missing_summary_and_metadata_json_does_not_crash(self, tmp_path: Path) -> None:
        settings, store = _bare_run(tmp_path)
        data = collect(settings, store, RUN_ID)
        assert data.duration_seconds is None
        assert data.warnings == []
        assert data.vuln_check_failed == []
        assert data.findings == []

    def test_malformed_summary_json_falls_back_cleanly(self, tmp_path: Path) -> None:
        settings, store = _bare_run(tmp_path)
        run_dir = tmp_path / "output" / RUN_ID
        (run_dir / "summary.json").write_text("{not valid json", encoding="utf-8")
        data = collect(settings, store, RUN_ID)
        assert data.duration_seconds is None

    def test_summary_json_that_is_a_list_not_a_dict_falls_back_cleanly(
        self, tmp_path: Path
    ) -> None:
        settings, store = _bare_run(tmp_path)
        run_dir = tmp_path / "output" / RUN_ID
        (run_dir / "summary.json").write_text("[1, 2, 3]", encoding="utf-8")
        data = collect(settings, store, RUN_ID)
        assert data.duration_seconds is None

    def test_targets_and_started_at_come_from_the_store(self, tmp_path: Path) -> None:
        settings, store = _bare_run(tmp_path)
        data = collect(settings, store, RUN_ID)
        assert data.targets == ["x.test"]
        assert data.started_at == "2026-01-01T00:00:00Z"
