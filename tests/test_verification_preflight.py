"""core/verification/preflight.py — hash/fingerprint helpers and the
historical cross-run check (design Part B.1).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.runner import PipelineRunner
from core.store import AssetStore
from core.verification.model import ContradictionSeverity
from core.verification.preflight import (
    compute_attribution_fingerprint,
    compute_scope_file_hash,
    historical_cross_check,
)


class TestComputeScopeFileHash:
    def test_none_scope_file_returns_none(self) -> None:
        assert compute_scope_file_hash(None) is None

    def test_missing_scope_file_returns_none(self, tmp_path: Path) -> None:
        assert compute_scope_file_hash(tmp_path / "does-not-exist.txt") is None

    def test_same_content_same_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "scope1.txt"
        f2 = tmp_path / "scope2.txt"
        f1.write_text("*.example.com\n", encoding="utf-8")
        f2.write_text("*.example.com\n", encoding="utf-8")
        assert compute_scope_file_hash(f1) == compute_scope_file_hash(f2)

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "scope1.txt"
        f2 = tmp_path / "scope2.txt"
        f1.write_text("*.example.com\n", encoding="utf-8")
        f2.write_text("*.other.com\n", encoding="utf-8")
        assert compute_scope_file_hash(f1) != compute_scope_file_hash(f2)

    def test_never_leaks_raw_content(self, tmp_path: Path) -> None:
        f1 = tmp_path / "scope1.txt"
        f1.write_text("supersecretprogram.example.com\n", encoding="utf-8")
        digest = compute_scope_file_hash(f1)
        assert digest is not None
        assert "supersecretprogram" not in digest


class TestComputeAttributionFingerprint:
    def test_nothing_configured_returns_none(self) -> None:
        assert compute_attribution_fingerprint(None, None) is None
        assert compute_attribution_fingerprint({}, None) is None

    def test_never_leaks_raw_header_value(self) -> None:
        fp = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "my_h1_handle"}, "bugcrowd; cosmiccashew"
        )
        assert fp is not None
        assert "my_h1_handle" not in fp
        assert "cosmiccashew" not in fp

    def test_same_pair_same_fingerprint(self) -> None:
        a = compute_attribution_fingerprint({"X-H1": "handle"}, "ua")
        b = compute_attribution_fingerprint({"X-H1": "handle"}, "ua")
        assert a == b

    def test_different_program_different_fingerprint(self) -> None:
        """The exact item-7 shape: Stripchat's header vs. Glassdoor's."""
        stripchat = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "stripchat_handle"}, None
        )
        glassdoor = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "glassdoor_handle"}, None
        )
        assert stripchat != glassdoor


def _run(store: AssetStore, run_id: str, **kwargs) -> None:
    store.create_run(
        ScanRun(
            run_id=run_id,
            started_at="2026-01-01T00:00:00Z",
            targets=kwargs.pop("targets", ["stripchat.com"]),
            program_name=kwargs.pop("program_name", "Stripchat"),
            **kwargs,
        )
    )
    store.finish_run(run_id, host_count=0, alive_count=0, warnings=[], errors=[])


class TestHistoricalCrossCheck:
    def test_first_run_for_program_has_nothing_to_compare(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []

    def test_no_program_name_is_a_noop(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1")
        findings = historical_cross_check(
            store,
            program_name="",
            scope_file_hash="sha256:abc",
            attribution_fingerprint=None,
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []

    def test_consistent_history_raises_nothing(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(
            store,
            "r1",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
            targets=["stripchat.com"],
        )
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []

    def test_attribution_fingerprint_mismatch_is_flagged(self, tmp_path: Path) -> None:
        """The exact catalog item 7 shape: a Stripchat-flavored .env
        (attribution fingerprint from a prior Stripchat run) run again
        under PROGRAM_NAME=Stripchat but with a DIFFERENT header/UA in
        effect than history shows for that program."""
        store = AssetStore(tmp_path / "recon.db")
        _run(
            store,
            "stripchat-run-1",
            attribution_fingerprint=compute_attribution_fingerprint(
                {"X-HackerOne-Research": "stripchat_handle"}, None
            ),
            targets=["stripchat.com"],
        )
        current_fp = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "glassdoor_handle"}, None
        )
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash=None,
            attribution_fingerprint=current_fp,
            current_scope_domains=["stripchat.com"],
        )
        assert len(findings) == 1
        assert findings[0].severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE
        assert findings[0].related_table == "runs"
        assert findings[0].related_id == "stripchat-run-1"

    def test_scope_file_hash_mismatch_is_flagged(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1", scope_file_hash="sha256:old", targets=["stripchat.com"])
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:new",
            attribution_fingerprint=None,
            current_scope_domains=["stripchat.com"],
        )
        assert len(findings) == 1
        assert findings[0].detector == "historical_cross_check_scope_file"

    def test_no_target_overlap_is_flagged(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1", targets=["stripchat.com"])
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash=None,
            attribution_fingerprint=None,
            current_scope_domains=["glassdoor.com"],
        )
        assert len(findings) == 1
        assert findings[0].detector == "historical_cross_check_target_overlap"

    def test_all_three_mismatches_produce_three_findings(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(
            store,
            "r1",
            scope_file_hash="sha256:old",
            attribution_fingerprint="sha256:old-attr",
            targets=["stripchat.com"],
        )
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:new",
            attribution_fingerprint="sha256:new-attr",
            current_scope_domains=["glassdoor.com"],
        )
        assert len(findings) == 3
        assert all(f.severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE for f in findings)

    def test_none_current_hash_never_flags_missing_history_value(self, tmp_path: Path) -> None:
        """A current hash of None (e.g. no SCOPE_FILE this run) must not be
        compared against a real historical hash — that is "no value", not
        "a different value"."""
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1", scope_file_hash="sha256:old", targets=["stripchat.com"])
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash=None,
            attribution_fingerprint=None,
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []


class TestHistoricalCrossCheckWiredIntoRunner:
    """core/runner.py::PipelineRunner.run() actually calls
    historical_cross_check and persists the result — not just that the
    function works in isolation.

    A crashed run (missing tools) never reaches `store.finish_run()`
    (that call sits deep in the normal successful-completion path,
    core/runner.py near `_finalize_to_store`) — confirmed while writing
    this test, an earlier draft ran BOTH runs through the real, crashing
    `PipelineRunner.run()` and got zero flags every time, because the
    first "prior" run was never eligible for
    `find_latest_finished_run_for_program` (it requires `finished_at` to
    be set). Fixed by seeding the prior run directly via the store — the
    same way `TestHistoricalCrossCheck` above does — and only driving the
    run actually under test (the second one) through the real,
    missing-tools-aborted `PipelineRunner.run()`, mirroring
    tests/test_runner.py::test_handles_missing_tools_gracefully's pattern
    to keep this fast and hermetic while still exercising the real
    pre-flight wiring inside `run()`.
    """

    @pytest.mark.asyncio
    async def test_stripchat_attribution_header_reused_for_a_different_program(
        self, project_root: Path
    ) -> None:
        """Catalog item 7: a prior finished run under PROGRAM_NAME=Stripchat
        with one attribution header, then a new run under the SAME stale
        PROGRAM_NAME but a DIFFERENT header in effect — the real mechanism
        this whole design exists to catch."""
        db_path = project_root / "output" / "recon.db"
        store = AssetStore(db_path)
        store.create_run(
            ScanRun(
                run_id="stripchat-run-1",
                started_at="2026-01-01T00:00:00Z",
                targets=["stripchat.com"],
                program_name="Stripchat",
                attribution_fingerprint=compute_attribution_fingerprint(
                    {"X-HackerOne-Research": "my_stripchat_handle"}, None
                ),
            )
        )
        store.finish_run("stripchat-run-1", host_count=0, alive_count=0, warnings=[], errors=[])

        glassdoor_settings = Settings(
            project_root=project_root,
            program_name="Stripchat",  # stale PROGRAM_NAME, matching the real incident
            researcher_attribution_header={"X-HackerOne-Research": "my_glassdoor_handle"},
        )
        runner2 = PipelineRunner(glassdoor_settings)
        with patch.object(
            runner2.tool_manager, "validate_tools", new=AsyncMock(return_value=False)
        ):
            with patch.object(
                runner2.tool_manager,
                "ensure_mandatory_tools",
                new=AsyncMock(side_effect=Exception("tools missing")),
            ):
                context2 = await runner2.run(domain="stripchat.com", run_id="run2")

        flags = store.get_verification_flags("run2")
        assert len(flags) == 1
        assert flags[0]["detector"] == "historical_cross_check_attribution"
        assert flags[0]["related_id"] == "stripchat-run-1"
        assert any("Verification (pre-flight)" in w for w in context2.warnings)

    @pytest.mark.asyncio
    async def test_clean_repeat_run_raises_no_false_flags(self, project_root: Path) -> None:
        """Same program, same attribution, same target as the seeded prior
        run — zero noise, same standard as every other detector in this
        design."""
        db_path = project_root / "output" / "recon.db"
        store = AssetStore(db_path)
        store.create_run(
            ScanRun(
                run_id="stripchat-run-1",
                started_at="2026-01-01T00:00:00Z",
                targets=["stripchat.com"],
                program_name="Stripchat",
                attribution_fingerprint=compute_attribution_fingerprint(
                    {"X-HackerOne-Research": "my_stripchat_handle"}, None
                ),
            )
        )
        store.finish_run("stripchat-run-1", host_count=0, alive_count=0, warnings=[], errors=[])

        settings2 = Settings(
            project_root=project_root,
            program_name="Stripchat",
            researcher_attribution_header={"X-HackerOne-Research": "my_stripchat_handle"},
        )
        runner2 = PipelineRunner(settings2)
        with patch.object(
            runner2.tool_manager, "validate_tools", new=AsyncMock(return_value=False)
        ):
            with patch.object(
                runner2.tool_manager,
                "ensure_mandatory_tools",
                new=AsyncMock(side_effect=Exception("tools missing")),
            ):
                context2 = await runner2.run(domain="stripchat.com", run_id="run2")

        assert store.get_verification_flags("run2") == []
        assert not any("Verification (pre-flight)" in w for w in context2.warnings)
