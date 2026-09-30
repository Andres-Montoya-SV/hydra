"""How a finished scan's per-tool states are recorded as provider outcomes.

Regression: a tool the pipeline never reached (e.g. naabu/httpx when no
host resolved) is still `ready` when the scan ends, and an enabled tool
without a discovery report is `missing`. Neither is an execution outcome,
so recording them raised *after* the scan was marked completed, and the
orchestrator's catch-all then flipped a clean scan to `failed`.

Each recorded outcome also carries a failure class (transient /
configuration / unknown), derived only from signals the pipeline already
records — never guessed from error text.
"""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

import pytest
from _org_helpers import api_client, verified_owner

from api.control_db import ControlDB
from api.scan_orchestrator import execute_scan
from api.settings import APISettings
from core.models import PipelineContext, ToolInfo, ToolStatus
from core.provider_contract import failure_class, recorded_outcome


def _tool(name: str, status: ToolStatus, *, lines: int = 0, **counters: int) -> ToolInfo:
    info = ToolInfo(name=name, display_name=name, required=False, enabled=True, status=status)
    info.output_lines = lines
    for key, value in counters.items():
        setattr(info, key, value)
    return info


END_OF_RUN = {
    "subfinder": _tool("subfinder", ToolStatus.SUCCESS_WITH_RESULTS, lines=3),
    "httpx": _tool("httpx", ToolStatus.READY),  # never reached: nothing resolved
    "naabu": _tool("naabu", ToolStatus.PENDING),
    "amass": _tool("amass", ToolStatus.MISSING),  # enabled, binary not found
    "gau": _tool("gau", ToolStatus.COMPLETED, lines=2),  # legacy terminal state
    "ctlogs": _tool("ctlogs", ToolStatus.UNAVAILABLE),
    "nuclei": _tool("nuclei", ToolStatus.FAILED, timeouts=1),
    "katana": _tool("katana", ToolStatus.FAILED),
}


class TestRecordedOutcome:
    @pytest.mark.parametrize(
        ("status", "lines", "expected"),
        [
            (ToolStatus.READY, 0, ToolStatus.SKIPPED),
            (ToolStatus.PENDING, 0, ToolStatus.SKIPPED),
            (ToolStatus.CHECKING, 0, ToolStatus.SKIPPED),
            (ToolStatus.MISSING, 0, ToolStatus.UNAVAILABLE),
            (ToolStatus.RUNNING, 0, ToolStatus.FAILED),
            (ToolStatus.COMPLETED, 2, ToolStatus.SUCCESS_WITH_RESULTS),
            (ToolStatus.COMPLETED, 0, ToolStatus.SUCCESS_NO_RESULTS),
            (ToolStatus.PARTIAL, 1, ToolStatus.PARTIAL),
        ],
    )
    def test_every_state_maps_to_an_execution_outcome(
        self, status: ToolStatus, lines: int, expected: ToolStatus
    ) -> None:
        assert recorded_outcome(_tool("x", status, lines=lines)) is expected


class TestFailureClass:
    @pytest.mark.parametrize(
        ("info", "expected"),
        [
            (_tool("x", ToolStatus.UNAVAILABLE), "transient"),
            (_tool("x", ToolStatus.PARTIAL), "transient"),
            (_tool("x", ToolStatus.FAILED, timeouts=1), "transient"),
            (_tool("x", ToolStatus.FAILED, rate_limits=2), "transient"),
            (_tool("x", ToolStatus.MISSING), "configuration"),
            (_tool("x", ToolStatus.FAILED), "unknown"),
            (_tool("x", ToolStatus.SUCCESS_WITH_RESULTS, lines=1), None),
            (_tool("x", ToolStatus.SKIPPED), None),
            (_tool("x", ToolStatus.READY), None),
        ],
    )
    def test_classification(self, info: ToolInfo, expected: str | None) -> None:
        assert failure_class(info) == expected


def _queued_scan(db: ControlDB) -> tuple[str, str]:
    account_id = db.create_account(email=f"rec-{secrets.token_hex(4)}@example.com")
    db.create_default_subscription(account_id, tier="free")
    organization_id = db.default_organization_id_for_account(account_id)
    scan_id = secrets.token_hex(16)
    db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain="example.com",
        db_path="x",
        organization_id=organization_id,
    )
    return account_id, scan_id


async def _pipeline_ending_with(settings, *, domain, targets_file, run_id):  # noqa: ANN001, ANN202
    return 0, PipelineContext(errors=[], tool_states=dict(END_OF_RUN))


class TestExecuteScanRecording:
    async def test_a_clean_scan_with_unreached_tools_stays_completed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api_settings = APISettings(data_dir=tmp_path / "api")
        db = ControlDB(api_settings.control_db_path)
        account_id, scan_id = _queued_scan(db)
        monkeypatch.setattr("app._run_headless_pipeline", _pipeline_ending_with)
        monkeypatch.setattr("app._external_mode_preflight", lambda args, settings: True)

        await execute_scan(
            api_settings=api_settings,
            control_db=db,
            account_id=account_id,
            scan_id=scan_id,
            domain="example.com",
        )

        scan = db.get_owned_scan(scan_id, account_id)
        recorded = {
            row.provider: (row.outcome, row.failure_class)
            for row in db.list_provider_run_outcomes(scan.organization_id, scan_id)
        }
        assert (scan.status, scan.error_message) == ("completed", None)
        assert recorded == {
            "subfinder": ("success_with_results", None),
            "httpx": ("skipped", None),
            "naabu": ("skipped", None),
            "amass": ("unavailable", "configuration"),
            "gau": ("success_with_results", None),
            "ctlogs": ("unavailable", "transient"),
            "nuclei": ("failed", "transient"),
            "katana": ("failed", "unknown"),
        }


class TestCollectionEndpointAndMigration:
    def test_scan_collection_reports_the_failure_class(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            db = client.app.state.control_db
            db.create_scan(
                scan_id="run-fc",
                account_id=account_id,
                domain="example.com",
                db_path="x",
                organization_id=org,
            )
            db.record_provider_run_outcomes(
                organization_id=org,
                account_id=account_id,
                run_id="run-fc",
                outcomes=[("ctlogs", "unavailable", 0), ("subfinder", "success_with_results", 4)],
                failure_classes={"ctlogs": "transient"},
            )

            body = client.get("/scans/run-fc/collection", headers=headers).json()

            assert {o["provider"]: o["failure_class"] for o in body["outcomes"]} == {
                "ctlogs": "transient",
                "subfinder": None,
            }

    # Upgrades an existing SQLite control-db file.
    @pytest.mark.sqlite_only
    def test_an_existing_database_gains_the_column(self, tmp_path: Path) -> None:
        path = tmp_path / "control.db"
        ControlDB(path)
        with sqlite3.connect(path) as conn:
            conn.execute("ALTER TABLE provider_run_outcomes DROP COLUMN failure_class")

        ControlDB(path)

        with sqlite3.connect(path) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(provider_run_outcomes)")}
        assert "failure_class" in columns
