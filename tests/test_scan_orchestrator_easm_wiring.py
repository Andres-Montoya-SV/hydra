"""Fase 18 (EASM roadmap) — proves `api/scan_orchestrator.py::execute_scan`
actually triggers the EASM backfill (`api/easm_backfill.py`) after a real
scan completes, and that a backfill failure never turns an otherwise-
successful scan into a "failed" one. The real pipeline
(`app._run_headless_pipeline`) is mocked out — this test is about the
NEW wiring, not about re-testing pipeline execution itself.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.control_db import ControlDB
from api.scan_orchestrator import execute_scan
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host
from core.models import PipelineContext
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _prepare_account_and_queued_scan(
    control_db: ControlDB, api_settings: APISettings, *, domain: str
) -> tuple[str, str, str]:
    account_id = control_db.create_account(email="owner@example.com")
    control_db.create_default_subscription(account_id, tier="free")
    organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain=domain,
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    # The real pipeline would have written this scan's own Host rows to
    # the account's AssetStore before returning -- the fake pipeline
    # below does the same, standing in for real collection.
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
    store.upsert_host(scan_id, Host(domain=domain, discovery_sources=["dnsx"]))
    return account_id, organization_id, scan_id


async def _fake_run_headless_pipeline(settings, *, domain, targets_file, run_id):
    return 0, PipelineContext(errors=[])


def _fake_external_mode_preflight(args, settings) -> bool:
    return True


class TestExecuteScanTriggersEasmBackfill:
    async def test_a_successful_scan_populates_easm_tables(
        self,
        control_db: ControlDB,
        api_settings: APISettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        account_id, organization_id, scan_id = _prepare_account_and_queued_scan(
            control_db, api_settings, domain="example.com"
        )
        monkeypatch.setattr("app._run_headless_pipeline", _fake_run_headless_pipeline)
        monkeypatch.setattr("app._external_mode_preflight", _fake_external_mode_preflight)

        await execute_scan(
            api_settings=api_settings,
            control_db=control_db,
            account_id=account_id,
            scan_id=scan_id,
            domain="example.com",
        )

        scan = control_db.get_owned_scan(scan_id, account_id)
        assert scan is not None
        assert scan.status == "completed"
        assert control_db.list_assets_for_organization(organization_id) != []

    async def test_a_backfill_failure_never_fails_an_otherwise_successful_scan(
        self,
        control_db: ControlDB,
        api_settings: APISettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        account_id, organization_id, scan_id = _prepare_account_and_queued_scan(
            control_db, api_settings, domain="example.com"
        )
        monkeypatch.setattr("app._run_headless_pipeline", _fake_run_headless_pipeline)
        monkeypatch.setattr("app._external_mode_preflight", _fake_external_mode_preflight)

        def boom(**kwargs: object) -> None:
            raise RuntimeError("simulated backfill failure")

        monkeypatch.setattr("api.easm_backfill.backfill_assets_for_organization", boom)

        await execute_scan(
            api_settings=api_settings,
            control_db=control_db,
            account_id=account_id,
            scan_id=scan_id,
            domain="example.com",
        )

        scan = control_db.get_owned_scan(scan_id, account_id)
        assert scan is not None
        assert scan.status == "completed"
