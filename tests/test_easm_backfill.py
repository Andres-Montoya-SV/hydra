"""Fase 18 (EASM roadmap) — tests for `api/easm_backfill.py`, the
missing wiring found while building monitoring integration: before this
phase, no live code path ever called any EASM backfill function, so
`assets`/`change_events`/`exposures`/etc. were never populated by a real
scan. These tests prove the new orchestration function actually
populates every EASM table from one real scan, and that its "safe"
wrapper never lets a backfill failure propagate.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.control_db import ControlDB
from api.easm_backfill import (
    run_easm_backfill_for_organization,
    run_easm_backfill_for_organization_safely,
)
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Finding, Host, TechnologyFinding, TlsCertificate
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _seed_completed_scan_with_rich_host(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
) -> None:
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain=domain,
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
    host = Host(
        domain=domain,
        discovery_sources=["dnsx"],
        tls=TlsCertificate(
            host=domain,
            issuer="Let's Encrypt",
            subject=f"CN={domain}",
            sans=[domain],
            not_before="2026-01-01",
            not_after="2026-04-01",
            fingerprint_sha256="a" * 64,
        ),
        findings=[
            Finding(
                host=domain,
                template_id="exposed-panel",
                severity="high",
                name="Exposed admin panel",
                source="nuclei",
            )
        ],
    )
    from core.assets import HttpService

    host.http_services.append(
        HttpService(
            url=f"https://{domain}",
            host=domain,
            status_code=200,
            source="httpx",
            technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=95)],
        )
    )
    store.upsert_host(scan_id, host)
    control_db.update_scan_status(scan_id, "completed")


class TestRunEasmBackfillForOrganization:
    def test_one_real_scan_populates_every_easm_table(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_completed_scan_with_rich_host(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
        )

        summary = run_easm_backfill_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        assert summary.assets_created >= 1
        assert summary.exposures_created >= 1
        assert summary.certificate_events_recorded >= 1
        assert summary.technology_events_recorded >= 1

        # And it actually landed where the monitoring worker (Fase 18's
        # own trigger) will read it from.
        assert control_db.list_assets_for_organization(organization_id) != []
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        assert control_db.list_certificate_events_for_asset(asset.asset_id) != []
        assert control_db.list_technology_events_for_asset(asset.asset_id) != []

    def test_running_it_twice_is_idempotent(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_completed_scan_with_rich_host(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
        )
        run_easm_backfill_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        second = run_easm_backfill_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        assert second.assets_created == 0
        assert second.certificate_events_recorded == 0
        assert second.technology_events_recorded == 0


class TestRunEasmBackfillSafely:
    def test_a_failure_in_one_step_never_propagates(
        self, control_db: ControlDB, api_settings: APISettings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_completed_scan_with_rich_host(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
        )

        def boom(**kwargs: object) -> None:
            raise RuntimeError("simulated backfill failure")

        monkeypatch.setattr("api.easm_backfill.backfill_assets_for_organization", boom)

        result = run_easm_backfill_for_organization_safely(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        assert result is None

    def test_success_returns_the_real_summary(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_completed_scan_with_rich_host(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
        )
        result = run_easm_backfill_for_organization_safely(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        assert result is not None
        assert result.assets_created >= 1
