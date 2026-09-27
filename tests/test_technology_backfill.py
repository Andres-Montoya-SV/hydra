"""Fase 14 (EASM roadmap) — the real, DB-backed half of technology
inventory tracking: `detect_technology_events_for_organization` and the
inventory queries (`list_current_technologies_for_asset`,
`list_assets_running_technology`) running against real scan-backed
domain assets. Proves idempotency, the phase's own required inventory
questions, and organization isolation.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.settings import APISettings
from api.technology_backfill import detect_technology_events_for_organization
from api.technology_events import TechnologyEventType
from api.tenancy import account_db_path
from core.assets import Host, HttpService, TechnologyFinding
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _run_scan_with_technologies(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
    technologies: list[TechnologyFinding],
    started_at: str,
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
    store.create_run(ScanRun(run_id=scan_id, started_at=started_at))
    service = HttpService(
        url=f"https://{domain}",
        host=domain,
        status_code=200,
        source="httpx",
        technologies=technologies,
    )
    store.upsert_host(
        scan_id, Host(domain=domain, discovery_sources=["dnsx"], http_services=[service])
    )
    control_db.update_scan_status(scan_id, "completed")
    backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )


class TestNameNormalizationCollapsesCrossSourceDuplicates:
    def test_httpx_lowercase_and_whatweb_titlecase_report_the_same_canonical_technology(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            technologies=[
                TechnologyFinding(name="Nginx", source="whatweb", confidence=90, version="1.24.0"),
                TechnologyFinding(name="nginx", source="httpx", confidence=95, version="1.24.0"),
            ],
            started_at="2026-01-01T00:00:00+00:00",
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        current = control_db.list_current_technologies_for_asset(asset.asset_id)
        names = {tech.technology_name for tech in current}
        assert names == {"nginx"}  # never {"Nginx", "nginx"}


class TestTechnologyEventDetection:
    def test_first_scan_reports_technology_added_for_everything_found(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            technologies=[
                TechnologyFinding(name="nginx", source="httpx", confidence=95, version="1.24.0")
            ],
            started_at="2026-01-01T00:00:00+00:00",
        )
        summary = detect_technology_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert summary.events_recorded == 1

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_technology_events_for_asset(asset.asset_id)
        assert [e.event_type for e in events] == [TechnologyEventType.ADDED.value]

    def test_a_removed_technology_is_detected_across_two_scans(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            technologies=[
                TechnologyFinding(name="nginx", source="httpx", confidence=95),
                TechnologyFinding(name="wordpress", source="httpx", confidence=95),
            ],
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=95)],
            started_at="2026-02-01T00:00:00+00:00",
        )
        detect_technology_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_technology_events_for_asset(asset.asset_id)
        removed = [e for e in events if e.event_type == TechnologyEventType.REMOVED.value]
        assert len(removed) == 1
        assert removed[0].technology_name == "WordPress"

        # And the inventory query agrees: WordPress is gone, nginx remains.
        current_names = {
            t.technology_name
            for t in control_db.list_current_technologies_for_asset(asset.asset_id)
        }
        assert current_names == {"nginx"}

    def test_running_the_backfill_twice_never_duplicates_events(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            technologies=[
                TechnologyFinding(name="nginx", source="httpx", confidence=95, version="1.24.0")
            ],
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            technologies=[
                TechnologyFinding(name="nginx", source="httpx", confidence=95, version="1.26.0")
            ],
            started_at="2026-02-01T00:00:00+00:00",
        )
        first = detect_technology_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        second = detect_technology_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert second.events_recorded == 0
        assert second.events_already_present == first.events_recorded


class TestInventoryQueries:
    def test_list_assets_running_technology_matches_exactly_never_a_substring(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="wp.example.com",
            technologies=[TechnologyFinding(name="wordpress", source="httpx", confidence=95)],
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="react.example.com",
            technologies=[TechnologyFinding(name="React", source="httpx", confidence=95)],
            started_at="2026-01-01T00:00:00+00:00",
        )
        matching = control_db.list_assets_running_technology(organization_id, "WordPress")
        assert [a.identity_key for a in matching] == ["domain:wp.example.com"]
        assert control_db.list_assets_running_technology(organization_id, "React Native") == []


class TestCrossOrganizationIsolation:
    def test_technology_events_for_organization_a_never_appear_in_organization_b(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="orga@example.com")
        account_b = control_db.create_account(email="orgb@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]
        _run_scan_with_technologies(
            control_db,
            api_settings,
            account_id=account_a,
            organization_id=org_a,
            domain="shared-name.example.com",
            technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=95)],
            started_at="2026-01-01T00:00:00+00:00",
        )
        detect_technology_events_for_organization(control_db=control_db, organization_id=org_a)

        assert control_db.list_technology_events_for_organization(org_a) != []
        assert control_db.list_technology_events_for_organization(org_b) == []
        assert control_db.list_assets_running_technology(org_b, "nginx") == []
