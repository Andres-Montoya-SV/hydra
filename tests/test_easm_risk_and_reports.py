"""Fase 21 (EASM roadmap) — the real, DB-backed half of risk scoring and
report-exposure integration: `ControlDB.risk_factors_for_exposure` and
`core/client_report/exposure_report.py::exposure_history_report_data`
running against real, scan-backed organizations.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.control_db import ControlDB
from api.easm_backfill import run_easm_backfill_for_organization
from api.exposure_identity import exposure_from_finding
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host
from core.client_report.exposure_report import exposure_history_report_data
from core.risk_scoring import RiskLevel, classify_exposure_risk
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _seed_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str = "example.com",
) -> str:
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
    store.upsert_host(scan_id, Host(domain=domain, discovery_sources=["dnsx"]))
    control_db.update_scan_status(scan_id, "completed")
    run_easm_backfill_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    return scan_id


def _real_scan_row(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str = "example.com",
) -> str:
    """`upsert_exposure` validates `run_id` against a real `scans` row
    belonging to this account/organization -- a made-up run_id string is
    rejected, so each simulated confirmation run needs its own real row."""
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain=domain,
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


class TestRiskFactorsForExposure:
    def test_a_fresh_high_severity_exposure_on_verified_scope_is_high_not_escalated(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        scan_id = _seed_scan(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        control_db.create_domain_verification(
            account_id=account_id, domain="example.com", token="tok"  # noqa: S106
        )
        record = control_db.get_all_verifications_for_account(account_id)[0]
        control_db.mark_verification_succeeded(
            record.verification_id,
            method="dns_txt",
            verified_at="2026-01-01T00:00:00+00:00",
            expires_at="2099-01-01T00:00:00+00:00",
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "admin-exposed",
                "severity": "high",
                "source": "nuclei",
                "url": "https://example.com/admin",
                "name": "Admin exposed",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        exposure_id, _, _ = control_db.upsert_exposure(
            organization_id=organization_id,
            account_id=account_id,
            run_id=scan_id,
            finding_id=1,
            draft=draft,
            observed_at="2026-01-01T00:00:00+00:00",
        )

        factors = control_db.risk_factors_for_exposure(
            organization_id, exposure_id, now="2026-01-03T00:00:00+00:00"
        )
        assert factors is not None
        assert factors.severity == "high"
        assert factors.domain_verified is True
        assert factors.days_open == 2
        assert factors.related_to_critical_asset is False

        classification = classify_exposure_risk(factors)
        assert classification.level == RiskLevel.HIGH

    def test_an_old_unresolved_exposure_escalates(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        scan_id = _seed_scan(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "weak-cipher",
                "severity": "low",
                "source": "sslyze",
                "url": "https://example.com",
                "name": "Weak cipher",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        exposure_id, _, _ = control_db.upsert_exposure(
            organization_id=organization_id,
            account_id=account_id,
            run_id=scan_id,
            finding_id=1,
            draft=draft,
            observed_at="2020-01-01T00:00:00+00:00",
        )
        factors = control_db.risk_factors_for_exposure(
            organization_id, exposure_id, now="2026-01-01T00:00:00+00:00"
        )
        assert factors is not None
        classification = classify_exposure_risk(factors)
        assert classification.level != RiskLevel.LOW  # escalated past its low base severity
        assert any("day(s)" in r for r in classification.reasons)

    def test_a_resolved_exposure_has_zero_days_open(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        scan_id = _seed_scan(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "old-issue",
                "severity": "medium",
                "source": "nuclei",
                "url": "https://example.com",
                "name": "Old issue",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        exposure_id, _, _ = control_db.upsert_exposure(
            organization_id=organization_id,
            account_id=account_id,
            run_id=scan_id,
            finding_id=1,
            draft=draft,
            observed_at="2020-01-01T00:00:00+00:00",
        )
        control_db.resolve_exposure(
            organization_id=organization_id,
            exposure_id=exposure_id,
            resolved_at="2020-02-01T00:00:00+00:00",
            resolution_reason="fixed",
        )
        factors = control_db.risk_factors_for_exposure(
            organization_id, exposure_id, now="2026-01-01T00:00:00+00:00"
        )
        assert factors is not None
        assert factors.days_open == 0

    def test_unknown_exposure_id_returns_none(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        assert control_db.risk_factors_for_exposure(organization_id, "does-not-exist") is None


class TestExposureReportShowsHistoryAcrossRuns:
    def test_five_runs_confirming_the_same_exposure_show_full_history_not_just_current_state(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_scan(control_db, api_settings, account_id=account_id, organization_id=organization_id)
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "admin-exposed",
                "severity": "high",
                "source": "nuclei",
                "url": "https://example.com/admin",
                "name": "Admin exposed",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        exposure_id = None
        for i in range(5):
            run_id = _real_scan_row(
                control_db, api_settings, account_id=account_id, organization_id=organization_id
            )
            exposure_id, _, _ = control_db.upsert_exposure(
                organization_id=organization_id,
                account_id=account_id,
                run_id=run_id,
                finding_id=1,
                draft=draft,
                observed_at=f"2026-01-0{i + 1}T00:00:00+00:00",
            )

        report = exposure_history_report_data(control_db, organization_id)
        assert len(report) == 1
        entry = report[0]
        assert entry.exposure_id == exposure_id
        assert len(entry.history) == 5  # every confirmation, not just the latest
        assert entry.risk_level in {"low", "medium", "high", "critical"}
        assert entry.risk_reasons  # never a bare label with no explanation

    def test_report_reflects_resolution_and_reappearance_in_history(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner6@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        scan_id = _seed_scan(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "admin-exposed",
                "severity": "high",
                "source": "nuclei",
                "url": "https://example.com/admin",
                "name": "Admin exposed",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        exposure_id, _, _ = control_db.upsert_exposure(
            organization_id=organization_id,
            account_id=account_id,
            run_id=scan_id,
            finding_id=1,
            draft=draft,
            observed_at="2026-01-01T00:00:00+00:00",
        )
        control_db.resolve_exposure(
            organization_id=organization_id,
            exposure_id=exposure_id,
            resolved_at="2026-01-02T00:00:00+00:00",
            resolution_reason="patched",
        )
        reappear_run_id = _real_scan_row(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        control_db.upsert_exposure(
            organization_id=organization_id,
            account_id=account_id,
            run_id=reappear_run_id,
            finding_id=1,
            draft=draft,
            observed_at="2026-01-03T00:00:00+00:00",
        )

        report = exposure_history_report_data(control_db, organization_id)
        entry = next(e for e in report if e.exposure_id == exposure_id)
        event_types = [event.event_type for event in entry.history]
        assert "observed" in event_types
        assert "resolved" in event_types
        assert "reopened" in event_types
        assert entry.status == "reopened"

    def test_report_never_leaks_across_organizations(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="orga@example.com")
        account_b = control_db.create_account(email="orgb@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]
        scan_id = _seed_scan(control_db, api_settings, account_id=account_a, organization_id=org_a)
        asset = control_db.get_asset_by_identity(
            organization_id=org_a, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "admin-exposed",
                "severity": "high",
                "source": "nuclei",
                "url": "https://example.com/admin",
                "name": "Admin exposed",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        control_db.upsert_exposure(
            organization_id=org_a,
            account_id=account_a,
            run_id=scan_id,
            finding_id=1,
            draft=draft,
            observed_at="2026-01-01T00:00:00+00:00",
        )

        assert exposure_history_report_data(control_db, org_a) != []
        assert exposure_history_report_data(control_db, org_b) == []
