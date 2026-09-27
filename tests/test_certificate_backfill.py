"""Fase 12 (EASM roadmap) — the real, DB-backed half of certificate event
detection: `detect_certificate_events_for_organization` running against
real scan-backed domain assets, proving idempotency (replaying the
backfill never duplicates events) and organization isolation.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.certificate_backfill import detect_certificate_events_for_organization
from api.certificate_events import CertificateEventType
from api.control_db import ControlDB
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, TlsCertificate
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _run_scan_with_cert(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
    cert: TlsCertificate,
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
    store.upsert_host(scan_id, Host(domain=domain, discovery_sources=["dnsx"], tls=cert))
    control_db.update_scan_status(scan_id, "completed")
    backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )


def _cert(fingerprint: str, **overrides: object) -> TlsCertificate:
    base = dict(
        host="example.com",
        issuer="Let's Encrypt",
        subject="CN=example.com",
        sans=["example.com"],
        not_before="2026-01-01",
        not_after="2026-04-01",
        fingerprint_sha256=fingerprint,
    )
    base.update(overrides)
    return TlsCertificate(**base)  # type: ignore[arg-type]


class TestCertificateEventDetection:
    def test_first_scan_produces_a_first_seen_event(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=_cert("a" * 64),
            started_at="2026-01-01T00:00:00+00:00",
        )
        summary = detect_certificate_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert summary.domain_assets_processed == 1
        assert summary.events_recorded == 1

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_certificate_events_for_asset(asset.asset_id)
        assert [e.event_type for e in events] == [CertificateEventType.FIRST_SEEN.value]

    def test_a_renewed_certificate_across_two_scans_is_detected(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=_cert("a" * 64),
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=_cert("b" * 64, not_after="2026-07-01"),
            started_at="2026-04-01T00:00:00+00:00",
        )
        summary = detect_certificate_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert summary.events_recorded == 2  # FIRST_SEEN + RENEWED

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_certificate_events_for_asset(asset.asset_id)
        assert {e.event_type for e in events} == {
            CertificateEventType.FIRST_SEEN.value,
            CertificateEventType.RENEWED.value,
        }

    def test_running_the_backfill_twice_never_duplicates_events(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=_cert("a" * 64),
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=_cert("b" * 64),
            started_at="2026-04-01T00:00:00+00:00",
        )
        first = detect_certificate_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        second = detect_certificate_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert second.events_recorded == 0
        assert second.events_already_present == first.events_recorded

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        assert (
            len(control_db.list_certificate_events_for_asset(asset.asset_id))
            == first.events_recorded
        )

    def test_an_unchanged_certificate_across_runs_produces_no_second_event(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        cert = _cert("a" * 64)
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=cert,
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_scan_with_cert(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            cert=cert,
            started_at="2026-02-01T00:00:00+00:00",
        )
        summary = detect_certificate_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert summary.events_recorded == 1  # only FIRST_SEEN -- the repeat is the identical fact

    def test_organizations_with_no_certificate_observations_are_skipped_cleanly(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        summary = detect_certificate_events_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert summary.domain_assets_processed == 0
        assert summary.events_recorded == 0
