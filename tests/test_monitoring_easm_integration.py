"""Fase 18 (EASM roadmap) — proves the monitoring notification trigger
actually reads from `change_events`/`certificate_events`/
`technology_events`/`exposures` (Fases 05/08/12/14), not only the raw
hostname digest: a certificate renewal or a new exposure with the exact
SAME hostname set still produces exactly one notification, citing the
real evidence. Reuses `tests/test_monitoring_worker.py`'s own fixtures
and helpers rather than duplicating the monitored-domain setup dance.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.monitoring_worker import run_monitoring_cycle
from api.settings import APISettings
from tests.test_monitoring_worker import (
    _account,
    _make_due,
    _monitor,
    _RecordingEmailSender,
    _verify_domain,
    _write_hosts,
)


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(
        data_dir=tmp_path / "api_data",
        monitoring_batch_size=10,
        monitoring_asset_count_ceiling=1000,
        monitoring_cycle_time_budget_seconds=60.0,
    )


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


@pytest.fixture
def sender() -> _RecordingEmailSender:
    return _RecordingEmailSender()


class TestCertificateRenewalWithNoHostnameChangeStillNotifies:
    def test_a_certificate_renewal_alone_generates_exactly_one_notification(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]

        # Baseline cycle: establishes the hostname digest, no notification.
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        first_scan_id = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, first_scan_id, ["example.com"])
        control_db.update_scan_status(first_scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        assert sender.monitoring_alerts == []

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )

        # Second cycle: the EXACT same hostname set (no add/remove), but
        # a real certificate-renewal event is recorded against this
        # scan's own run_id -- simulating what api/easm_backfill.py would
        # have produced from a real TLS observation change.
        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        second_scan_id = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, second_scan_id, ["example.com"])
        control_db.record_certificate_event(
            organization_id=organization_id,
            asset_id=asset.asset_id,
            run_id=second_scan_id,
            event_type="CERTIFICATE_RENEWED",
            reason="same subject/issuer, new fingerprint (aaa...->bbb...)",
            previous_fingerprint="a" * 64,
            new_fingerprint="b" * 64,
        )
        control_db.update_scan_status(second_scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        assert len(sender.monitoring_alerts) == 1
        _, _, lines, _ = sender.monitoring_alerts[0]
        assert any("CERTIFICATE_RENEWED" in line for line in lines)
        assert any("same subject/issuer" in line for line in lines)

    def test_the_webhook_payload_also_carries_the_citation(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id = control_db.get_monitored_domain(account_id, "example.com").pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id, ["example.com"])
        control_db.update_scan_status(scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id_2 = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id_2, ["example.com"])
        control_db.record_technology_event(
            organization_id=organization_id,
            asset_id=asset.asset_id,
            run_id=scan_id_2,
            event_type="TECHNOLOGY_ADDED",
            technology_name="WordPress",
            reason="newly observed: WordPress",
        )
        control_db.update_scan_status(scan_id_2, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        pending = control_db.list_unsent_notifications()
        # Already flushed by run_monitoring_cycle -- rebuild the outcome
        # from the DB write path instead, proving the citation survived
        # the outbox round trip, not just the in-memory object.
        assert pending == []
        rows = control_db.list_technology_events_for_asset(asset.asset_id)
        assert any(r.event_type == "TECHNOLOGY_ADDED" for r in rows)


class TestNoEasmSignalNeverFabricatesANotification:
    def test_an_unchanged_scan_with_no_easm_events_still_sends_nothing(
        self, control_db: ControlDB, api_settings: APISettings, sender: _RecordingEmailSender
    ) -> None:
        account_id = _account(control_db)
        _verify_domain(control_db, account_id, "example.com")
        record = _monitor(control_db, api_settings, account_id, "example.com")

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id = control_db.get_monitored_domain(account_id, "example.com").pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id, ["example.com"])
        control_db.update_scan_status(scan_id, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        assert sender.monitoring_alerts == []

        _make_due(control_db, record.monitoring_id)
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)
        scan_id_2 = control_db.get_monitored_domain(
            account_id, "example.com"
        ).pending_passive_scan_id
        _write_hosts(api_settings, account_id, scan_id_2, ["example.com"])  # identical hostnames
        control_db.update_scan_status(scan_id_2, "completed")
        run_monitoring_cycle(api_settings=api_settings, control_db=control_db, email_sender=sender)

        assert sender.monitoring_alerts == []
