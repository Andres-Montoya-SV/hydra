"""Fase 05 (EASM roadmap) — the real, DB-backed half:
`detect_and_record_changes_for_organization` running against real
scans/assets/observations (Fases 02-04), including the fail-tolerance
and reappearance scenarios using genuine asset identity (Fase 03) rather
than fixtures standing in for it.

A "missed run" here is modeled as a real completed scan whose `Host`
simply carries no observation-worthy data for a given domain (an empty
`hosts` list for that AssetStore run) — a real, if minimal, stand-in for
a scan that ran and finished but genuinely found nothing for that
target this time (a timeout partway through discovery, a transient
resolver failure that dropped one domain from this cycle, etc.).
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.change_backfill import detect_and_record_changes_for_organization
from api.control_db import ControlDB
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, Port
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _run_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
    hosts: list[Host],
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
    for host in hosts:
        store.upsert_host(scan_id, host)
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


def _reconcile(control_db: ControlDB, api_settings: APISettings, organization_id: str) -> None:
    backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )


class TestNewChangedUnchangedAgainstRealData:
    def test_first_scan_produces_a_new_event(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        _reconcile(control_db, api_settings, organization_id)

        summary = detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        assert summary.change_events_recorded == 1

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_change_events_for_asset(asset.asset_id)
        assert len(events) == 1
        assert events[0].new_state == "new"
        assert events[0].previous_state is None

    def test_a_repeated_identical_observation_produces_no_new_event(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        for _ in range(3):
            _run_scan(
                control_db,
                api_settings,
                account_id=account_id,
                organization_id=organization_id,
                domain="example.com",
                hosts=[Host(domain="example.com", discovery_sources=["dnsx"])],
            )
        _reconcile(control_db, api_settings, organization_id)

        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_change_events_for_asset(asset.asset_id)
        # Only the initial NEW — the other two runs are identical.
        assert [e.new_state for e in events] == ["new"]

    def test_a_new_port_on_a_later_run_is_its_own_new_asset_not_a_change_to_the_domain(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """Adding a port doesn't change the DOMAIN asset's own observed
        facts (its `domain_resolved` evidence is unaffected by which
        ports exist) — it creates a genuinely NEW `port` asset instead,
        never a `changed` event on the domain."""
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[
                Host(
                    domain="example.com",
                    ports=[Port(host="example.com", port=22, source="naabu")],
                )
            ],
        )
        _reconcile(control_db, api_settings, organization_id)

        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        domain_asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        assert [
            e.new_state for e in control_db.list_change_events_for_asset(domain_asset.asset_id)
        ] == ["new"]

        port_asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="port",
            identity_key="port:example.com:22:tcp",
        )
        assert port_asset is not None
        assert [
            e.new_state for e in control_db.list_change_events_for_asset(port_asset.asset_id)
        ] == ["new"]

    def test_the_domains_own_evidence_changing_produces_a_changed_event_on_the_domain(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3b@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com", discovery_sources=["dnsx"])],
        )
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com", discovery_sources=["dnsx", "httpx"])],
        )
        _reconcile(control_db, api_settings, organization_id)

        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        domain_asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_change_events_for_asset(domain_asset.asset_id)
        assert [e.new_state for e in events] == ["new", "changed"]


class TestFailToleranceWithRealScans:
    def test_a_real_failed_scan_that_observed_nothing_does_not_mark_a_real_asset_disappeared(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        # Second scan against the SAME target genuinely completed but
        # found nothing (a real, if minimal, stand-in for a transient
        # failure) — a SINGLE miss.
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[],
        )
        # Third scan recovers, observing the SAME asset again.
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        _reconcile(control_db, api_settings, organization_id)

        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        events = control_db.list_change_events_for_asset(asset.asset_id)
        assert "disappeared" not in [e.new_state for e in events]
        assert control_db.get_current_lifecycle_state_for_asset(asset.asset_id) == "new"

    def test_two_consecutive_real_failed_scans_do_mark_the_asset_disappeared_then_reappeared(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="gone.example.com")],
        )
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[],
        )
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[],
        )
        _reconcile(control_db, api_settings, organization_id)
        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:gone.example.com",
        )
        assert control_db.get_current_lifecycle_state_for_asset(asset.asset_id) == "disappeared"

        # A later scan observes it again — genuine reappearance, using
        # the SAME asset identity (Fase 03), never a new asset row.
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="gone.example.com")],
        )
        _reconcile(control_db, api_settings, organization_id)
        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        same_asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:gone.example.com",
        )
        assert same_asset.asset_id == asset.asset_id
        assert control_db.get_current_lifecycle_state_for_asset(asset.asset_id) == "reappeared"
        states = [e.new_state for e in control_db.list_change_events_for_asset(asset.asset_id)]
        assert states == ["new", "disappeared", "reappeared"]


class TestQueryByRun:
    def test_all_changes_detected_in_one_run_are_retrievable_by_run_id(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner6@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        scan_id = _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[
                Host(domain="a.example.com"),
                Host(domain="b.example.com"),
            ],
        )
        _reconcile(control_db, api_settings, organization_id)
        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        events = control_db.list_change_events_for_run(scan_id)
        assert len(events) == 2
        assert {e.new_state for e in events} == {"new"}


class TestDeterminismAndIdempotency:
    def test_running_the_backfill_twice_produces_the_same_final_state_and_no_duplicate_events(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner7@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[],
        )
        _reconcile(control_db, api_settings, organization_id)

        first = detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )
        second = detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        assert second.change_events_recorded == 0
        assert second.change_events_already_present == first.change_events_recorded

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        assert (
            len(control_db.list_change_events_for_asset(asset.asset_id))
            == first.change_events_recorded
        )


class TestOrganizationIsolation:
    """The same adversarial pattern required (and already proven) for
    Fase 03/04, reapplied to change events: two organizations observing
    an identical shared host must never end up sharing a change_event
    row, even though both independently derive the exact same digests."""

    def test_two_organizations_scanning_the_same_shared_host_never_share_change_events(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="consultant@example.com")
        org_a, _role = control_db.list_organizations_for_account(account_id)[0]
        org_b = control_db.create_organization(name="Client B Inc")
        control_db.add_account_organization_role(
            account_id=account_id, organization_id=org_b, role="owner"
        )

        shared_host = Host(domain="shared-cdn.example.net")
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=org_a,
            domain="shared-cdn.example.net",
            hosts=[shared_host],
        )
        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=org_b,
            domain="shared-cdn.example.net",
            hosts=[shared_host],
        )
        _reconcile(control_db, api_settings, org_a)
        _reconcile(control_db, api_settings, org_b)

        detect_and_record_changes_for_organization(control_db=control_db, organization_id=org_a)
        detect_and_record_changes_for_organization(control_db=control_db, organization_id=org_b)

        asset_a = control_db.get_asset_by_identity(
            organization_id=org_a, asset_type="domain", identity_key="domain:shared-cdn.example.net"
        )
        asset_b = control_db.get_asset_by_identity(
            organization_id=org_b, asset_type="domain", identity_key="domain:shared-cdn.example.net"
        )
        assert asset_a.asset_id != asset_b.asset_id

        events_a = control_db.list_change_events_for_asset(asset_a.asset_id)
        events_b = control_db.list_change_events_for_asset(asset_b.asset_id)
        assert len(events_a) == 1
        assert len(events_b) == 1
        assert events_a[0].change_event_id != events_b[0].change_event_id
        assert events_a[0].organization_id == org_a
        assert events_b[0].organization_id == org_b

    def test_a_scan_for_an_unrelated_domain_in_the_same_organization_is_never_counted_as_a_miss(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """The false-disappearance risk `host_for_asset`/
        `domain_is_covered` scoping exists to prevent: an organization
        monitoring TWO distinct domains must not have a scan of one
        domain count as a "missed run" for an asset that only ever lived
        under the other."""
        account_id = control_db.create_account(email="owner8@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="first-target.example",
            hosts=[Host(domain="first-target.example")],
        )
        # Many scans of a COMPLETELY different target — none of these
        # are relevant runs for the first-target.example asset, so they
        # must never accumulate as misses against it.
        for _ in range(5):
            _run_scan(
                control_db,
                api_settings,
                account_id=account_id,
                organization_id=organization_id,
                domain="second-target.example",
                hosts=[Host(domain="second-target.example")],
            )
        _reconcile(control_db, api_settings, organization_id)

        detect_and_record_changes_for_organization(
            control_db=control_db, organization_id=organization_id
        )

        first_asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:first-target.example",
        )
        assert control_db.get_current_lifecycle_state_for_asset(first_asset.asset_id) == "new"
