"""Fase 03 (EASM roadmap) — the real, DB-backed half: `assets`/
`asset_identifiers` persistence (`api/control_db.py`) and the backfill
(`api/asset_backfill.py`) that replays an organization's real,
already-existing scan history through the pure reconciliation logic
tested in isolation in `tests/test_asset_identity.py`.

Every scan here writes REAL `Host` rows into a REAL, per-account
`AssetStore` (never a mock standing in for the recon pipeline's own
storage) — the same `core.store.AssetStore`/`api/tenancy.py::
account_db_path` any real scan actually uses.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _run_completed_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
    hosts: list[Host],
) -> str:
    """Creates a real scan row (organization-scoped, Fase 02) AND writes
    real `Host` rows into that account's real `AssetStore` under the
    same `scan_id` as the run_id — exactly the shape a genuine completed
    scan leaves behind, which is what `backfill_assets_for_organization`
    reads back."""
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


class TestBackfillAgainstRealRunHistory:
    def test_a_host_seen_in_two_runs_reconciles_to_one_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com", ips=["1.2.3.4"])],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com", ips=["1.2.3.4"])],
        )

        summary = backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        assert summary.scans_processed == 2
        assert summary.assets_created == 1
        assert summary.assets_touched == 1  # the second run re-observes the same asset

        assets = control_db.list_assets_for_organization(organization_id, asset_type="domain")
        assert len(assets) == 1
        assert assets[0].identity_key == "domain:example.com"

    def test_a_new_host_in_a_later_run_creates_a_second_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com"), Host(domain="new.example.com")],
        )

        summary = backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        assert summary.assets_created == 2
        assert summary.assets_touched == 1
        domains = {
            a.identity_key
            for a in control_db.list_assets_for_organization(organization_id, asset_type="domain")
        }
        assert domains == {"domain:example.com", "domain:new.example.com"}

    def test_reappearance_across_a_gap_run_does_not_duplicate_the_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """A host present in run 1, ABSENT from run 2 (e.g. a transient
        failure meant that scan simply never observed it), and present
        again in run 3 — must reconcile to exactly one asset row, never
        two."""
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="flaky.example.com")],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[],  # run 2 observed nothing for this domain
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="flaky.example.com")],
        )

        summary = backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        assert summary.assets_created == 1
        assert summary.assets_touched == 1  # only run 3 re-touches it; run 2 saw nothing
        assets = control_db.list_assets_for_organization(organization_id)
        assert [a.identity_key for a in assets] == ["domain:flaky.example.com"]

    def test_backfill_is_idempotent_if_run_a_second_time(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        assets = control_db.list_assets_for_organization(organization_id)
        assert len(assets) == 1

    def test_a_manually_sampled_asset_carries_the_right_evidence(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """The phase's own "verificar manualmente una muestra de los
        resultados" requirement, made concrete: pick one specific asset
        out of the backfill's output and check every field by hand
        against what was actually fed in."""
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        scan_id = _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="sampled.example.com",
            hosts=[Host(domain="sampled.example.com", ips=["9.9.9.9"])],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:sampled.example.com",
        )
        assert asset is not None
        assert asset.organization_id == organization_id
        assert asset.last_seen_run_id == scan_id

        identifiers = control_db.list_identifiers_for_asset(asset.asset_id)
        assert len(identifiers) == 1
        assert identifiers[0].identifier_type == "ip"
        assert identifiers[0].identifier_value == "9.9.9.9"


class TestCloudStorageBackfill:
    def test_cloud_bucket_is_a_cloud_storage_asset_not_a_domain(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="cloud-owner@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        scan_id = _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="example.com",
            hosts=[Host(domain="example.com")],
        )
        store = AssetStore(account_db_path(api_settings, account_id))
        store.record_cloud_resources(
            scan_id,
            [
                {
                    "provider": "s3",
                    "bucket": "example-assets",
                    "url": "https://example-assets.s3.amazonaws.com/",
                    "classification": "exists_private",
                    "exists": True,
                    "public_listable": False,
                    "status_code": 403,
                }
            ],
        )

        backfill_assets_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )

        cloud_assets = control_db.list_assets_for_organization(
            organization_id, asset_type="cloud_storage"
        )
        assert len(cloud_assets) == 1
        assert cloud_assets[0].identity_key == "cloud_storage:s3:example-assets"

        domains = control_db.list_assets_for_organization(
            organization_id, asset_type="domain"
        )
        assert {asset.identity_key for asset in domains} == {"domain:example.com"}

        observations = control_db.list_observations_for_asset(cloud_assets[0].asset_id)
        assert len(observations) == 1
        assert observations[0].observation_type == "cloud_storage_observed"

    def test_same_cloud_resource_across_runs_reconciles_to_one_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="cloud-history@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        for classification, public in (
            ("exists_private", False),
            ("public_listable", True),
        ):
            scan_id = _run_completed_scan(
                control_db,
                api_settings,
                account_id=account_id,
                organization_id=organization_id,
                domain="example.com",
                hosts=[Host(domain="example.com")],
            )
            AssetStore(account_db_path(api_settings, account_id)).record_cloud_resources(
                scan_id,
                [
                    {
                        "provider": "gcs",
                        "bucket": "example-assets",
                        "url": "https://storage.googleapis.com/example-assets",
                        "classification": classification,
                        "exists": True,
                        "public_listable": public,
                        "status_code": 200 if public else 403,
                    }
                ],
            )

        summary = backfill_assets_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )

        cloud_assets = control_db.list_assets_for_organization(
            organization_id, asset_type="cloud_storage"
        )
        assert len(cloud_assets) == 1
        assert cloud_assets[0].identity_key == "cloud_storage:gcs:example-assets"
        assert summary.assets_created == 2
        assert summary.assets_touched == 2


class TestCrossOrganizationIsolationIsAdversariallyProven:
    """The phase's own required adversarial case: two DIFFERENT
    organizations scan the SAME public host (a shared CDN case) — they
    must never end up sharing one `assets` row, even though the
    identity_key they each compute is byte-for-byte identical."""

    def test_two_organizations_scanning_the_same_shared_cdn_host_never_share_an_asset_row(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="consultant@example.com")
        org_a, _role = control_db.list_organizations_for_account(account_id)[0]
        org_b = control_db.create_organization(name="Client B Inc")
        control_db.add_account_organization_role(
            account_id=account_id, organization_id=org_b, role="owner"
        )

        shared_cdn_host = Host(domain="shared-cdn.example.net", ips=["198.51.100.7"])

        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=org_a,
            domain="shared-cdn.example.net",
            hosts=[shared_cdn_host],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=org_b,
            domain="shared-cdn.example.net",
            hosts=[shared_cdn_host],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=org_a
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=org_b
        )

        asset_a = control_db.get_asset_by_identity(
            organization_id=org_a, asset_type="domain", identity_key="domain:shared-cdn.example.net"
        )
        asset_b = control_db.get_asset_by_identity(
            organization_id=org_b, asset_type="domain", identity_key="domain:shared-cdn.example.net"
        )
        assert asset_a is not None
        assert asset_b is not None
        assert asset_a.asset_id != asset_b.asset_id
        assert asset_a.organization_id == org_a
        assert asset_b.organization_id == org_b

        # Neither organization's asset LIST leaks the other's row, even
        # though both describe "the same" real-world host.
        assets_a = {a.asset_id for a in control_db.list_assets_for_organization(org_a)}
        assets_b = {a.asset_id for a in control_db.list_assets_for_organization(org_b)}
        assert assets_a.isdisjoint(assets_b)

        # And the shared IP identifier is recorded independently on each
        # organization's own asset row — never merged into one.
        ids_a = control_db.list_identifiers_for_asset(asset_a.asset_id)
        ids_b = control_db.list_identifiers_for_asset(asset_b.asset_id)
        assert [i.identifier_value for i in ids_a] == ["198.51.100.7"]
        assert [i.identifier_value for i in ids_b] == ["198.51.100.7"]

    def test_two_organizations_under_different_accounts_are_equally_isolated(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """The simpler, non-consultant case — different accounts
        entirely — must be isolated too, not just the same-account
        multi-org case."""
        account_a = control_db.create_account(email="a@example.com")
        account_b = control_db.create_account(email="b@example.com")
        org_a, _role_a = control_db.list_organizations_for_account(account_a)[0]
        org_b, _role_b = control_db.list_organizations_for_account(account_b)[0]

        shared_host = Host(domain="shared.example.net", ips=["203.0.113.55"])
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_a,
            organization_id=org_a,
            domain="shared.example.net",
            hosts=[shared_host],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_b,
            organization_id=org_b,
            domain="shared.example.net",
            hosts=[shared_host],
        )

        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=org_a
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=org_b
        )

        asset_a = control_db.get_asset_by_identity(
            organization_id=org_a, asset_type="domain", identity_key="domain:shared.example.net"
        )
        asset_b = control_db.get_asset_by_identity(
            organization_id=org_b, asset_type="domain", identity_key="domain:shared.example.net"
        )
        assert asset_a is not None and asset_b is not None
        assert asset_a.asset_id != asset_b.asset_id
