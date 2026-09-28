"""Productization Phase 02 — the data-layer half of the Attack Surface
Inventory API: real SQL-level pagination/search/sort for
`ControlDB.list_assets_for_organization` (it had none before this phase
— `api/routers/easm.py`'s own docstring claimed otherwise, incorrectly),
plus the two new "current state" derivations
(`get_current_certificate_for_asset`, reusing the exact same
"latest run wins" pattern `list_current_technologies_for_asset` already
established) and the first real caller of the already-written
`list_identifiers_for_asset`.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
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


def _run_completed_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
    hosts: list[Host],
    started_at: str = "2026-01-01T00:00:00+00:00",
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
    store.create_run(ScanRun(run_id=scan_id, started_at=started_at))
    for host in hosts:
        store.upsert_host(scan_id, host)
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


def _tls_cert(
    *, domain: str, issuer: str, fingerprint_char: str, year: str, sans: list[str]
) -> TlsCertificate:
    return TlsCertificate(
        host=domain,
        issuer=issuer,
        subject=f"CN={domain}",
        sans=sans,
        not_before=f"{year}-01-01",
        not_after=f"{year}-04-01",
        fingerprint_sha256=fingerprint_char * 64,
    )


def _seed_organization_with_domains(
    control_db: ControlDB, api_settings: APISettings, *, domains: list[str], email: str
) -> str:
    account_id = control_db.create_account(email=email)
    organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
    for domain in domains:
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain=domain,
            hosts=[Host(domain=domain, discovery_sources=["dnsx"])],
        )
    backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    return organization_id


class TestAssetListingPaginationSearchSort:
    def test_limit_and_offset_are_real_sql_level_pagination(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        organization_id = _seed_organization_with_domains(
            control_db,
            api_settings,
            domains=[f"host{i}.example.com" for i in range(5)],
            email="page@example.com",
        )

        page1 = control_db.list_assets_for_organization(organization_id, limit=2, offset=0)
        page2 = control_db.list_assets_for_organization(organization_id, limit=2, offset=2)
        page3 = control_db.list_assets_for_organization(organization_id, limit=2, offset=4)
        assert len(page1) == 2
        assert len(page2) == 2
        assert len(page3) == 1
        all_ids = {a.asset_id for a in page1 + page2 + page3}
        assert len(all_ids) == 5  # no duplicates, no gaps across pages

    def test_a_limit_of_none_returns_every_row_unbounded_for_internal_callers(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """The exact backward-compatibility guarantee every pre-existing
        internal caller (backfills, list_assets_running_technology)
        depends on — this phase's new limit/offset parameters must never
        silently truncate them."""
        organization_id = _seed_organization_with_domains(
            control_db,
            api_settings,
            domains=[f"nolimit{i}.example.com" for i in range(6)],
            email="nolimit@example.com",
        )

        rows = control_db.list_assets_for_organization(organization_id)
        assert len(rows) == 6

    def test_q_matches_a_case_insensitive_substring_of_identity_key(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        organization_id = _seed_organization_with_domains(
            control_db,
            api_settings,
            domains=["www.example.com", "api.example.com", "unrelated.test"],
            email="search@example.com",
        )

        matches = control_db.list_assets_for_organization(organization_id, q="EXAMPLE")
        assert {a.identity_key for a in matches} == {
            "domain:www.example.com",
            "domain:api.example.com",
        }

    def test_q_treats_percent_and_underscore_as_literal_characters(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """A LIKE search's own wildcard characters must not let a client
        accidentally (or deliberately) turn `q` into a broader pattern
        match than "this literal substring" — `100%.example.com` should
        only match itself, never act as `100<anything>.example.com`."""
        organization_id = _seed_organization_with_domains(
            control_db,
            api_settings,
            domains=["100x.example.com"],
            email="escape@example.com",
        )

        literal_percent = control_db.list_assets_for_organization(organization_id, q="100%")
        assert literal_percent == []

    def test_sort_and_order_are_respected(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="sort@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="first.example.com",
            hosts=[Host(domain="first.example.com", discovery_sources=["dnsx"])],
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="second.example.com",
            hosts=[Host(domain="second.example.com", discovery_sources=["dnsx"])],
            started_at="2026-02-01T00:00:00+00:00",
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        ascending = control_db.list_assets_for_organization(
            organization_id, sort="first_seen_at", order="asc"
        )
        descending = control_db.list_assets_for_organization(
            organization_id, sort="first_seen_at", order="desc"
        )
        assert [a.identity_key for a in ascending] == [
            "domain:first.example.com",
            "domain:second.example.com",
        ]
        assert [a.identity_key for a in descending] == list(
            reversed([a.identity_key for a in ascending])
        )

    def test_an_unlisted_sort_column_is_rejected(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        organization_id = _seed_organization_with_domains(
            control_db, api_settings, domains=["x.example.com"], email="badsort@example.com"
        )
        with pytest.raises(ValueError):
            control_db.list_assets_for_organization(organization_id, sort="asset_type")

    def test_an_invalid_order_is_rejected(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        organization_id = _seed_organization_with_domains(
            control_db, api_settings, domains=["x.example.com"], email="badorder@example.com"
        )
        with pytest.raises(ValueError):
            control_db.list_assets_for_organization(organization_id, order="sideways")


class TestCurrentCertificateForAsset:
    def test_returns_none_when_the_asset_has_never_had_a_certificate(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="nocert@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="nocert.example.com",
            hosts=[Host(domain="nocert.example.com", discovery_sources=["dnsx"])],
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:nocert.example.com",
        )

        assert control_db.get_current_certificate_for_asset(asset.asset_id) is None

    def _seed_two_certificate_runs(
        self, control_db: ControlDB, api_settings: APISettings, *, domain: str
    ) -> tuple[str, str]:
        account_id = control_db.create_account(email="cert@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        old_cert = _tls_cert(
            domain=domain, issuer="Old CA", fingerprint_char="a", year="2025", sans=[domain]
        )
        new_cert = _tls_cert(
            domain=domain,
            issuer="New CA",
            fingerprint_char="b",
            year="2026",
            sans=[domain, f"www.{domain}"],
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain=domain,
            hosts=[Host(domain=domain, discovery_sources=["dnsx"], tls=old_cert)],
            started_at="2026-01-01T00:00:00+00:00",
        )
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain=domain,
            hosts=[Host(domain=domain, discovery_sources=["dnsx"], tls=new_cert)],
            started_at="2026-02-01T00:00:00+00:00",
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        return account_id, organization_id

    def test_returns_the_most_recent_runs_certificate_not_an_older_one(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        domain = "cert.example.com"
        _account_id, organization_id = self._seed_two_certificate_runs(
            control_db, api_settings, domain=domain
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key=f"domain:{domain}"
        )

        current = control_db.get_current_certificate_for_asset(asset.asset_id)
        assert current is not None
        assert current.fingerprint_sha256 == "b" * 64
        assert current.issuer == "New CA"
        assert set(current.sans) == {domain, f"www.{domain}"}


class TestAssetIdentifiers:
    def test_a_resolved_ip_is_recorded_as_an_identifier(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="ip@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        domain = "ip.example.com"
        _run_completed_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain=domain,
            hosts=[Host(domain=domain, discovery_sources=["dnsx"], ips=["203.0.113.9"])],
        )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key=f"domain:{domain}"
        )

        identifiers = control_db.list_identifiers_for_asset(asset.asset_id)
        assert [(i.identifier_type, i.identifier_value) for i in identifiers] == [
            ("ip", "203.0.113.9")
        ]
