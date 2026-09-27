"""Fase 12 (EASM roadmap) — the real, DB-backed half of RDAP enrichment:
`lookup_rdap_for_domain` running against real organizations, proving
`RDAP result != authorized target`: it only ever enriches an ALREADY
known asset, never creates one, and registration/entity data never
attributes ownership of anything.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from unittest.mock import patch

import pytest

import api.rdap_lookup as rdap_lookup
from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.rdap_lookup import lookup_rdap_for_domain
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host
from core.collection.rdap_client import RdapHop, RdapResult
from core.store import AssetStore, ScanRun

_REGISTRATION_BODY = {
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Acme Registrar"]]]}
    ],
    "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}],
}


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _seed_known_domain(
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
    store.upsert_host(scan_id, Host(domain=domain, discovery_sources=["dnsx"]))
    control_db.update_scan_status(scan_id, "completed")
    backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )


def _mock_rdap_success(body: dict) -> RdapResult:
    return RdapResult(
        hops=(
            RdapHop(
                url="https://rdap.org/domain/x", allowed=True, reason="allowed", status_code=200
            ),
        ),
        status_code=200,
        body=body,
        blocked=False,
    )


class TestRdapEnrichesOnlyAlreadyKnownAssets:
    def test_a_domain_not_already_known_is_never_created_as_an_asset_or_candidate(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]

        with patch.object(
            rdap_lookup, "fetch_rdap_domain", return_value=_mock_rdap_success(_REGISTRATION_BODY)
        ):
            summary = lookup_rdap_for_domain(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                domain="never-scanned.example.com",
            )

        assert summary.domain_was_known_asset is False
        assert summary.ingest is None
        assert control_db.list_assets_for_organization(organization_id) == []
        assert control_db.list_candidate_assets_for_organization(organization_id) == []

    def test_an_already_known_domain_gets_registration_evidence(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_known_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="known.example.com",
        )

        with patch.object(
            rdap_lookup, "fetch_rdap_domain", return_value=_mock_rdap_success(_REGISTRATION_BODY)
        ):
            summary = lookup_rdap_for_domain(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                domain="known.example.com",
            )

        assert summary.domain_was_known_asset is True
        assert summary.ingest is not None
        assert summary.ingest.observations_recorded_on_known_assets == 1
        assert summary.ingest.candidates_created == 0

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:known.example.com",
        )
        rdap_evidence = [
            o
            for o in control_db.list_observations_for_asset(asset.asset_id)
            if o.evidence.source == "RDAP"
        ]
        assert len(rdap_evidence) == 1
        assert "Acme Registrar" in rdap_evidence[0].evidence.detail
        assert rdap_evidence[0].evidence.confidence_class == "THIRD_PARTY_CURRENT"

    def test_a_blocked_rdap_lookup_records_nothing(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_known_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="blocked.example.com",
        )
        blocked_result = RdapResult(
            hops=(), status_code=None, body=None, blocked=True, blocked_reason="too_many_redirects"
        )
        with patch.object(rdap_lookup, "fetch_rdap_domain", return_value=blocked_result):
            summary = lookup_rdap_for_domain(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                domain="blocked.example.com",
            )
        assert summary.rdap_blocked is True
        assert summary.ingest is None

    def test_an_empty_rdap_response_records_nothing(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_known_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="empty-rdap.example.com",
        )
        with patch.object(rdap_lookup, "fetch_rdap_domain", return_value=_mock_rdap_success({})):
            summary = lookup_rdap_for_domain(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                domain="empty-rdap.example.com",
            )
        assert summary.ingest is None


class TestCrossOrganizationIsolation:
    def test_rdap_evidence_for_organization_a_never_appears_in_organization_b(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="orga@example.com")
        account_b = control_db.create_account(email="orgb@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]
        _seed_known_domain(
            control_db,
            api_settings,
            account_id=account_a,
            organization_id=org_a,
            domain="shared-name.example.com",
        )
        _seed_known_domain(
            control_db,
            api_settings,
            account_id=account_b,
            organization_id=org_b,
            domain="shared-name.example.com",
        )

        with patch.object(
            rdap_lookup, "fetch_rdap_domain", return_value=_mock_rdap_success(_REGISTRATION_BODY)
        ):
            lookup_rdap_for_domain(
                control_db=control_db,
                organization_id=org_a,
                account_id=account_a,
                domain="shared-name.example.com",
            )

        asset_a = control_db.get_asset_by_identity(
            organization_id=org_a,
            asset_type="domain",
            identity_key="domain:shared-name.example.com",
        )
        asset_b = control_db.get_asset_by_identity(
            organization_id=org_b,
            asset_type="domain",
            identity_key="domain:shared-name.example.com",
        )
        assert any(
            o.evidence.source == "RDAP"
            for o in control_db.list_observations_for_asset(asset_a.asset_id)
        )
        assert not any(
            o.evidence.source == "RDAP"
            for o in control_db.list_observations_for_asset(asset_b.asset_id)
        )
