"""Fase 10 (EASM roadmap) — the real, DB-backed half:
`ingest_external_observation_batch` running against real organizations/
assets (Fases 02-06), proving the phase's own required invariants:
`imported asset != authorized asset`, provenance survives normalization,
an old third-party observation never beats a newer direct one, and a
malicious/careless external source can never poison the graph across
organizations.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.external_observation import (
    ExternalObservationDraft,
    ObservationConfidenceClass,
    ObservationSource,
)
from api.external_observation_ingest import ingest_external_observation_batch
from api.observation_identity import OBSERVATION_TYPE_DOMAIN_RESOLVED
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


def _seed_real_scanned_domain(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
) -> None:
    """A REAL scan-discovered asset, via the exact Fase 03/04 backfill
    path — never a shortcut fixture standing in for it."""
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


class TestImportedAssetIsNeverAuthorized:
    """The phase's own required adversarial test."""

    def test_a_domain_only_ever_seen_via_import_becomes_a_candidate_never_an_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        summary = ingest_external_observation_batch(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            drafts=[
                ExternalObservationDraft(
                    candidate_type="DOMAIN",
                    normalized_value="never-scanned.example.com",
                    display_value="never-scanned.example.com",
                    observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
                    detail="found in an Nmap scan report",
                    source=ObservationSource.NMAP,
                    confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
                )
            ],
        )
        assert summary.candidates_created == 1
        assert summary.observations_recorded_on_known_assets == 0

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:never-scanned.example.com",
        )
        assert asset is None  # NEVER promoted to an asset just by being imported

        candidates = control_db.list_candidate_assets_for_organization(organization_id)
        assert len(candidates) == 1
        assert candidates[0].normalized_value == "never-scanned.example.com"
        assert candidates[0].authorization_status == "DENY"
        assert candidates[0].scope_status == "UNKNOWN"

        # And, per Fase 06's own already-proven guarantee: never reachable
        # by anything that feeds active scanning.
        assert control_db.get_verified_domains_for_account(account_id) == []
        assert (
            control_db.list_due_active_monitoring_page(
                due_before="2099-01-01T00:00:00+00:00", cursor=None, limit=100
            )
            == []
        )

    def test_an_existing_authorized_asset_receives_evidence_not_a_second_candidate(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """The other half of the same rule: a fact about something
        ALREADY known/authorized is ordinary corroborating evidence, not
        a candidate — Observed != Owned only restricts the UNKNOWN case."""
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _seed_real_scanned_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="known.example.com",
        )

        summary = ingest_external_observation_batch(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            drafts=[
                ExternalObservationDraft(
                    candidate_type="DOMAIN",
                    normalized_value="known.example.com",
                    display_value="known.example.com",
                    observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
                    detail="also seen in RDAP",
                    source=ObservationSource.RDAP,
                    confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
                )
            ],
        )
        assert summary.observations_recorded_on_known_assets == 1
        assert summary.candidates_created == 0
        assert control_db.list_candidate_assets_for_organization(organization_id) == []


class TestProvenanceSurvivesNormalization:
    def test_source_and_confidence_class_are_preserved_on_the_evidence_row(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _seed_real_scanned_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="traced.example.com",
        )

        ingest_external_observation_batch(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            drafts=[
                ExternalObservationDraft(
                    candidate_type="DOMAIN",
                    normalized_value="TRACED.example.com.",  # deliberately unnormalized input
                    display_value="TRACED.example.com.",
                    observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
                    detail="customer-provided inventory entry",
                    source=ObservationSource.CUSTOMER_IMPORT,
                    confidence_class=ObservationConfidenceClass.CUSTOMER_SUPPLIED,
                )
            ],
            raw_artifact_reference="s3://imports/customer-inventory-2026-09-26.csv",
        )

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:traced.example.com",
        )
        results = control_db.list_observations_for_asset(asset.asset_id)
        imported = [r for r in results if r.evidence.source == "CUSTOMER_IMPORT"]
        assert len(imported) == 1
        assert imported[0].evidence.confidence_class == "CUSTOMER_SUPPLIED"
        assert imported[0].evidence.detail == "customer-provided inventory entry"

        batches = control_db.list_observation_batches_for_organization(organization_id)
        assert len(batches) == 1
        assert batches[0].source == "CUSTOMER_IMPORT"
        assert batches[0].raw_artifact_reference == "s3://imports/customer-inventory-2026-09-26.csv"
        assert batches[0].account_id == account_id


class TestOldThirdPartyNeverBeatsNewerDirectObservation:
    def test_current_evidence_prefers_hydras_own_direct_observation(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        _seed_real_scanned_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="contested.example.com",
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id,
            asset_type="domain",
            identity_key="domain:contested.example.com",
        )

        # A THIRD-PARTY import arrives, reporting a DIFFERENT fact about
        # the exact same observation_type.
        ingest_external_observation_batch(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            drafts=[
                ExternalObservationDraft(
                    candidate_type="DOMAIN",
                    normalized_value="contested.example.com",
                    display_value="contested.example.com",
                    observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
                    detail="stale third-party feed entry",
                    source=ObservationSource.EXTERNAL_INTELLIGENCE,
                    confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
                )
            ],
        )

        current = control_db.current_evidence_for_asset_and_type(
            organization_id=organization_id,
            asset_id=asset.asset_id,
            observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
        )
        assert current is not None
        assert current.confidence_class == "DIRECT_CURRENT"
        assert current.source == "dnsx"  # Hydra's own real scan evidence

        # And nothing was deleted — the third-party evidence still exists
        # in full history, just not chosen as "current."
        all_evidence_sources = {
            r.evidence.source for r in control_db.list_observations_for_asset(asset.asset_id)
        }
        assert all_evidence_sources == {"dnsx", "EXTERNAL_INTELLIGENCE"}


class TestExternalSourceCannotPoisonAnotherOrganization:
    def test_importing_into_organization_a_never_appears_in_organization_b(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="orga@example.com")
        account_b = control_db.create_account(email="orgb@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]

        ingest_external_observation_batch(
            control_db=control_db,
            organization_id=org_a,
            account_id=account_a,
            drafts=[
                ExternalObservationDraft(
                    candidate_type="DOMAIN",
                    normalized_value="shared-name.example.com",
                    display_value="shared-name.example.com",
                    observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
                    detail="imported for org A",
                    source=ObservationSource.RDAP,
                    confidence_class=ObservationConfidenceClass.THIRD_PARTY_CURRENT,
                )
            ],
        )

        assert control_db.list_candidate_assets_for_organization(org_a) != []
        assert control_db.list_candidate_assets_for_organization(org_b) == []
        assert control_db.list_observation_batches_for_organization(org_b) == []

    def test_a_batch_requires_at_least_one_observation(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        with pytest.raises(ValueError):
            ingest_external_observation_batch(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                drafts=[],
            )
