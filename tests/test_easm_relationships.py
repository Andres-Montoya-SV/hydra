"""Fase 07 — organization-scoped, evidence-backed relationship graph."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_identity import ExistingAsset, ReconciliationDecision
from api.control_db import ControlDB
from api.relationship_backfill import backfill_relationships_for_organization
from api.relationship_identity import relationship_from_rows
from api.settings import APISettings
from api.tenancy import account_db_path
from core.intel.model import (
    CollectionStatus,
    ConfidenceBand,
    EntityType,
    Evidence,
    IntelEntity,
    Observation,
    Relationship,
    RelationshipType,
    ScopeStatus,
)
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _relationship_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    source: str = "domain:a.example.com",
    target: str = "domain:b.example.com",
    relationship_type: RelationshipType = RelationshipType.SHARES_IPV4,
    with_evidence: bool = True,
) -> str:
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain="example.com",
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))

    source_type = EntityType.DOMAIN if source.startswith("domain:") else EntityType.CERTIFICATE
    target_type = EntityType.DOMAIN if target.startswith("domain:") else EntityType.CERTIFICATE
    entities = {
        source: IntelEntity(
            entity_id=source,
            entity_type=source_type,
            key=source.split(":", 1)[1],
            scope_status=ScopeStatus.IN_SCOPE,
            collection_status=CollectionStatus.COLLECTED,
        ),
        target: IntelEntity(
            entity_id=target,
            entity_type=target_type,
            key=target.split(":", 1)[1],
            scope_status=ScopeStatus.IN_SCOPE,
            collection_status=CollectionStatus.COLLECTED,
        ),
    }
    observation = Observation(
        observation_id=f"obs-{scan_id}",
        entity_id=source,
        source="fixture",
        collector="fixture",
        run_id=scan_id,
        observed_at="2026-01-01T00:00:00+00:00",
    )
    evidence_id = f"evidence-{scan_id}" if with_evidence else ""
    evidence = (
        {
            evidence_id: Evidence(
                evidence_id=evidence_id,
                source="fixture",
                collector="fixture",
                observation_id=observation.observation_id,
                reason="shared signal",
                metadata={"signal": "203.0.113.9"},
                observed_at="2026-01-01T00:00:00+00:00",
            )
        }
        if with_evidence
        else {}
    )
    relationship = Relationship(
        relationship_id=f"rel-{scan_id}",
        source_entity=source,
        relationship_type=relationship_type,
        target_entity=target,
        confidence=ConfidenceBand.HIGH,
        strength="strong",
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-01T00:00:00+00:00",
        evidence_id=evidence_id,
        data={"signal": "203.0.113.9"},
    )

    class Snapshot:
        observations = [observation]
        indicators: list = []
        hypotheses: list = []
        collection_attempts: list = []

        def __init__(self) -> None:
            self.entities = entities
            self.evidence = evidence
            self.relationships = {relationship.relationship_id: relationship}

    store.persist_registry(scan_id, {}, intel=Snapshot())
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


class TestRelationshipNormalization:
    def test_missing_evidence_is_rejected(self) -> None:
        assert (
            relationship_from_rows(
                {
                    "source_entity": "domain:a.example.com",
                    "target_entity": "domain:b.example.com",
                    "relationship_type": "SHARES_IPV4",
                    "confidence": "HIGH",
                    "evidence_id": "ev-1",
                },
                None,
            )
            is None
        )

    def test_unknown_relationship_type_is_rejected(self) -> None:
        assert (
            relationship_from_rows(
                {
                    "source_entity": "domain:a.example.com",
                    "target_entity": "domain:b.example.com",
                    "relationship_type": "MAGIC_LINK",
                    "confidence": "HIGH",
                    "evidence_id": "ev-1",
                },
                {"evidence_id": "ev-1"},
            )
            is None
        )


class TestRelationshipBackfill:
    def test_same_edge_across_runs_is_one_cross_run_relationship(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="rel-owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _relationship_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
        )
        _relationship_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
        )

        summary = backfill_relationships_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        relationships = control_db.list_relationships_for_organization(organization_id)
        assert summary.relationships_created == 1
        assert summary.relationships_touched == 1
        assert summary.evidence_rows_recorded == 2
        assert len(relationships) == 1
        assert len(control_db.list_relationship_evidence(relationships[0].relationship_id)) == 2

    def test_certificate_endpoint_does_not_need_to_be_fabricated_as_asset(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="rel-cert@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        cert = "certificate:" + "a" * 64
        _relationship_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            target=cert,
            relationship_type=RelationshipType.PRESENTS_CERTIFICATE,
        )
        backfill_relationships_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        rel = control_db.list_relationships_for_organization(organization_id)[0]
        assert rel.target_entity == cert
        assert rel.target_asset_id is None

    def test_existing_domain_assets_are_linked_without_becoming_identity_rule(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="rel-assets@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        control_db.apply_asset_reconciliation(
            organization_id=organization_id,
            run_id="asset-seed",
            observed_at="2026-01-01T00:00:00+00:00",
            decisions=[
                ReconciliationDecision(
                    asset_id="asset-a",
                    asset_type="domain",
                    identity_key="domain:a.example.com",
                    is_new=True,
                    identifiers=(),
                ),
                ReconciliationDecision(
                    asset_id="asset-b",
                    asset_type="domain",
                    identity_key="domain:b.example.com",
                    is_new=True,
                    identifiers=(),
                ),
            ],
        )
        _relationship_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
        )
        backfill_relationships_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        rel = control_db.list_relationships_for_organization(organization_id)[0]
        assert rel.source_asset_id == "asset-a"
        assert rel.target_asset_id == "asset-b"

    def test_ungrounded_relationship_is_not_persisted(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="rel-ungrounded@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _relationship_scan(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            with_evidence=False,
        )
        summary = backfill_relationships_for_organization(
            control_db=control_db,
            api_settings=api_settings,
            organization_id=organization_id,
        )
        assert summary.ungrounded_relationships_skipped == 1
        assert control_db.list_relationships_for_organization(organization_id) == []

    def test_same_edge_in_two_organizations_is_never_shared(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="rel-a@example.com")
        account_b = control_db.create_account(email="rel-b@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]
        for account_id, organization_id in ((account_a, org_a), (account_b, org_b)):
            _relationship_scan(
                control_db,
                api_settings,
                account_id=account_id,
                organization_id=organization_id,
            )
            backfill_relationships_for_organization(
                control_db=control_db,
                api_settings=api_settings,
                organization_id=organization_id,
            )
        a = control_db.list_relationships_for_organization(org_a)[0]
        b = control_db.list_relationships_for_organization(org_b)[0]
        assert a.relationship_id != b.relationship_id
