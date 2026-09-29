"""Productization Phase 03 — the first API surface over Fase 07's
relationship graph: `GET /organizations/{id}/relationships`,
`.../relationships/{id}/evidence` (the "why are these two entities
related" answer), and `.../assets/{id}/relationships` (the asset-centric
neighborhood view, reusing `ControlDB.relationship_neighborhood`
verbatim). Seeding follows `tests/test_easm_relationships.py`'s own
established pattern exactly.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi.testclient import TestClient

from api.control_db import ControlDB
from api.relationship_backfill import backfill_relationships_for_organization
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


def _intel_entity(entity_id: str) -> IntelEntity:
    entity_type = EntityType.DOMAIN if entity_id.startswith("domain:") else EntityType.CERTIFICATE
    return IntelEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        key=entity_id.split(":", 1)[1],
        scope_status=ScopeStatus.IN_SCOPE,
        collection_status=CollectionStatus.COLLECTED,
    )


def _relationship_snapshot(
    *, scan_id: str, source: str, target: str, relationship_type: RelationshipType
):
    observation = Observation(
        observation_id=f"obs-{scan_id}",
        entity_id=source,
        source="fixture",
        collector="fixture",
        run_id=scan_id,
        observed_at="2026-01-01T00:00:00+00:00",
    )
    evidence_id = f"evidence-{scan_id}"
    evidence = Evidence(
        evidence_id=evidence_id,
        source="fixture",
        collector="fixture",
        observation_id=observation.observation_id,
        reason="shared signal",
        metadata={"signal": "203.0.113.9"},
        observed_at="2026-01-01T00:00:00+00:00",
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
            self.entities = {source: _intel_entity(source), target: _intel_entity(target)}
            self.evidence = {evidence_id: evidence}
            self.relationships = {relationship.relationship_id: relationship}

    return Snapshot()


def _relationship_scan(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    source: str = "domain:a.example.com",
    target: str = "domain:b.example.com",
    relationship_type: RelationshipType = RelationshipType.SHARES_IPV4,
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
    snapshot = _relationship_snapshot(
        scan_id=scan_id, source=source, target=target, relationship_type=relationship_type
    )
    store.persist_registry(scan_id, {}, intel=snapshot)
    control_db.update_scan_status(scan_id, "completed")
    return scan_id


def _seed_org_with_one_relationship(client: TestClient, *, email: str) -> tuple[str, str, str]:
    """Returns (api_key, organization_id, relationship_id)."""
    account = client.post("/accounts", json={"email": email}).json()
    api_key = account["api_key"]
    db = client.app.state.control_db
    api_settings: APISettings = client.app.state.api_settings
    organization_id, _ = db.list_organizations_for_account(account["account_id"])[0]
    _relationship_scan(
        db, api_settings, account_id=account["account_id"], organization_id=organization_id
    )
    backfill_relationships_for_organization(
        control_db=db, api_settings=api_settings, organization_id=organization_id
    )
    relationship = db.list_relationships_for_organization(organization_id)[0]
    return api_key, organization_id, relationship.relationship_id


class TestListRelationships:
    def test_lists_a_real_relationship_with_structured_data(self, tmp_path: Path) -> None:
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, org, relationship_id = _seed_org_with_one_relationship(
                client, email="rel-list@example.com"
            )

            resp = client.get(f"/organizations/{org}/relationships", headers={"X-API-Key": api_key})
            assert resp.status_code == 200
            body = resp.json()
            assert len(body) == 1
            row = body[0]
            assert row["relationship_id"] == relationship_id
            assert row["relationship_type"] == "SHARES_IPV4"
            assert row["confidence"] == "HIGH"
            assert row["data"] == {"signal": "203.0.113.9"}

    def test_relationship_type_filter_is_respected(self, tmp_path: Path) -> None:
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "rel-filter@example.com"}).json()
            api_key = account["api_key"]
            db = client.app.state.control_db
            api_settings: APISettings = client.app.state.api_settings
            organization_id, _ = db.list_organizations_for_account(account["account_id"])[0]
            _relationship_scan(
                db,
                api_settings,
                account_id=account["account_id"],
                organization_id=organization_id,
                source="domain:a.example.com",
                target="domain:b.example.com",
                relationship_type=RelationshipType.SHARES_IPV4,
            )
            _relationship_scan(
                db,
                api_settings,
                account_id=account["account_id"],
                organization_id=organization_id,
                source="domain:a.example.com",
                target="certificate:" + "c" * 64,
                relationship_type=RelationshipType.PRESENTS_CERTIFICATE,
            )
            backfill_relationships_for_organization(
                control_db=db, api_settings=api_settings, organization_id=organization_id
            )

            resp = client.get(
                f"/organizations/{organization_id}/relationships",
                headers={"X-API-Key": api_key},
                params={"relationship_type": "PRESENTS_CERTIFICATE"},
            )
            body = resp.json()
            assert len(body) == 1
            assert body[0]["relationship_type"] == "PRESENTS_CERTIFICATE"

    def test_limit_and_offset_are_real_sql_level_pagination(self, tmp_path: Path) -> None:
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "rel-page@example.com"}).json()
            db = client.app.state.control_db
            api_settings: APISettings = client.app.state.api_settings
            organization_id, _ = db.list_organizations_for_account(account["account_id"])[0]
            for i in range(3):
                _relationship_scan(
                    db,
                    api_settings,
                    account_id=account["account_id"],
                    organization_id=organization_id,
                    source=f"domain:src{i}.example.com",
                    target=f"domain:dst{i}.example.com",
                )
            backfill_relationships_for_organization(
                control_db=db, api_settings=api_settings, organization_id=organization_id
            )

            page1 = client.get(
                f"/organizations/{organization_id}/relationships",
                headers={"X-API-Key": account["api_key"]},
                params={"limit": 2, "offset": 0},
            )
            page2 = client.get(
                f"/organizations/{organization_id}/relationships",
                headers={"X-API-Key": account["api_key"]},
                params={"limit": 2, "offset": 2},
            )
            assert len(page1.json()) == 2
            assert len(page2.json()) == 1
            ids = {r["relationship_id"] for r in page1.json() + page2.json()}
            assert len(ids) == 3


class TestRelationshipEvidence:
    def test_evidence_carries_a_real_reason_and_metadata(self, tmp_path: Path) -> None:
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, org, relationship_id = _seed_org_with_one_relationship(
                client, email="rel-evidence@example.com"
            )

            resp = client.get(
                f"/organizations/{org}/relationships/{relationship_id}/evidence",
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert len(body) == 1
            assert body[0]["reason"] == "shared signal"
            assert body[0]["metadata"] == {"signal": "203.0.113.9"}

    def test_a_nonexistent_relationship_id_is_a_clean_404(self, tmp_path: Path) -> None:
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "rel-404@example.com"}).json()
            organization_id = client.app.state.control_db.list_organizations_for_account(
                account["account_id"]
            )[0][0]
            resp = client.get(
                f"/organizations/{organization_id}/relationships/does-not-exist/evidence",
                headers={"X-API-Key": account["api_key"]},
            )
            assert resp.status_code == 404


class TestAssetRelationshipNeighborhood:
    def test_lists_relationships_reachable_from_the_asset(self, tmp_path: Path) -> None:
        from api.asset_backfill import backfill_assets_for_organization
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "rel-asset@example.com"}).json()
            api_key = account["api_key"]
            db = client.app.state.control_db
            api_settings: APISettings = client.app.state.api_settings
            organization_id, _ = db.list_organizations_for_account(account["account_id"])[0]

            from core.assets import Host

            scan_id = secrets.token_hex(16)
            db.create_scan(
                scan_id=scan_id,
                account_id=account["account_id"],
                domain="a.example.com",
                db_path=str(api_settings.data_dir),
                organization_id=organization_id,
            )
            store = AssetStore(account_db_path(api_settings, account["account_id"]))
            store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
            store.upsert_host(scan_id, Host(domain="a.example.com", discovery_sources=["dnsx"]))
            db.update_scan_status(scan_id, "completed")
            backfill_assets_for_organization(
                control_db=db, api_settings=api_settings, organization_id=organization_id
            )
            asset = db.get_asset_by_identity(
                organization_id=organization_id,
                asset_type="domain",
                identity_key="domain:a.example.com",
            )

            _relationship_scan(
                db,
                api_settings,
                account_id=account["account_id"],
                organization_id=organization_id,
                source="domain:a.example.com",
                target="domain:b.example.com",
            )
            backfill_relationships_for_organization(
                control_db=db, api_settings=api_settings, organization_id=organization_id
            )

            resp = client.get(
                f"/organizations/{organization_id}/assets/{asset.asset_id}/relationships",
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert len(body) == 1
            assert body[0]["source_entity"] == "domain:a.example.com"
            assert body[0]["target_entity"] == "domain:b.example.com"


class TestForeignAccountCannotProbeRelationships:
    def test_relationship_endpoints_404_for_a_non_member(self, tmp_path: Path) -> None:
        from api.main import create_app

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            _owner_key, org, relationship_id = _seed_org_with_one_relationship(
                client, email="rel-target@example.com"
            )
            foreign = client.post("/accounts", json={"email": "rel-foreign@example.com"}).json()
            headers = {"X-API-Key": foreign["api_key"]}

            assert (
                client.get(f"/organizations/{org}/relationships", headers=headers).status_code
                == 404
            )
            assert (
                client.get(
                    f"/organizations/{org}/relationships/{relationship_id}/evidence",
                    headers=headers,
                ).status_code
                == 404
            )
