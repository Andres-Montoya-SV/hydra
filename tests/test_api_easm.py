"""Fase 19 (EASM roadmap) — API isolation and workflow tests for
`api/routers/easm.py`: organizations, assets, candidate assets (read +
promote/discard), observations, change/certificate/technology events,
current-technology inventory, and the capability status view.

Follows `tests/test_api_exposures.py`'s own established pattern exactly:
seed via a real `TestClient` account + direct `ControlDB` writes for the
domain-model rows, then exercise the HTTP layer. Every new endpoint gets
an explicit foreign-account IDOR/BOLA check, per the phase's own "no se
resume" requirement.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi.testclient import TestClient

from api.asset_backfill import backfill_assets_for_organization
from api.easm_backfill import run_easm_backfill_for_organization
from api.main import create_app
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, TlsCertificate
from core.store import AssetStore, ScanRun


def _seed_account_with_domain_asset(
    client: TestClient, *, email: str, domain: str = "example.com"
) -> tuple[str, str, str, str]:
    """Returns (api_key, account_id, organization_id, asset_id) for a
    freshly created account with one real, scan-backed domain asset."""
    account = client.post("/accounts", json={"email": email}).json()
    api_key = account["api_key"]
    account_id = account["account_id"]
    db = client.app.state.control_db
    api_settings: APISettings = client.app.state.api_settings
    organization_id, _ = db.list_organizations_for_account(account_id)[0]

    scan_id = secrets.token_hex(16)
    db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain=domain,
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
    store.upsert_host(
        scan_id,
        Host(
            domain=domain,
            discovery_sources=["dnsx"],
            tls=TlsCertificate(
                host=domain,
                issuer="Let's Encrypt",
                subject=f"CN={domain}",
                sans=[domain],
                not_before="2026-01-01",
                not_after="2026-04-01",
                fingerprint_sha256="a" * 64,
            ),
        ),
    )
    db.update_scan_status(scan_id, "completed")
    run_easm_backfill_for_organization(
        control_db=db, api_settings=api_settings, organization_id=organization_id
    )
    asset = db.get_asset_by_identity(
        organization_id=organization_id, asset_type="domain", identity_key=f"domain:{domain}"
    )
    return api_key, account_id, organization_id, asset.asset_id


def _seed_candidate(client: TestClient, *, organization_id: str, account_id: str) -> str:
    from api.candidate_assets import CandidateAssetDraft

    db = client.app.state.control_db
    candidate_id, _created = db.upsert_candidate_asset(
        organization_id=organization_id,
        run_id="seed-run",
        draft=CandidateAssetDraft(
            candidate_type="DOMAIN",
            normalized_value="candidate.example.com",
            display_value="candidate.example.com",
            scope_status="UNKNOWN",
            collection_status="DISCOVERED",
            authorization_status="DENY",
            reason="discovered via correlation",
            depth=1,
            priority=50,
            collector="ctlogs",
            source_entity_id="",
            parent_indicator_id=None,
            lineage_reference="seed-run",
        ),
    )
    return candidate_id


class TestOwnerCanReadAssetsAndSubResources:
    def test_full_read_surface_for_an_owner(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, _, org, asset_id = _seed_account_with_domain_asset(
                client, email="owner@example.com"
            )
            headers = {"X-API-Key": api_key}

            orgs = client.get("/organizations", headers=headers)
            assert orgs.status_code == 200
            assert orgs.json()[0]["organization_id"] == org
            assert orgs.json()[0]["role"] == "owner"

            assets = client.get(f"/organizations/{org}/assets", headers=headers)
            assert assets.status_code == 200
            assert [a["asset_id"] for a in assets.json()] == [asset_id]

            one = client.get(f"/organizations/{org}/assets/{asset_id}", headers=headers)
            assert one.status_code == 200
            assert one.json()["asset_type"] == "domain"

            observations = client.get(
                f"/organizations/{org}/assets/{asset_id}/observations", headers=headers
            )
            assert observations.status_code == 200
            assert len(observations.json()) >= 1
            assert observations.json()[0]["evidence"]["source"]

            cert_events = client.get(
                f"/organizations/{org}/assets/{asset_id}/certificate-events", headers=headers
            )
            assert cert_events.status_code == 200
            assert cert_events.json()[0]["event_type"] == "CERTIFICATE_FIRST_SEEN"

            tech_events = client.get(
                f"/organizations/{org}/assets/{asset_id}/technology-events", headers=headers
            )
            assert tech_events.status_code == 200

            current_tech = client.get(
                f"/organizations/{org}/assets/{asset_id}/technologies", headers=headers
            )
            assert current_tech.status_code == 200

            change_events = client.get(
                f"/organizations/{org}/assets/{asset_id}/change-events", headers=headers
            )
            assert change_events.status_code == 200

            capabilities = client.get(f"/organizations/{org}/capabilities", headers=headers)
            assert capabilities.status_code == 200
            assert any(row["provider"] == "httpx" for row in capabilities.json())


class TestPagination:
    def test_limit_and_offset_are_respected(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, account_id, org, _ = _seed_account_with_domain_asset(
                client, email="pagination@example.com"
            )
            headers = {"X-API-Key": api_key}
            db = client.app.state.control_db
            api_settings: APISettings = client.app.state.api_settings
            store = AssetStore(account_db_path(api_settings, account_id))

            for i in range(5):
                scan_id = secrets.token_hex(16)
                domain = f"host{i}.example.com"
                db.create_scan(
                    scan_id=scan_id,
                    account_id=account_id,
                    domain=domain,
                    db_path=str(api_settings.data_dir),
                    organization_id=org,
                )
                store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
                store.upsert_host(scan_id, Host(domain=domain, discovery_sources=["dnsx"]))
                db.update_scan_status(scan_id, "completed")
            backfill_assets_for_organization(
                control_db=db, api_settings=api_settings, organization_id=org
            )

            page1 = client.get(
                f"/organizations/{org}/assets", headers=headers, params={"limit": 2, "offset": 0}
            )
            page2 = client.get(
                f"/organizations/{org}/assets", headers=headers, params={"limit": 2, "offset": 2}
            )
            assert len(page1.json()) == 2
            assert len(page2.json()) == 2
            assert {a["asset_id"] for a in page1.json()}.isdisjoint(
                {a["asset_id"] for a in page2.json()}
            )


class TestOrganizationCreationAndMembers:
    """Productization Phase 01 — the first HTTP surface over Fase 02's
    already-tested `create_organization`/`add_account_organization_role`/
    `role_can_manage_members` data-layer logic (`tests/test_organizations.py`
    covers those directly; this covers the router wiring on top)."""

    def test_create_organization_makes_the_caller_its_owner(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "consultant@example.com"}).json()
            headers = {"X-API-Key": account["api_key"]}

            resp = client.post("/organizations", headers=headers, json={"name": "Client B Inc"})
            assert resp.status_code == 201
            body = resp.json()
            assert body["name"] == "Client B Inc"
            assert body["role"] == "owner"

            orgs = client.get("/organizations", headers=headers).json()
            org_ids = {o["organization_id"] for o in orgs}
            assert body["organization_id"] in org_ids
            assert len(org_ids) == 2  # the account's own 1:1 org, plus this new one

    def test_owner_can_add_and_list_a_viewer_member(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            owner = client.post("/accounts", json={"email": "member-owner@example.com"}).json()
            viewer = client.post("/accounts", json={"email": "member-viewer@example.com"}).json()
            owner_headers = {"X-API-Key": owner["api_key"]}
            org_id = client.get("/organizations", headers=owner_headers).json()[0][
                "organization_id"
            ]

            add = client.post(
                f"/organizations/{org_id}/members",
                headers=owner_headers,
                json={"account_id": viewer["account_id"], "role": "viewer"},
            )
            assert add.status_code == 200
            assert add.json() == {
                "account_id": viewer["account_id"],
                "role": "viewer",
                "created_at": add.json()["created_at"],
            }

            members = client.get(f"/organizations/{org_id}/members", headers=owner_headers).json()
            by_account = {m["account_id"]: m["role"] for m in members}
            assert by_account == {owner["account_id"]: "owner", viewer["account_id"]: "viewer"}

            # The viewer can now see this organization via GET /organizations
            # (real access, not just a row that exists in the DB).
            viewer_orgs = client.get(
                "/organizations", headers={"X-API-Key": viewer["api_key"]}
            ).json()
            assert any(
                o["organization_id"] == org_id and o["role"] == "viewer" for o in viewer_orgs
            )

    def test_viewer_cannot_add_a_member(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            owner = client.post("/accounts", json={"email": "v-owner@example.com"}).json()
            viewer = client.post("/accounts", json={"email": "v-viewer@example.com"}).json()
            third = client.post("/accounts", json={"email": "v-third@example.com"}).json()
            owner_headers = {"X-API-Key": owner["api_key"]}
            org_id = client.get("/organizations", headers=owner_headers).json()[0][
                "organization_id"
            ]
            client.post(
                f"/organizations/{org_id}/members",
                headers=owner_headers,
                json={"account_id": viewer["account_id"], "role": "viewer"},
            )

            resp = client.post(
                f"/organizations/{org_id}/members",
                headers={"X-API-Key": viewer["api_key"]},
                json={"account_id": third["account_id"], "role": "viewer"},
            )
            assert resp.status_code == 403

    def test_adding_a_nonexistent_account_id_is_a_clean_404(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            owner = client.post("/accounts", json={"email": "nx-owner@example.com"}).json()
            owner_headers = {"X-API-Key": owner["api_key"]}
            org_id = client.get("/organizations", headers=owner_headers).json()[0][
                "organization_id"
            ]

            resp = client.post(
                f"/organizations/{org_id}/members",
                headers=owner_headers,
                json={"account_id": "does-not-exist", "role": "viewer"},
            )
            assert resp.status_code == 404

    def test_owner_can_remove_a_viewer(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            owner = client.post("/accounts", json={"email": "rm-owner@example.com"}).json()
            viewer = client.post("/accounts", json={"email": "rm-viewer@example.com"}).json()
            owner_headers = {"X-API-Key": owner["api_key"]}
            org_id = client.get("/organizations", headers=owner_headers).json()[0][
                "organization_id"
            ]
            client.post(
                f"/organizations/{org_id}/members",
                headers=owner_headers,
                json={"account_id": viewer["account_id"], "role": "viewer"},
            )

            resp = client.delete(
                f"/organizations/{org_id}/members/{viewer['account_id']}", headers=owner_headers
            )
            assert resp.status_code == 204

            members = client.get(f"/organizations/{org_id}/members", headers=owner_headers).json()
            assert viewer["account_id"] not in {m["account_id"] for m in members}

    def test_removing_the_only_owner_is_a_clean_409_not_a_500(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            owner = client.post("/accounts", json={"email": "self-rm@example.com"}).json()
            owner_headers = {"X-API-Key": owner["api_key"]}
            org_id = client.get("/organizations", headers=owner_headers).json()[0][
                "organization_id"
            ]

            resp = client.delete(
                f"/organizations/{org_id}/members/{owner['account_id']}", headers=owner_headers
            )
            assert resp.status_code == 409

            # Refused, not partially applied.
            members = client.get(f"/organizations/{org_id}/members", headers=owner_headers).json()
            assert owner["account_id"] in {m["account_id"] for m in members}

    def test_viewer_cannot_remove_a_member(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            owner = client.post("/accounts", json={"email": "vrm-owner@example.com"}).json()
            viewer = client.post("/accounts", json={"email": "vrm-viewer@example.com"}).json()
            owner_headers = {"X-API-Key": owner["api_key"]}
            org_id = client.get("/organizations", headers=owner_headers).json()[0][
                "organization_id"
            ]
            client.post(
                f"/organizations/{org_id}/members",
                headers=owner_headers,
                json={"account_id": viewer["account_id"], "role": "viewer"},
            )

            resp = client.delete(
                f"/organizations/{org_id}/members/{owner['account_id']}",
                headers={"X-API-Key": viewer["api_key"]},
            )
            assert resp.status_code == 403


class TestAssetListingSearchAndSort:
    def test_q_filters_by_identity_key_substring(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, account_id, org, _ = _seed_account_with_domain_asset(
                client, email="q-search@example.com", domain="www.searchable.example.com"
            )
            headers = {"X-API-Key": api_key}

            hit = client.get(
                f"/organizations/{org}/assets", headers=headers, params={"q": "SEARCHABLE"}
            )
            miss = client.get(
                f"/organizations/{org}/assets", headers=headers, params={"q": "nomatch"}
            )
            assert len(hit.json()) == 1
            assert miss.json() == []

    def test_sort_and_order_params_are_accepted(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, _, org, _ = _seed_account_with_domain_asset(
                client, email="sort-http@example.com"
            )
            headers = {"X-API-Key": api_key}

            resp = client.get(
                f"/organizations/{org}/assets",
                headers=headers,
                params={"sort": "last_seen_at", "order": "desc"},
            )
            assert resp.status_code == 200

    def test_an_unsupported_sort_value_is_a_clean_422(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, _, org, _ = _seed_account_with_domain_asset(
                client, email="badsort-http@example.com"
            )
            resp = client.get(
                f"/organizations/{org}/assets",
                headers={"X-API-Key": api_key},
                params={"sort": "asset_type"},
            )
            assert resp.status_code == 422


class TestAssetCurrentCertificateAndIdentifiers:
    def test_current_certificate_reflects_the_seeded_tls_snapshot(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, _, org, asset_id = _seed_account_with_domain_asset(
                client, email="cert-http@example.com"
            )
            headers = {"X-API-Key": api_key}

            resp = client.get(
                f"/organizations/{org}/assets/{asset_id}/certificate", headers=headers
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["fingerprint_sha256"] == "a" * 64
            assert body["issuer"] == "Let's Encrypt"

    def test_current_certificate_is_null_not_404_when_never_observed(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "nocert-http@example.com"}).json()
            api_key = account["api_key"]
            db = client.app.state.control_db
            api_settings: APISettings = client.app.state.api_settings
            organization_id, _ = db.list_organizations_for_account(account["account_id"])[0]

            scan_id = secrets.token_hex(16)
            db.create_scan(
                scan_id=scan_id,
                account_id=account["account_id"],
                domain="nohttps.example.com",
                db_path=str(api_settings.data_dir),
                organization_id=organization_id,
            )
            store = AssetStore(account_db_path(api_settings, account["account_id"]))
            store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
            store.upsert_host(
                scan_id, Host(domain="nohttps.example.com", discovery_sources=["dnsx"])
            )
            db.update_scan_status(scan_id, "completed")
            run_easm_backfill_for_organization(
                control_db=db, api_settings=api_settings, organization_id=organization_id
            )
            asset = db.get_asset_by_identity(
                organization_id=organization_id,
                asset_type="domain",
                identity_key="domain:nohttps.example.com",
            )

            resp = client.get(
                f"/organizations/{organization_id}/assets/{asset.asset_id}/certificate",
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            assert resp.json() is None

    def test_identifiers_lists_the_assets_resolved_ips(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            account = client.post("/accounts", json={"email": "ip-http@example.com"}).json()
            api_key = account["api_key"]
            db = client.app.state.control_db
            api_settings: APISettings = client.app.state.api_settings
            organization_id, _ = db.list_organizations_for_account(account["account_id"])[0]

            scan_id = secrets.token_hex(16)
            db.create_scan(
                scan_id=scan_id,
                account_id=account["account_id"],
                domain="withip.example.com",
                db_path=str(api_settings.data_dir),
                organization_id=organization_id,
            )
            store = AssetStore(account_db_path(api_settings, account["account_id"]))
            store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
            store.upsert_host(
                scan_id,
                Host(
                    domain="withip.example.com",
                    discovery_sources=["dnsx"],
                    ips=["198.51.100.7"],
                ),
            )
            db.update_scan_status(scan_id, "completed")
            run_easm_backfill_for_organization(
                control_db=db, api_settings=api_settings, organization_id=organization_id
            )
            asset = db.get_asset_by_identity(
                organization_id=organization_id,
                asset_type="domain",
                identity_key="domain:withip.example.com",
            )

            resp = client.get(
                f"/organizations/{organization_id}/assets/{asset.asset_id}/identifiers",
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert len(body) == 1
            assert body[0]["identifier_type"] == "ip"
            assert body[0]["identifier_value"] == "198.51.100.7"


class TestCandidateAssetPromotionFlow:
    def test_owner_can_promote_a_candidate_into_a_real_asset(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, account_id, org, _ = _seed_account_with_domain_asset(
                client, email="promoter@example.com"
            )
            headers = {"X-API-Key": api_key}
            candidate_id = _seed_candidate(client, organization_id=org, account_id=account_id)

            listed = client.get(f"/organizations/{org}/candidate-assets", headers=headers)
            assert listed.status_code == 200
            assert any(c["candidate_asset_id"] == candidate_id for c in listed.json())

            got = client.get(
                f"/organizations/{org}/candidate-assets/{candidate_id}", headers=headers
            )
            assert got.status_code == 200
            assert got.json()["review_status"] == "pending"

            promoted = client.post(
                f"/organizations/{org}/candidate-assets/{candidate_id}/promote",
                headers=headers,
                json={"justification": "confirmed as our own infrastructure"},
            )
            assert promoted.status_code == 200
            assert promoted.json()["review_status"] == "promoted"
            assert promoted.json()["promoted_asset_id"] is not None

            db = client.app.state.control_db
            real_asset = db.get_asset(org, promoted.json()["promoted_asset_id"])
            assert real_asset is not None
            assert real_asset.asset_type == "domain"

    def test_owner_can_discard_a_candidate(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, account_id, org, _ = _seed_account_with_domain_asset(
                client, email="discarder@example.com"
            )
            headers = {"X-API-Key": api_key}
            candidate_id = _seed_candidate(client, organization_id=org, account_id=account_id)

            discarded = client.post(
                f"/organizations/{org}/candidate-assets/{candidate_id}/discard",
                headers=headers,
                json={"justification": "not ours, unrelated infrastructure"},
            )
            assert discarded.status_code == 200
            assert discarded.json()["review_status"] == "discarded"

    def test_a_viewer_cannot_promote_or_discard(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, account_id, org, _ = _seed_account_with_domain_asset(
                client, email="vieweraccount-owner@example.com"
            )
            db = client.app.state.control_db
            viewer_account = client.post(
                "/accounts", json={"email": "viewer-member@example.com"}
            ).json()
            db.add_account_organization_role(
                account_id=viewer_account["account_id"], organization_id=org, role="viewer"
            )
            candidate_id = _seed_candidate(client, organization_id=org, account_id=account_id)
            viewer_headers = {"X-API-Key": viewer_account["api_key"]}

            # A viewer CAN read (membership, not ownership, gates reads).
            read = client.get(
                f"/organizations/{org}/candidate-assets/{candidate_id}", headers=viewer_headers
            )
            assert read.status_code == 200

            for action in ("promote", "discard"):
                response = client.post(
                    f"/organizations/{org}/candidate-assets/{candidate_id}/{action}",
                    headers=viewer_headers,
                    json={"justification": "a viewer should never be allowed to do this"},
                )
                assert response.status_code == 403

            unchanged = client.get(
                f"/organizations/{org}/candidate-assets/{candidate_id}",
                headers={"X-API-Key": api_key},
            )
            assert unchanged.json()["review_status"] == "pending"


def _org_scoped_get_paths(org: str, asset_id: str, candidate_id: str) -> list[str]:
    return [
        "/organizations",  # not org-scoped, but must never leak the target's org
        f"/organizations/{org}/assets",
        f"/organizations/{org}/assets/{asset_id}",
        f"/organizations/{org}/assets/{asset_id}/observations",
        f"/organizations/{org}/assets/{asset_id}/change-events",
        f"/organizations/{org}/assets/{asset_id}/certificate-events",
        f"/organizations/{org}/assets/{asset_id}/technology-events",
        f"/organizations/{org}/assets/{asset_id}/technologies",
        f"/organizations/{org}/assets/{asset_id}/certificate",
        f"/organizations/{org}/assets/{asset_id}/identifiers",
        f"/organizations/{org}/assets/{asset_id}/relationships",
        f"/organizations/{org}/assets/{asset_id}/network",
        f"/organizations/{org}/assets/{asset_id}/visual",
        f"/organizations/{org}/analyst/assets/{asset_id}/provenance",
        f"/organizations/{org}/explanations/asset/{asset_id}",
        f"/organizations/{org}/scope/exclusions",
        f"/organizations/{org}/relationships",
        f"/organizations/{org}/candidate-assets",
        f"/organizations/{org}/candidate-assets/{candidate_id}",
        f"/organizations/{org}/capabilities",
        f"/organizations/{org}/members",
    ]


class TestForeignAccountCannotProbeAnyEndpoint:
    def test_every_read_and_write_endpoint_returns_404_for_a_non_member(
        self, tmp_path: Path
    ) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            _owner_key, owner_account_id, org, asset_id = _seed_account_with_domain_asset(
                client, email="target-owner@example.com"
            )
            candidate_id = _seed_candidate(client, organization_id=org, account_id=owner_account_id)
            foreign = client.post(
                "/accounts", json={"email": "foreign-attacker@example.com"}
            ).json()
            headers = {"X-API-Key": foreign["api_key"]}

            get_paths = _org_scoped_get_paths(org, asset_id, candidate_id)
            for path in get_paths:
                response = client.get(path, headers=headers)
                if path == "/organizations":
                    # The foreign account has its own default organization
                    # (every account does) -- the IDOR concern is that
                    # this list never contains the TARGET's organization.
                    assert response.status_code == 200
                    assert org not in {row["organization_id"] for row in response.json()}
                else:
                    assert response.status_code == 404, path

            for action in ("promote", "discard"):
                response = client.post(
                    f"/organizations/{org}/candidate-assets/{candidate_id}/{action}",
                    headers=headers,
                    json={"justification": "attempted by an outsider"},
                )
                assert response.status_code == 404

            add_member = client.post(
                f"/organizations/{org}/members",
                headers=headers,
                json={"account_id": owner_account_id, "role": "viewer"},
            )
            assert add_member.status_code == 404

            remove_member = client.delete(
                f"/organizations/{org}/members/{owner_account_id}", headers=headers
            )
            assert remove_member.status_code == 404

    def test_a_nonexistent_asset_and_candidate_id_also_404_for_a_real_member(
        self, tmp_path: Path
    ) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            api_key, _, org, _ = _seed_account_with_domain_asset(
                client, email="member-real@example.com"
            )
            headers = {"X-API-Key": api_key}
            assert (
                client.get(
                    f"/organizations/{org}/assets/does-not-exist", headers=headers
                ).status_code
                == 404
            )
            assert (
                client.get(
                    f"/organizations/{org}/candidate-assets/does-not-exist", headers=headers
                ).status_code
                == 404
            )

    def test_no_api_key_is_401_not_404(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            _, _, org, asset_id = _seed_account_with_domain_asset(
                client, email="unauth@example.com"
            )
            response = client.get(f"/organizations/{org}/assets/{asset_id}")
            assert response.status_code == 401
