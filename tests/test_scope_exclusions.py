"""Roadmap v2: organization scope exclusions and the known / candidate /
authorized / observed / excluded classification of a host.

Exclusions reuse the scope engine's own `!pattern` enforcement, so the
engine-level tests below go through the real `allows_active_collection`
gate and the real `PipelineRunner._enforce_scope`. API tests run with
`max_concurrent_scans=0`: queued scans never execute."""

from __future__ import annotations

from pathlib import Path

import pytest
from _verified_account import create_verified_account
from _verified_domain import seed_verified_domain
from fastapi.testclient import TestClient

from api.candidate_assets import CandidateAssetDraft
from api.main import create_app
from api.settings import APISettings
from config.settings import Settings
from core.exceptions import ConfigurationError
from core.intel.scope import CollectionScope, allows_active_collection
from core.models import DomainTarget
from core.runner import PipelineRunner
from core.scope import configured_scope_patterns, normalize_exclusion_pattern

DOMAIN = "acme.example"


class TestPatterns:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Legacy.ACME.example.", "legacy.acme.example"),
            ("*.corp.acme.example", "*.corp.acme.example"),
            ("acme.example/*/whistleblowing", "acme.example/*/whistleblowing"),
        ],
    )
    def test_valid_patterns_are_normalized(self, raw: str, expected: str) -> None:
        assert normalize_exclusion_pattern(raw) == expected

    @pytest.mark.parametrize(
        "raw", ["", "https://acme.example", "!acme.example", "acme", "a b.example", "*"]
    )
    def test_invalid_patterns_are_rejected(self, raw: str) -> None:
        with pytest.raises(ValueError, match="exclusion|host"):
            normalize_exclusion_pattern(raw)


class TestEnforcement:
    def _scope(self, *exclusions: str) -> CollectionScope:
        return CollectionScope.from_seeds(
            [DOMAIN], patterns=configured_scope_patterns(None, list(exclusions))
        )

    def test_an_excluded_host_and_its_subdomains_are_never_collected(self) -> None:
        scope = self._scope("legacy.acme.example")

        assert not allows_active_collection("legacy.acme.example", scope)
        assert not allows_active_collection("https://api.legacy.acme.example/x", scope)
        assert allows_active_collection("www.acme.example", scope)

    def test_a_path_exclusion_blocks_the_path_not_the_host(self) -> None:
        scope = self._scope("acme.example/*/whistleblowing")

        assert allows_active_collection("acme.example", scope)
        assert not allows_active_collection("https://acme.example/es/whistleblowing/x", scope)

    def test_a_run_whose_target_is_excluded_is_refused(self, tmp_path: Path) -> None:
        settings = Settings(project_root=tmp_path, scope_exclusions=["acme.example"])

        with pytest.raises(ConfigurationError, match="explicitly excluded"):
            PipelineRunner(settings)._enforce_scope([DomainTarget(domain="www.acme.example")])

    def test_exclusions_never_turn_into_a_positive_allowlist(self, tmp_path: Path) -> None:
        settings = Settings(project_root=tmp_path, scope_exclusions=["legacy.acme.example"])

        PipelineRunner(settings)._enforce_scope([DomainTarget(domain="acme.example")])


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(APISettings(data_dir=tmp_path / "api", max_concurrent_scans=0)))


def _owner(client: TestClient) -> tuple[dict[str, str], str, str]:
    api_key, account_id = create_verified_account(client)
    org = client.app.state.control_db.list_organizations_for_account(account_id)[0][0]
    return {"X-API-Key": api_key}, account_id, org


def _add(client: TestClient, headers: dict[str, str], org: str, pattern: str):  # noqa: ANN202
    return client.post(
        f"/organizations/{org}/scope/exclusions",
        headers=headers,
        json={"pattern": pattern, "reason": "decommissioned, third-party hosted"},
    )


class TestExclusionEndpoints:
    def test_owner_adds_lists_and_removes_with_history_kept(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            headers, _, org = _owner(client)
            created = _add(client, headers, org, "Legacy.acme.example").json()
            url = f"/organizations/{org}/scope/exclusions"

            removed = client.request(
                "DELETE",
                f"{url}/{created['exclusion_id']}",
                headers=headers,
                json={"reason": "back in scope"},
            )

            assert created["pattern"] == "legacy.acme.example"
            assert removed.status_code == 204
            assert client.get(url, headers=headers).json() == []
            history = client.get(url, headers=headers, params={"include_removed": True}).json()
            assert history[0]["removal_reason"] == "back in scope"
            assert _add(client, headers, org, "legacy.acme.example").status_code == 201

    def test_duplicates_invalid_patterns_and_blank_reasons_are_rejected(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            headers, _, org = _owner(client)
            _add(client, headers, org, "legacy.acme.example")

            blank = client.post(
                f"/organizations/{org}/scope/exclusions",
                headers=headers,
                json={"pattern": "x.acme.example", "reason": "   "},
            )

            assert _add(client, headers, org, "legacy.acme.example").status_code == 409
            assert _add(client, headers, org, "https://x.example").status_code == 422
            assert blank.status_code == 422

    def test_viewer_can_read_but_not_change(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            owner, _, org = _owner(client)
            created = _add(client, owner, org, "legacy.acme.example").json()
            viewer_key, viewer_id = create_verified_account(client)
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            viewer = {"X-API-Key": viewer_key}
            url = f"/organizations/{org}/scope/exclusions"

            delete = client.request(
                "DELETE",
                f"{url}/{created['exclusion_id']}",
                headers=viewer,
                json={"reason": "nope"},
            )

            assert client.get(url, headers=viewer).status_code == 200
            assert _add(client, viewer, org, "other.acme.example").status_code == 403
            assert delete.status_code == 403

    def test_a_foreign_account_gets_404_everywhere(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            owner, _, org = _owner(client)
            created = _add(client, owner, org, "legacy.acme.example").json()
            foreign, _, _ = _owner(client)
            url = f"/organizations/{org}/scope"

            responses = [
                client.get(f"{url}/exclusions", headers=foreign),
                _add(client, foreign, org, "x.acme.example"),
                client.request(
                    "DELETE",
                    f"{url}/exclusions/{created['exclusion_id']}",
                    headers=foreign,
                    json={"reason": "attack"},
                ),
                client.get(f"{url}/classify", headers=foreign, params={"host": DOMAIN}),
            ]

            assert [r.status_code for r in responses] == [404, 404, 404, 404]
            assert client.get(f"{url}/exclusions", headers=owner).json()[0]["removed_at"] is None

    def test_removing_another_orgs_exclusion_is_404(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            owner, _, org = _owner(client)
            created = _add(client, owner, org, "legacy.acme.example").json()
            other_owner, _, other_org = _owner(client)

            resp = client.request(
                "DELETE",
                f"/organizations/{other_org}/scope/exclusions/{created['exclusion_id']}",
                headers=other_owner,
                json={"reason": "cross-org"},
            )

            assert resp.status_code == 404


class TestScanCreation:
    def test_a_scan_of_an_excluded_target_is_refused_without_spending_quota(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            seed_verified_domain(client, account_id, DOMAIN)
            _add(client, headers, org, "legacy.acme.example")

            refused = client.post(
                "/scans", headers=headers, json={"domain": "api.legacy.acme.example"}
            )
            allowed = client.post("/scans", headers=headers, json={"domain": DOMAIN})

            assert refused.status_code == 422
            assert refused.json()["detail"]["error"] == "target_excluded"
            assert allowed.status_code == 202
            usage = client.get("/account/subscription", headers=headers).json()
            assert usage["scans_used_this_period"] == 1


def _classify(client: TestClient, headers: dict[str, str], org: str, host: str) -> dict:
    return client.get(
        f"/organizations/{org}/scope/classify", headers=headers, params={"host": host}
    ).json()


def _candidate(client: TestClient, org: str, value: str, scope_status: str) -> None:
    client.app.state.control_db.upsert_candidate_asset(
        organization_id=org,
        run_id="run-1",
        draft=CandidateAssetDraft(
            candidate_type="DOMAIN",
            normalized_value=value,
            display_value=value,
            scope_status=scope_status,
            collection_status="DISCOVERED",
            authorization_status="DENY",
            reason="shared certificate",
            depth=1,
            priority=50,
            collector="ctlogs",
            source_entity_id="",
            parent_indicator_id=None,
            lineage_reference="run-1",
        ),
    )


class TestClassification:
    def test_each_class_with_its_reason(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            seed_verified_domain(client, account_id, DOMAIN)
            _candidate(client, org, "new.acme.example", "IN_SCOPE")
            _candidate(client, org, "cdn.partner.example", "OUT_OF_SCOPE")
            _add(client, headers, org, "legacy.acme.example")

            got = {
                host: _classify(client, headers, org, host)["classification"]
                for host in (
                    "legacy.acme.example",
                    "new.acme.example",
                    "cdn.partner.example",
                    "shop.acme.example",
                    "nowhere.example",
                )
            }

            assert got == {
                "legacy.acme.example": "excluded",
                "new.acme.example": "candidate",
                "cdn.partner.example": "observed_related",
                "shop.acme.example": "authorized_scope",
                "nowhere.example": "unknown",
            }
            assert (
                "verified domain acme.example"
                in _classify(client, headers, org, "shop.acme.example")["reason"]
            )

    def test_an_exclusion_wins_over_a_candidate(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            headers, _, org = _owner(client)
            _candidate(client, org, "new.acme.example", "IN_SCOPE")
            created = _add(client, headers, org, "*.acme.example").json()

            body = _classify(client, headers, org, "new.acme.example")

            assert (body["classification"], body["exclusion_id"]) == (
                "excluded",
                created["exclusion_id"],
            )


class TestOrchestratorHandOff:
    def test_api_scans_carry_the_organizations_active_exclusions(self, tmp_path: Path) -> None:
        from api.scan_orchestrator import _scan_settings

        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            seed_verified_domain(client, account_id, DOMAIN)
            _add(client, headers, org, "legacy.acme.example")
            removed = _add(client, headers, org, "old.acme.example").json()
            client.request(
                "DELETE",
                f"/organizations/{org}/scope/exclusions/" f"{removed['exclusion_id']}",
                headers=headers,
                json={"reason": "ok"},
            )
            scan_id = client.post("/scans", headers=headers, json={"domain": DOMAIN}).json()[
                "scan_id"
            ]

            settings = _scan_settings(
                client.app.state.api_settings,
                client.app.state.control_db,
                account_id=account_id,
                scan_id=scan_id,
                passive=False,
            )

            assert settings.scope_exclusions == ["legacy.acme.example"]
