"""Roadmap v2 "Capability & Tool Access": organization default provider
set, per-scan override, tier ceiling with a typed entitlement error, and
the audit trail. The API tests run with `max_concurrent_scans=0`, so queued
scans are never executed and nothing touches the network."""

from __future__ import annotations

from pathlib import Path

import pytest
from _org_helpers import api_client, verified_owner
from _verified_account import create_verified_account
from _verified_domain import seed_verified_domain

from api.collection_capabilities import (
    CapabilityRequestError,
    builtin_default,
    optional_providers,
    resolve_scan_providers,
    tier_ceiling,
    validate_requested,
)
from api.settings import APISettings

DOMAIN = "caps.example"
HIGH_VOLUME = {"cloud_bucket_enum", "ffuf", "naabu", "param_fuzz"}


class TestCatalogAndCeilings:
    def test_todays_defaults_fit_every_tier_so_no_behavior_changes(self) -> None:
        for tier in ("free", "medium", "pro", "ultra"):
            assert builtin_default() <= tier_ceiling(tier)

    def test_high_volume_collectors_need_pro_or_ultra(self) -> None:
        assert not (HIGH_VOLUME & tier_ceiling("free"))
        assert not (HIGH_VOLUME & tier_ceiling("medium"))
        assert tier_ceiling("pro") == optional_providers() == tier_ceiling("ultra")

    def test_unknown_and_always_on_providers_are_rejected(self) -> None:
        with pytest.raises(CapabilityRequestError):
            validate_requested(["not-a-provider"])
        with pytest.raises(CapabilityRequestError):
            validate_requested(["httpx"])

    def test_resolution_prefers_override_then_org_default_then_current(self) -> None:
        common = {"current": frozenset({"ctlogs"}), "tier": "pro"}
        only_whois = frozenset({"whois"})
        assert resolve_scan_providers(override=only_whois, org_default=frozenset(), **common) == {
            "whois"
        }
        assert resolve_scan_providers(override=None, org_default=only_whois, **common) == {"whois"}
        assert resolve_scan_providers(override=None, org_default=None, **common) == {"ctlogs"}

    def test_resolution_clips_to_the_tier_ceiling(self) -> None:
        saved = frozenset({"naabu", "ctlogs"})
        resolved = resolve_scan_providers(
            override=None, org_default=saved, current=frozenset(), tier="free"
        )
        assert resolved == {"ctlogs"}


class TestOrganizationDefault:
    def test_a_new_org_reports_the_builtin_default(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            body = client.get(f"/organizations/{org}/collection-settings", headers=headers).json()

            assert body["source"] == "default"
            assert set(body["enabled_providers"]) == builtin_default()
            assert body["not_entitled"] == []
            naabu = next(p for p in body["providers"] if p["provider"] == "naabu")
            assert naabu["entitled"] is False

    def test_owner_saves_a_default_and_it_is_audited_once(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            url = f"/organizations/{org}/collection-settings"

            saved = client.put(url, headers=headers, json={"enabled_providers": ["ctlogs"]})
            client.put(url, headers=headers, json={"enabled_providers": ["ctlogs"]})

            assert saved.status_code == 200
            assert (saved.json()["source"], saved.json()["enabled_providers"]) == (
                "organization",
                ["ctlogs"],
            )
            audit = client.get(f"{url}/audit", headers=headers).json()
            assert len(audit) == 1  # the identical second PUT wrote nothing
            assert audit[0]["action"] == "org_default_updated"
            assert audit[0]["actor_account_id"] == account_id
            assert set(audit[0]["before"]) == builtin_default()
            assert audit[0]["after"] == ["ctlogs"]

    def test_a_higher_tier_provider_is_a_typed_403_not_a_silent_drop(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            url = f"/organizations/{org}/collection-settings"

            resp = client.put(url, headers=headers, json={"enabled_providers": ["ctlogs", "naabu"]})

            assert resp.status_code == 403
            assert resp.json()["detail"]["error"] == "capability_not_entitled"
            assert resp.json()["detail"]["providers"] == ["naabu"]
            assert client.get(url, headers=headers).json()["source"] == "default"
            assert client.get(f"{url}/audit", headers=headers).json() == []

    def test_unknown_or_always_on_provider_is_422(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            url = f"/organizations/{org}/collection-settings"

            unknown = client.put(url, headers=headers, json={"enabled_providers": ["nope"]})
            required = client.put(url, headers=headers, json={"enabled_providers": ["httpx"]})

            assert (unknown.status_code, required.status_code) == (422, 422)

    def test_a_downgrade_shows_saved_providers_as_not_entitled(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            db = client.app.state.control_db
            db.set_tier(account_id, "pro")
            url = f"/organizations/{org}/collection-settings"
            client.put(url, headers=headers, json={"enabled_providers": ["ctlogs", "naabu"]})

            db.set_tier(account_id, "free")
            body = client.get(url, headers=headers).json()

            assert body["enabled_providers"] == ["ctlogs", "naabu"]
            assert (body["effective_providers"], body["not_entitled"]) == (["ctlogs"], ["naabu"])


class TestRolesAndTenancy:
    def test_viewer_can_read_but_not_change(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            owner_headers, _, org = verified_owner(client)
            viewer_key, viewer_id = create_verified_account(client)
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            viewer = {"X-API-Key": viewer_key}
            url = f"/organizations/{org}/collection-settings"

            read = client.get(url, headers=viewer)
            write = client.put(url, headers=viewer, json={"enabled_providers": ["ctlogs"]})

            assert (read.status_code, write.status_code) == (200, 403)
            assert client.get(url, headers=owner_headers).json()["source"] == "default"

    def test_foreign_account_gets_404_everywhere(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            _, _, org = verified_owner(client)
            foreign_key, _ = create_verified_account(client)
            foreign = {"X-API-Key": foreign_key}
            url = f"/organizations/{org}/collection-settings"

            responses = [
                client.get(url, headers=foreign),
                client.put(url, headers=foreign, json={"enabled_providers": ["ctlogs"]}),
                client.get(f"{url}/audit", headers=foreign),
            ]

            assert [r.status_code for r in responses] == [404, 404, 404]


class TestScanOverride:
    def test_override_is_stored_on_the_scan_and_audited(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            seed_verified_domain(client, account_id, DOMAIN)

            created = client.post(
                "/scans", headers=headers, json={"domain": DOMAIN, "providers": ["whois"]}
            )

            assert created.status_code == 202
            scan_id = created.json()["scan_id"]
            status = client.get(f"/scans/{scan_id}", headers=headers).json()
            assert status["capability_override"] == ["whois"]
            audit = client.get(
                f"/organizations/{org}/collection-settings/audit", headers=headers
            ).json()
            assert [(a["action"], a["scan_id"], a["after"]) for a in audit] == [
                ("scan_override", scan_id, ["whois"])
            ]
            # A scan override never becomes the organization's default.
            settings_url = f"/organizations/{org}/collection-settings"
            assert client.get(settings_url, headers=headers).json()["source"] == "default"

    def test_override_above_the_tier_creates_no_scan_and_spends_no_quota(
        self, tmp_path: Path
    ) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            seed_verified_domain(client, account_id, DOMAIN)
            db = client.app.state.control_db

            resp = client.post(
                "/scans", headers=headers, json={"domain": DOMAIN, "providers": ["naabu"]}
            )

            assert resp.status_code == 403
            assert resp.json()["detail"]["error"] == "capability_not_entitled"
            assert db.list_scans_for_organization(org) == []
            assert db.list_capability_audit(org) == []

    def test_scan_without_override_has_none(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, _ = verified_owner(client)
            seed_verified_domain(client, account_id, DOMAIN)

            scan_id = client.post("/scans", headers=headers, json={"domain": DOMAIN}).json()[
                "scan_id"
            ]

            assert (
                client.get(f"/scans/{scan_id}", headers=headers).json()["capability_override"]
                is None
            )


class TestExecutionEnforcement:
    """What actually runs: execute_scan with the real pipeline replaced by a
    stub that captures the Settings it receives (the pattern
    tests/test_scan_orchestrator_easm_wiring.py uses)."""

    @staticmethod
    async def _execute(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, tier: str, default
    ):  # noqa: ANN001, ANN205
        from api.control_db import ControlDB
        from api.scan_orchestrator import execute_scan
        from core.models import PipelineContext

        api_settings = APISettings(data_dir=tmp_path / "api")
        db = ControlDB(api_settings.control_db_path)
        account_id = db.create_account(email="exec@example.com")
        db.create_default_subscription(account_id, tier=tier)
        org = db.list_organizations_for_account(account_id)[0][0]
        if default is not None:
            db.set_org_collection_settings(
                organization_id=org,
                actor_account_id=account_id,
                providers=frozenset(default),
                previous=builtin_default(),
            )
        db.create_scan(scan_id="s1", account_id=account_id, domain=DOMAIN, db_path="x")
        captured: list = []

        async def fake_pipeline(settings, *, domain, targets_file, run_id):  # noqa: ANN001
            captured.append(settings)
            return 1, PipelineContext(errors=["stubbed"])

        monkeypatch.setattr("app._run_headless_pipeline", fake_pipeline)
        monkeypatch.setattr("app._external_mode_preflight", lambda args, settings: True)
        await execute_scan(
            api_settings=api_settings,
            control_db=db,
            account_id=account_id,
            scan_id="s1",
            domain=DOMAIN,
        )
        return captured[0], db.get_owned_scan("s1", account_id)

    async def test_the_org_default_decides_what_runs_and_is_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings, scan = await self._execute(tmp_path, monkeypatch, tier="free", default={"whois"})

        assert settings.enable_whois is True
        assert settings.enable_ctlogs is False  # on by default, but not in the saved set
        assert scan.effective_providers == ("whois",)

    async def test_a_saved_provider_above_the_tier_does_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings, scan = await self._execute(
            tmp_path, monkeypatch, tier="free", default={"whois", "naabu"}
        )

        assert settings.enable_naabu is False
        assert scan.effective_providers == ("whois",)
