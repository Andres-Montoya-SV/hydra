"""Productization Phase 12a: per-tier entitlements, enforced atomically."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from _org_helpers import api_client, verified_owner
from _verified_account import create_verified_account
from fastapi.testclient import TestClient
from test_api_imports import MASSCAN_JSON, NMAP_XML

from api import subscriptions
from api.control_db import ControlDB, LimitReachedError
from api.db import PoolConfig
from api.entitlements import ENTITLEMENT_FIELDS, limit_of, upgrade_for
from api.subscriptions import apply_tier_change
from api.tiers import TIERS

ORDER = ("free", "medium", "pro", "ultra")


@pytest.fixture
def client(tmp_path: Path) -> Any:
    with api_client(tmp_path) as test_client:
        yield test_client


def _refusal(response: Any, entitlement: str, limit: int) -> None:
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "entitlement_exceeded"
    assert (detail["entitlement"], detail["limit"]) == (entitlement, limit)


class TestTheTable:
    def test_every_entitlement_grows_with_the_tier(self) -> None:
        for entitlement in ENTITLEMENT_FIELDS:
            limits = [limit_of(TIERS[t], entitlement) for t in ORDER]
            finite = [v for v in limits if v is not None]
            assert finite == sorted(finite), entitlement
            # Once unlimited, never limited again.
            assert all(v is None for v in limits[limits.index(None) :]) if None in limits else True

    def test_the_decided_numbers(self) -> None:
        table = {
            t: (
                TIERS[t].max_organizations,
                TIERS[t].max_members_per_organization,
                TIERS[t].imports_per_month,
                TIERS[t].max_integrations,
            )
            for t in ORDER
        }
        assert table == {
            "free": (1, 2, 2, 1),
            "medium": (3, 5, 20, 3),
            "pro": (10, 20, 100, 10),
            "ultra": (None, 100, 1000, 25),
        }

    def test_the_upgrade_hint(self) -> None:
        assert upgrade_for("free", "organizations") == "medium"
        assert upgrade_for("pro", "organizations") == "ultra"
        assert upgrade_for("ultra", "members") is None


class TestQuotaIsAtomicAcrossProcesses:
    """Several API processes on one database: each `ControlDB` here has its
    own connection pool. Before Phase 12a, a separate check and increment
    let all of them through (8 of 8 accepted on a quota of 1)."""

    @pytest.mark.parametrize("cap", [1, 3])
    def test_never_more_than_the_cap(self, tmp_path: Path, cap: int) -> None:
        path = tmp_path / "control.db"
        setup = ControlDB(path)
        account = setup.create_account(email="race@example.com")
        processes = [ControlDB(path, pool=PoolConfig(min_size=1, max_size=2)) for _ in range(8)]
        barrier = threading.Barrier(len(processes))
        period = subscriptions.current_period_key()

        def reserve(db: ControlDB) -> bool:
            barrier.wait()
            return db.reserve_usage(account, period, "scans", cap)

        with ThreadPoolExecutor(len(processes)) as pool:
            accepted = sum(pool.map(reserve, processes))

        assert accepted == cap
        assert setup.get_monthly_usage(account, period).scans_used == cap

    def test_count_limits_hold_under_concurrency_too(self, tmp_path: Path) -> None:
        path = tmp_path / "control.db"
        setup = ControlDB(path)
        account = setup.create_account(email="orgs@example.com")  # owns 1 (its default)
        processes = [ControlDB(path, pool=PoolConfig(min_size=1, max_size=2)) for _ in range(6)]
        barrier = threading.Barrier(len(processes))

        def create(db: ControlDB) -> bool:
            barrier.wait()
            try:
                db.create_owned_organization(account_id=account, name="x", limit=3)
            except LimitReachedError:
                return False
            return True

        with ThreadPoolExecutor(len(processes)) as pool:
            created = sum(pool.map(create, processes))

        assert created == 2  # 1 default + 2 = the limit of 3
        owned = [r for _, r in setup.list_organizations_for_account(account) if r == "owner"]
        assert len(owned) == 3


class TestOrganizationsAndMembers:
    def test_free_owns_one_organization(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        _refusal(
            client.post("/organizations", headers=headers, json={"name": "B"}), "organizations", 1
        )
        apply_tier_change(client.app.state.control_db, account, "medium")
        assert client.post("/organizations", headers=headers, json={"name": "B"}).status_code == 201

    def test_members_count_the_owner_and_a_role_change_never_counts(
        self, client: TestClient
    ) -> None:
        headers, _, org = verified_owner(client)
        _, first = create_verified_account(client)
        _, second = create_verified_account(client)
        path = f"/organizations/{org}/members"

        assert (
            client.post(
                path, headers=headers, json={"account_id": first, "role": "viewer"}
            ).status_code
            == 200
        )
        _refusal(
            client.post(path, headers=headers, json={"account_id": second, "role": "viewer"}),
            "members",
            2,
        )
        # At the limit, changing an existing member's role still works.
        assert (
            client.post(
                path, headers=headers, json={"account_id": first, "role": "owner"}
            ).status_code
            == 200
        )

    def test_data_over_a_limit_after_a_downgrade_is_kept(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        apply_tier_change(db, account, "pro")
        for name in ("B", "C"):
            assert (
                client.post("/organizations", headers=headers, json={"name": name}).status_code
                == 201
            )
        apply_tier_change(db, account, "free")

        assert len(client.get("/organizations", headers=headers).json()) == 3  # nothing removed
        _refusal(
            client.post("/organizations", headers=headers, json={"name": "D"}), "organizations", 1
        )


class TestImports:
    def _upload(
        self, client: TestClient, headers: dict[str, str], org: str, body: bytes, **params: Any
    ) -> Any:
        source = "nmap" if body.startswith(b"<") else "masscan"
        return client.post(
            f"/organizations/{org}/imports/{source}", headers=headers, content=body, params=params
        )

    def test_only_real_new_imports_count(self, client: TestClient) -> None:
        headers, account, org = verified_owner(client)
        db: ControlDB = client.app.state.control_db

        def used() -> int:
            return db.get_monthly_usage(account, subscriptions.current_period_key()).imports_used

        assert self._upload(client, headers, org, NMAP_XML, dry_run="true").status_code == 200
        assert (
            self._upload(
                client,
                headers,
                org,
                b"<not-nmap",
            ).status_code
            == 422
        )
        assert used() == 0  # a dry run and a rejected report are free
        assert self._upload(client, headers, org, NMAP_XML).status_code == 200
        assert self._upload(client, headers, org, NMAP_XML).status_code == 200  # re-import
        assert used() == 1
        assert self._upload(client, headers, org, MASSCAN_JSON).status_code == 200
        assert used() == 2
        _refusal(self._upload(client, headers, org, NMAP_XML.replace(b"10", b"11")), "imports", 2)


class TestIntegrations:
    def test_webhooks_and_the_subscription_view(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import api.routers.webhooks as webhooks_router

        async def allow(url: str) -> tuple[bool, str, str]:
            return True, "", "93.184.216.34"

        monkeypatch.setattr(webhooks_router, "validate_webhook_destination", allow)
        headers, _, _ = verified_owner(client)
        body = {"url": "https://hooks.example.com/x", "event_types": ["monitoring.changed"]}
        assert client.post("/webhooks", headers=headers, json=body).status_code == 201
        _refusal(client.post("/webhooks", headers=headers, json=body), "webhooks", 1)

        view = client.get("/account/subscription", headers=headers).json()
        assert view["webhooks_count"] == 1 and view["webhooks_limit"] == 1
        assert view["organizations_owned"] == 1 and view["organizations_limit"] == 1
        assert view["imports_limit"] == 2 and view["members_per_organization_limit"] == 2


class TestEntitlementsNeverAuthorize:
    def test_ultra_still_cannot_scan_an_unverified_domain(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        apply_tier_change(client.app.state.control_db, account, "ultra")
        response = client.post("/scans", headers=headers, json={"domain": "not-verified.example"})
        assert response.status_code == 403
        assert "is not verified for this account" in response.json()["detail"]
