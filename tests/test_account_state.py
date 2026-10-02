"""Productization Phase 12b: read-only suspension, the downgrade rule for
verified domains, and the scan priority queue."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _org_helpers import api_client, verified_owner
from _verified_domain import seed_verified_domain
from test_adversarial_api import OPERATOR, PUBLIC, ROUTES, Route, _call
from test_monitoring_worker import _make_due, _monitor, _RecordingEmailSender

from api.auth import _ALLOWED_WHILE_SUSPENDED
from api.control_db import ControlDB
from api.monitoring_worker import run_monitoring_cycle
from api.scan_worker import PRIORITY_TIERS
from api.settings import APISettings
from api.subscriptions import apply_tier_change

_WRITES = [
    r
    for r in ROUTES
    if r.method not in ("GET", "HEAD", "OPTIONS") and (r.method, r.path) not in PUBLIC | OPERATOR
]
_REFUSED = [r for r in _WRITES if (r.method, r.path) not in _ALLOWED_WHILE_SUSPENDED]
_ALLOWED = [r for r in _WRITES if (r.method, r.path) in _ALLOWED_WHILE_SUSPENDED]


def _suspended_account(tmp_path: Path) -> Any:
    with api_client(tmp_path) as client:
        headers, account, org = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        values = {
            "organization_id": org,
            "key_id": db.list_keys_for_account(account)[0].key_id,
            "account_id": account,
            "domain": "example.com",
        }
        db.set_subscription_status(account, "suspended")
        yield client, headers["X-API-Key"], values


@pytest.fixture(scope="module")
def suspended(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Shared by the refused writes, which change nothing."""
    yield from _suspended_account(tmp_path_factory.mktemp("suspended"))


@pytest.fixture
def fresh_suspended(tmp_path: Path) -> Any:
    """Its own account: the allowed writes rotate, revoke and delete."""
    yield from _suspended_account(tmp_path)


class TestReadOnlySuspension:
    def test_the_allow_list_names_real_routes(self) -> None:
        assert _ALLOWED_WHILE_SUSPENDED <= {(r.method, r.path) for r in ROUTES}

    @pytest.mark.parametrize("route", _REFUSED, ids=str)
    def test_every_other_write_is_402(self, suspended: Any, route: Route) -> None:
        client, key, values = suspended
        response = _call(client, route, values, key)
        assert response.status_code == 402, (str(route), response.text[:200])
        assert response.json()["detail"]["error"] == "account_suspended"

    @pytest.mark.parametrize("route", _ALLOWED, ids=str)
    def test_keys_billing_and_deletion_stay_open(self, fresh_suspended: Any, route: Route) -> None:
        client, key, values = fresh_suspended
        assert _call(client, route, values, key).status_code != 402

    def test_reads_and_export_stay_open(self, fresh_suspended: Any) -> None:
        client, key, values = fresh_suspended
        headers = {"X-API-Key": key}
        org = values["organization_id"]
        assert client.get("/organizations", headers=headers).status_code == 200
        assert client.get(f"/organizations/{org}/assets", headers=headers).status_code == 200
        assert client.get(f"/organizations/{org}/export", headers=headers).status_code == 200
        assert client.get("/account/export", headers=headers).status_code == 200

    def test_monitoring_stops_too_passive_included(self, tmp_path: Path) -> None:
        api_settings = APISettings(data_dir=tmp_path / "api_data")
        db = ControlDB(api_settings.control_db_path)
        account = db.create_account(email="mon@example.com")
        db.mark_email_verified(account)
        _verify(db, account, "example.com")
        row = _monitor(db, api_settings, account, "example.com")
        _make_due(db, row.monitoring_id)
        db.create_default_subscription(account)
        db.set_subscription_status(account, "suspended")

        run_monitoring_cycle(
            api_settings=api_settings, control_db=db, email_sender=_RecordingEmailSender()
        )

        org = db.default_organization_id_for_account(account)
        assert db.list_scans_for_organization(org) == []


def _verify(db: ControlDB, account: str, domain: str) -> None:
    """A currently valid verification (seed_verified_domain, without a client)."""

    class _Client:
        class app:  # noqa: N801 - mimics TestClient.app.state
            class state:  # noqa: N801
                control_db = db

    seed_verified_domain(_Client(), account, domain)  # type: ignore[arg-type]


class TestDowngradeKeepsTheOldestDomainsScannable:
    def test_only_the_tiers_oldest_n_can_be_scanned(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account, _ = verified_owner(client)
            db: ControlDB = client.app.state.control_db
            apply_tier_change(db, account, "medium")  # 3 verified domains
            for domain in ("first.example", "second.example", "third.example"):
                seed_verified_domain(client, account, domain)
            apply_tier_change(db, account, "free")  # 1

            # The over-limit domain first: Free's single monthly scan then
            # goes to the domain that is still scannable.
            third = client.post("/scans", headers=headers, json={"domain": "third.example"})
            first = client.post("/scans", headers=headers, json={"domain": "first.example"})
            opt_in = client.post(
                "/domains/second.example/monitoring", headers=headers, json={"speed2": False}
            )
            view = client.get("/account/subscription", headers=headers).json()

            assert first.status_code == 202
            assert third.status_code == 403
            assert third.json()["detail"]["entitlement"] == "verified_domains"
            assert "allows 1 verified domain." in third.json()["detail"]["message"]
            assert opt_in.status_code == 403
            assert view["unscannable_verified_domains"] == ["second.example", "third.example"]

            apply_tier_change(db, account, "medium")
            again = client.post("/scans", headers=headers, json={"domain": "third.example"})
            assert again.status_code == 202  # an upgrade restores it, no re-verification


class TestPriorityQueue:
    def test_paid_priority_tiers_are_claimed_first_then_the_oldest(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db")
        accounts = {}
        for tier in ("free", "pro", "medium", "ultra"):
            account = db.create_account(email=f"{tier}@example.com")
            db.create_default_subscription(account, tier=tier)
            accounts[tier] = account
        for tier in ("free", "pro", "medium", "ultra"):  # queued in this order
            db.create_scan(
                scan_id=f"scan-{tier}", account_id=accounts[tier], domain="x.example", db_path="x"
            )

        claimed = []
        while (scan := db.claim_next_queued_scan("w", PRIORITY_TIERS)) is not None:
            claimed.append(scan.scan_id)

        assert PRIORITY_TIERS == ("pro", "ultra")
        assert claimed == ["scan-pro", "scan-ultra", "scan-free", "scan-medium"]

    def test_without_priority_tiers_it_is_plain_oldest_first(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db")
        for i, tier in enumerate(("free", "ultra")):
            account = db.create_account(email=f"{tier}{i}@example.com")
            db.create_default_subscription(account, tier=tier)
            db.create_scan(scan_id=f"scan-{i}", account_id=account, domain="x.example", db_path="x")
        first = db.claim_next_queued_scan("w")
        assert first is not None and first.scan_id == "scan-0"
