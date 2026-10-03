"""Productization Phase 13b: the demo organization and feedback."""

from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from _org_helpers import api_client, verified_owner
from _verified_account import create_verified_account
from fastapi.testclient import TestClient
from test_adversarial_api import ROUTES, Route, _call

import api.routers.feedback as feedback_router
from api.auth import _ALLOWED_ON_DEMO
from api.control_db import ControlDB
from api.db import PoolConfig
from api.demo import DEMO_TRIGGER_SOURCE, demo_hosts
from api.main import create_app
from api.settings import APISettings
from api.subscriptions import apply_tier_change
from api.tenancy import account_settings
from api.tenant_lifecycle import purge_organization_now

_RESERVED_NAMES = ("example.com", "example.net", "example.org")
_DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_DEMO_WRITES = [
    r
    for r in ROUTES
    if r.method not in ("GET", "HEAD", "OPTIONS") and "organization_id" in r.params
]


@pytest.fixture
def client(tmp_path: Path) -> Any:
    with api_client(tmp_path) as test_client:
        yield test_client


def _demo(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post("/demo/organization", headers=headers)
    assert response.status_code in (200, 201), response.text
    return str(response.json()["organization_id"])


def _reserved_name(name: str) -> bool:
    name = name.lower().rstrip(".")
    return name.endswith(".test") or any(
        name == r or name.endswith("." + r) for r in _RESERVED_NAMES
    )


class TestTheFixturesAreSafe:
    def test_every_name_and_address_is_reserved_for_documentation(self) -> None:
        for host in demo_hosts():
            names = [host.domain, *(r.host for r in host.dns_records)]
            names += [s.host for s in host.http_services] + [f.host for f in host.findings]
            names += host.tls.sans if host.tls else []
            names += [r.value for r in host.dns_records if r.record_type in ("MX", "CNAME")]
            assert all(_reserved_name(n) for n in names), names
            for url in [s.url for s in host.http_services] + [f.url or "" for f in host.findings]:
                assert _reserved_name(url.split("/")[2].split(":")[0]), url
            addresses = host.ips + [r.value for r in host.dns_records if r.record_type == "A"]
            for address in addresses:
                ip = ipaddress.ip_address(address)
                assert any(ip in net for net in _DOCUMENTATION_NETWORKS), address


class TestTheDemoOrganization:
    def test_created_once_labelled_and_full_of_real_engine_output(self, client: TestClient) -> None:
        headers, _, _ = verified_owner(client)
        first = client.post("/demo/organization", headers=headers)
        again = client.post("/demo/organization", headers=headers)
        assert (first.status_code, again.status_code) == (201, 200)
        org = first.json()["organization_id"]
        assert again.json()["organization_id"] == org and first.json()["is_demo"] is True

        listed = {
            o["organization_id"]: o["is_demo"]
            for o in client.get("/organizations", headers=headers).json()
        }
        assert listed[org] is True and list(listed.values()).count(True) == 1

        assets = client.get(f"/organizations/{org}/assets", headers=headers).json()
        assert all(
            _reserved_name(a["identity_key"].split(":")[1])
            for a in assets
            if a["asset_type"] == "domain"
        )
        exposures = client.get(f"/organizations/{org}/exposures", headers=headers).json()
        assert sorted(e["severity"] for e in exposures) == ["high", "low", "medium"]
        high = next(e for e in exposures if e["severity"] == "high")
        evidence = client.get(
            f"/organizations/{org}/exposures/{high['exposure_id']}/evidence", headers=headers
        ).json()
        assert evidence[0]["finding"]["url"] == "https://staging.example.com/wp-admin"

    def test_one_demo_even_under_concurrency(self, tmp_path: Path) -> None:
        path = tmp_path / "control.db"
        account = ControlDB(path).create_account(email="race@example.com")
        processes = [ControlDB(path, pool=PoolConfig(min_size=1, max_size=2)) for _ in range(6)]
        barrier = threading.Barrier(len(processes))

        def create(db: ControlDB) -> tuple[str, bool]:
            barrier.wait()
            return db.create_demo_organization(account_id=account, name="Demo")

        with ThreadPoolExecutor(len(processes)) as pool:
            results = list(pool.map(create, processes))
        assert len({org for org, _ in results}) == 1
        assert [created for _, created in results].count(True) == 1


class TestReadOnly:
    @pytest.fixture(scope="class")
    def world(self, tmp_path_factory: pytest.TempPathFactory) -> Any:
        with api_client(tmp_path_factory.mktemp("demo")) as client:
            headers, account, _ = verified_owner(client)
            org = _demo(client, headers)
            yield client, headers["X-API-Key"], {"organization_id": org, "account_id": account}

    @pytest.mark.parametrize(
        "route", [r for r in _DEMO_WRITES if (r.method, r.path) not in _ALLOWED_ON_DEMO], ids=str
    )
    def test_every_write_is_refused(self, world: Any, route: Route) -> None:
        client, key, values = world
        response = _call(client, route, values, key)
        assert response.status_code == 403, (str(route), response.text[:200])
        assert response.json()["error"]["code"] == "demo_organization_read_only"

    def test_a_non_member_sees_nothing_not_even_that_it_is_a_demo(self, world: Any) -> None:
        client, _, values = world
        stranger_key, _ = create_verified_account(client)
        response = client.post(
            f"/organizations/{values['organization_id']}/scope/exclusions",
            headers={"X-API-Key": stranger_key},
            json={"pattern": "x.example.com", "reason": "r"},
        )
        assert response.status_code == 404

    def test_it_can_be_deleted_and_made_again(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        org = _demo(client, headers)
        assert client.delete(f"/organizations/{org}", headers=headers).status_code == 202
        purge_organization_now(db, client.app.state.api_settings, org)
        assert db.get_organization(org) is None
        assert _demo(client, headers) != org


class TestNeverScannedNorCounted:
    def test_not_counted_against_organizations_or_scans(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)  # Free: 1 organization
        _demo(client, headers)
        view = client.get("/account/subscription", headers=headers).json()
        assert view["organizations_owned"] == 1 and view["scans_used_this_period"] == 0
        refused = client.post("/organizations", headers=headers, json={"name": "B"})
        assert refused.json()["error"]["code"] == "entitlement_exceeded"
        apply_tier_change(client.app.state.control_db, account, "medium")  # 3
        for name in ("B", "C"):
            assert (
                client.post("/organizations", headers=headers, json={"name": name}).status_code
                == 201
            )

    def test_scans_never_target_it_and_retention_never_purges_it(self, client: TestClient) -> None:
        headers, account, default_org = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        org = _demo(client, headers)
        assert db.default_organization_id_for_account(account) == default_org != org
        purgeable = db.list_purgeable_scans_for_account(account, cutoff="9999", limit=100)
        assert [s for s in purgeable if s.trigger_source == DEMO_TRIGGER_SOURCE] == []
        (demo_scan,) = db.list_scans_for_organization(org)
        assert demo_scan.trigger_source == "demo"
        # Recorded like every real scan's.
        settings = account_settings(client.app.state.api_settings, account)
        assert demo_scan.db_path == str(settings.project_root)


class TestNoWorkerEverRunsTheDemoScan:
    """Found by the 13c acceptance test: the demo scan was inserted
    `queued` and completed a moment later, so a running scan worker could
    claim it and really scan example.com."""

    def test_the_claim_skips_demo_scans_even_if_one_were_queued(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db")
        account = db.create_account(email="claim@example.com")
        db.create_scan(
            scan_id="queued-demo",
            account_id=account,
            domain="example.com",
            db_path="x",
            trigger_source="demo",
        )
        assert db.claim_next_queued_scan("w") is None

    def test_creating_a_demo_with_workers_running_never_runs_a_pipeline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ran: list[str] = []

        async def pipeline(settings: Any, *, domain: str, targets_file: Any, run_id: str) -> Any:
            ran.append(domain)
            raise RuntimeError("a demo scan must never run")

        monkeypatch.setattr("app._run_headless_pipeline", pipeline)
        settings = APISettings(
            data_dir=tmp_path / "api", max_concurrent_scans=2, scan_poll_interval_seconds=0.01
        )
        with TestClient(create_app(settings)) as c:
            headers, _, _ = verified_owner(c)
            org = _demo(c, headers)
            time.sleep(0.3)  # many worker poll cycles
            (scan,) = c.app.state.control_db.list_scans_for_organization(org)
        assert ran == [] and (scan.status, scan.worker_id) == ("completed", None)


class TestFeedback:
    def test_stored_with_the_request_id_and_release(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        response = client.post(
            "/feedback", headers=headers, json={"category": "idea", "message": "Dark mode?"}
        )
        assert response.status_code == 201
        body = response.json()
        assert (body["account_id"], body["category"], body["message"]) == (
            account,
            "idea",
            "Dark mode?",
        )
        assert body["request_id"] == response.headers["X-Request-ID"]
        export = client.get("/account/export", headers=headers).json()
        assert [f["feedback_id"] for f in export["feedback"]] == [body["feedback_id"]]

    @pytest.mark.parametrize(
        "body",
        [
            {"category": "idea", "message": ""},
            {"category": "idea", "message": "x" * 4001},
            {"category": "complaint", "message": "x"},
            {"message": "x"},
        ],
    )
    def test_bounded_and_validated(self, client: TestClient, body: dict[str, str]) -> None:
        headers, _, _ = verified_owner(client)
        response = client.post("/feedback", headers=headers, json=body)
        assert response.status_code == 422

    def test_rate_limited_per_account(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(feedback_router, "DAILY_LIMIT", 2)
        headers, _, _ = verified_owner(client)
        other, _ = create_verified_account(client)
        body = {"category": "bug", "message": "x"}
        codes = [client.post("/feedback", headers=headers, json=body).status_code for _ in range(3)]
        assert codes == [201, 201, 429]
        limited = client.post("/feedback", headers=headers, json=body)
        assert limited.headers["Retry-After"] == "3600"
        assert limited.json()["error"]["retryable"] is True
        assert client.post("/feedback", headers={"X-API-Key": other}, json=body).status_code == 201

    def test_a_suspended_account_can_still_reach_us(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        client.app.state.control_db.set_subscription_status(account, "suspended")
        body = {"category": "question", "message": "Why am I suspended?"}
        assert client.post("/feedback", headers=headers, json=body).status_code == 201

    def test_operators_read_it_everyone_else_gets_404(self, client: TestClient) -> None:
        headers, _, _ = verified_owner(client)
        client.post("/feedback", headers=headers, json={"category": "bug", "message": "secret-ish"})
        operator_key, operator = create_verified_account(client)
        db: ControlDB = client.app.state.control_db
        db.set_operator(operator, True)

        assert client.get("/admin/feedback", headers=headers).status_code == 404
        listed = client.get("/admin/feedback", headers={"X-API-Key": operator_key}).json()
        assert [f["message"] for f in listed] == ["secret-ish"]

        events = db.list_security_events(limit=50, offset=0)
        submitted = next(e for e in events if e.action == "feedback.submitted")
        assert "secret-ish" not in submitted.details_json  # the text never reaches the log
        assert any(e.action == "admin.feedback_listed" for e in events)

    def test_deleted_with_the_account(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        client.post("/feedback", headers=headers, json={"category": "bug", "message": "x"})
        db.purge_account(account)
        assert db.list_feedback_for_account(account) == []
