"""Productization Phase 13a: one error shape for every failure, retry
semantics, the version endpoint and the support diagnostics."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from _org_helpers import api_client, verified_owner
from _verified_account import create_verified_account, unique_email
from _verified_domain import seed_verified_domain
from fastapi.testclient import TestClient
from test_adversarial_api import PUBLIC, ROUTES, Route, _call

from api.control_db import ControlDB
from api.errors import code_for
from api.main import create_app
from api.settings import APISettings
from api.subscriptions import apply_tier_change
from api.version import API_VERSION, HYDRA_VERSION

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path: Path) -> Any:
    with api_client(tmp_path) as test_client:
        yield test_client


def _envelope(response: Any, status: int, code: str | None = None) -> dict[str, Any]:
    """The response is `status`, keeps a `detail`, and carries the error
    object; returns that object."""
    assert response.status_code == status, response.text[:300]
    body = response.json()
    assert "detail" in body
    error = body["error"]
    assert set(error) == {"code", "message", "request_id", "retryable"}
    assert error["code"] == (code or code_for(status, body["detail"]))
    assert isinstance(error["message"], str) and error["message"]
    assert error["request_id"] == response.headers["X-Request-ID"]
    return dict(error)


class TestEveryErrorHasTheEnvelope:
    @pytest.mark.parametrize(
        "route", [r for r in ROUTES if (r.method, r.path) not in PUBLIC], ids=str
    )
    def test_every_protected_route_without_a_key(self, client: TestClient, route: Route) -> None:
        response = _call(client, route, {}, None)
        _envelope(response, 401, "unauthenticated")

    def test_unknown_path_and_wrong_method(self, client: TestClient) -> None:
        _envelope(client.get("/no-such-thing"), 404, "not_found")
        _envelope(client.put("/health"), 405, "method_not_allowed")

    def test_validation_keeps_fastapis_detail_list(self, client: TestClient) -> None:
        response = client.post("/accounts", json={})
        error = _envelope(response, 422, "validation_failed")
        assert isinstance(response.json()["detail"], list)  # unchanged shape
        assert error["message"].startswith("body.email")

    def test_the_edges_own_refusals(self, client: TestClient) -> None:
        _envelope(client.get("/organizations", params={"q": "a\x00b"}), 400, "bad_request")
        too_big = client.post("/accounts", content=b"x", headers={"Content-Length": str(10**9)})
        _envelope(too_big, 413, "payload_too_large")

    def test_an_unhandled_exception_is_json_with_a_request_id(self, tmp_path: Path) -> None:
        app = create_app(APISettings(data_dir=tmp_path / "api", max_concurrent_scans=0))

        def boom() -> None:
            raise RuntimeError("secret internal detail")

        app.add_api_route("/boom", boom)
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.get("/boom")
        error = _envelope(response, 500, "internal_error")
        assert error["retryable"] is False
        assert "secret internal detail" not in response.text
        assert response.headers["X-Content-Type-Options"] == "nosniff"  # edge headers too
        # Still raised to the server, which logs it. (No second startup:
        # /boom needs none, and the backup loop would start twice.)
        with pytest.raises(RuntimeError, match="secret internal detail"):
            TestClient(app).get("/boom")

    def test_a_structured_detail_lends_its_code(self, client: TestClient) -> None:
        headers, _, _ = verified_owner(client)
        response = client.post("/organizations", headers=headers, json={"name": "B"})
        error = _envelope(response, 403, "entitlement_exceeded")
        assert error["message"] == response.json()["detail"]["message"]


class TestSpecificCodes:
    def test_onboarding_failures(self, client: TestClient) -> None:
        signup = client.post("/accounts", json={"email": unique_email()}).json()
        headers = {"X-API-Key": signup["api_key"]}
        scan = client.post("/scans", headers=headers, json={"domain": "example.com"})
        _envelope(scan, 403, "email_not_verified")
        _envelope(
            client.post("/accounts/verify-email", json={"token": "x" * 43}),
            404,
            "verification_token_invalid",
        )

        client.app.state.control_db.mark_email_verified(signup["account_id"])
        scan = client.post("/scans", headers=headers, json={"domain": "example.com"})
        _envelope(scan, 403, "domain_not_verified")
        opt_in = client.post("/domains/example.com/monitoring", headers=headers, json={})
        _envelope(opt_in, 403, "domain_not_verified")

    def test_scan_quota_and_a_scan_not_completed(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        seed_verified_domain(client, account, "example.com")
        first = client.post("/scans", headers=headers, json={"domain": "example.com"})
        assert first.status_code == 202
        report = client.get(f"/scans/{first.json()['scan_id']}/report", headers=headers)
        _envelope(report, 409, "scan_not_completed")
        second = client.post("/scans", headers=headers, json={"domain": "example.com"})
        _envelope(second, 403, "scan_quota_exceeded")

    def test_owner_role_required(self, client: TestClient) -> None:
        owner_headers, _, org = verified_owner(client)
        viewer_key, viewer = create_verified_account(client)
        client.post(
            f"/organizations/{org}/members",
            headers=owner_headers,
            json={"account_id": viewer, "role": "viewer"},
        )
        response = client.post(
            f"/organizations/{org}/scope/exclusions",
            headers={"X-API-Key": viewer_key},
            json={"pattern": "x.example.com", "reason": "r"},
        )
        _envelope(response, 403, "owner_role_required")

    def test_suspended(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        client.app.state.control_db.set_subscription_status(account, "suspended")
        _envelope(
            client.post("/organizations", headers=headers, json={"name": "B"}),
            402,
            "account_suspended",
        )


class TestRetrySemantics:
    def test_a_rate_limited_key_is_told_when_to_retry(self, tmp_path: Path) -> None:
        settings = APISettings(
            data_dir=tmp_path / "api", max_concurrent_scans=0, rate_limit_per_minute=2
        )
        with TestClient(create_app(settings)) as c:
            headers, _, _ = verified_owner(c)
            responses = [c.get("/organizations", headers=headers) for _ in range(4)]
        limited = responses[-1]
        error = _envelope(limited, 429, "rate_limited")
        assert error["retryable"] is True
        assert limited.headers["Retry-After"] == "30"

    def test_account_creation_limit_says_when_to_retry(self, tmp_path: Path) -> None:
        settings = APISettings(
            data_dir=tmp_path / "api",
            max_concurrent_scans=0,
            account_creation_rate_limit_per_ip_per_day=1,
        )
        with TestClient(create_app(settings)) as c:
            c.post("/accounts", json={"email": unique_email()})
            limited = c.post("/accounts", json={"email": unique_email()})
        assert _envelope(limited, 429, "rate_limited")["retryable"] is True
        assert limited.headers["Retry-After"] == "3600"

    def test_missing_configuration_is_not_retryable(self, client: TestClient) -> None:
        headers, _, _ = verified_owner(client)
        response = client.post(
            "/account/subscription",
            headers=headers,
            json={"tier": "pro", "billing_email": "billing@example.com"},
        )
        assert _envelope(response, 503, "unavailable")["retryable"] is False
        assert "Retry-After" not in response.headers

    def test_client_errors_are_never_retryable(self, client: TestClient) -> None:
        assert _envelope(client.get("/no-such-thing"), 404)["retryable"] is False


class TestVersion:
    def test_public_and_without_the_build_commit(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HYDRA_BUILD_COMMIT", "abc123")
        response = client.get("/version")
        assert response.status_code == 200
        assert response.json() == {"version": HYDRA_VERSION, "api_version": API_VERSION}

    def test_one_version_everywhere(self, client: TestClient) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text()  # no tomllib on 3.10
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.M)
        assert declared is not None and declared[1] == HYDRA_VERSION
        assert f'version="Hydra {HYDRA_VERSION}"' in (ROOT / "app.py").read_text()
        assert client.get("/openapi.json").json()["info"]["version"] == HYDRA_VERSION


class TestDiagnostics:
    def test_a_new_unverified_account(self, client: TestClient) -> None:
        signup = client.post("/accounts", json={"email": unique_email()}).json()
        response = client.get("/account/diagnostics", headers={"X-API-Key": signup["api_key"]})
        assert response.status_code == 200
        body = response.json()
        assert body["request_id"] == response.headers["X-Request-ID"]
        assert (body["account_id"], body["email_verified"], body["tier"]) == (
            signup["account_id"],
            False,
            "free",
        )
        assert any(h.startswith("Email not verified") for h in body["hints"])
        assert any(h.startswith("No verified domain yet") for h in body["hints"])
        assert signup["api_key"] not in response.text  # never key material

    def test_the_build_commit_and_a_failed_scan(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HYDRA_BUILD_COMMIT", "abc123")
        headers, account, _ = verified_owner(client)
        seed_verified_domain(client, account, "example.com")
        scan_id = client.post("/scans", headers=headers, json={"domain": "example.com"}).json()[
            "scan_id"
        ]
        db: ControlDB = client.app.state.control_db
        db.update_scan_status(scan_id, "failed", error_message="provider timed out")

        body = client.get("/account/diagnostics", headers=headers).json()
        assert body["build_commit"] == "abc123"
        assert body["verified_domains"] == 1 and body["scans_used_this_period"] == 1
        assert [(s["scan_id"], s["status"], s["error_message"]) for s in body["recent_scans"]] == [
            (scan_id, "failed", "provider timed out")
        ]
        assert any(h.startswith("This month's scans are used up") for h in body["hints"])

    def test_only_the_callers_own_scans(self, client: TestClient) -> None:
        owner_headers, owner, org = verified_owner(client)
        apply_tier_change(client.app.state.control_db, owner, "medium")
        seed_verified_domain(client, owner, "example.com")
        client.post("/scans", headers=owner_headers, json={"domain": "example.com"})
        member_key, member = create_verified_account(client)
        client.post(
            f"/organizations/{org}/members",
            headers=owner_headers,
            json={"account_id": member, "role": "viewer"},
        )
        body = client.get("/account/diagnostics", headers={"X-API-Key": member_key}).json()
        assert body["account_id"] == member
        assert body["recent_scans"] == []
        assert "example.com" not in str(body)

    def test_suspended_and_over_the_domain_limit(self, client: TestClient) -> None:
        headers, account, _ = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        apply_tier_change(db, account, "medium")
        for domain in ("a.example", "b.example"):
            seed_verified_domain(client, account, domain)
        apply_tier_change(db, account, "free")
        db.set_subscription_status(account, "suspended")

        body = client.get("/account/diagnostics", headers=headers).json()
        assert body["unscannable_verified_domains"] == ["b.example"]
        assert any(h.startswith("Account suspended") for h in body["hints"])
        assert any("beyond the tier's limit" in h for h in body["hints"])

    def test_the_ten_newest_scans_in_one_query(self, client: TestClient) -> None:
        headers, account, org = verified_owner(client)
        db: ControlDB = client.app.state.control_db
        for i in range(12):  # padded ids: the tie-break agrees with creation order
            db.create_scan(
                scan_id=f"scan-{i:02d}",
                account_id=account,
                domain="example.com",
                db_path="x",
                organization_id=org,
            )
        body = client.get("/account/diagnostics", headers=headers).json()
        assert [s["scan_id"] for s in body["recent_scans"]] == [
            f"scan-{i:02d}" for i in range(11, 1, -1)
        ]


def test_every_specific_code_is_documented() -> None:
    used = set()
    for path in (ROOT / "api").rglob("*.py"):
        source = path.read_text()
        used |= set(re.findall(r'code="([a-z_]+)"', source))  # ApiError
        used |= set(re.findall(r'"error": "([a-z_]+)"', source))  # structured detail
    doc = (ROOT / "docs/productization/13a_errors_and_diagnostics.md").read_text()
    assert used, "no specific codes found"
    assert {c for c in used if f"`{c}`" not in doc} == set()
