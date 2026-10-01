"""Productization Phase 11b: the security audit log and operator accounts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _verified_account import create_verified_account
from _webhook_test_server import (
    reset_webhook_test_state,
    start_webhook_test_server,
    stop_webhook_test_server,
)
from fastapi.testclient import TestClient
from test_ticketing_integrations import JIRA_CREDENTIAL, KEY, _connect_jira

import api.routers.webhooks as webhooks_router
from api import operators
from api.main import create_app
from api.settings import APISettings


@pytest.fixture
def client(tmp_path: Path) -> Any:
    settings = APISettings(data_dir=tmp_path / "api", secrets_keys=KEY, max_concurrent_scans=0)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def jira(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A local stand-in for a Jira site (as in test_ticketing_integrations)."""
    import api.webhooks as webhooks_module

    httpd, port, thread, tmp_dir = start_webhook_test_server()
    reset_webhook_test_state(status=201, body=b'{"id": "10001", "key": "SEC-1"}')

    async def loopback(url: str) -> tuple[bool, str, str]:
        return True, "", "127.0.0.1"

    monkeypatch.setattr(webhooks_module, "validate_webhook_destination", loopback)
    monkeypatch.setattr("api.routers.integrations.validate_webhook_destination", loopback)
    try:
        yield f"https://localhost:{port}"
    finally:
        stop_webhook_test_server(httpd, thread, tmp_dir)


def _account(client: TestClient) -> tuple[dict[str, str], str, str]:
    key, account_id = create_verified_account(client)
    org = client.app.state.control_db.default_organization_id_for_account(account_id)
    return {"X-API-Key": key}, account_id, org


def _operator(client: TestClient) -> dict[str, str]:
    headers, account_id, _ = _account(client)
    operators.set_operator(client.app.state.control_db, account_id, True)
    return headers


def _actions(events: list[dict[str, Any]]) -> list[str]:
    return [e["action"] for e in events]


def _mine(client: TestClient, headers: dict[str, str]) -> list[dict[str, Any]]:
    response = client.get("/account/security-events", headers=headers)
    assert response.status_code == 200
    return response.json()


class TestKeys:
    def test_the_key_lifecycle_is_recorded_without_any_key(self, client: TestClient) -> None:
        response = client.post("/accounts", json={"email": "keys@example.com"})
        raw_key, key_id = response.json()["api_key"], response.json()["key_id"]
        headers = {"X-API-Key": raw_key}
        rotated = client.post(f"/keys/{key_id}/rotate", headers=headers).json()
        new_headers = {"X-API-Key": rotated["new_api_key"]}
        assert client.post(f"/keys/{key_id}/revoke", headers=new_headers).status_code == 204

        events = _mine(client, new_headers)
        assert _actions(events)[::-1] == [
            "account.created",
            "key.created",
            "key.rotated",
            "key.revoked",
        ]
        assert events[1]["target_id"] == key_id  # newest first: the rotation
        assert events[1]["details"]["new_key_id"] == rotated["new_key_id"]
        text = str(events)
        assert raw_key not in text and rotated["new_api_key"] not in text

    def test_the_request_id_and_client_are_recorded(self, client: TestClient) -> None:
        response = client.post(
            "/accounts",
            json={"email": "rid@example.com"},
            headers={"X-Request-ID": "trace-0001-abc"},
        )
        events = _mine(client, {"X-API-Key": response.json()["api_key"]})
        assert {e["request_id"] for e in events} == {"trace-0001-abc"}
        assert all(e["client_ip"] for e in events)


class TestFailedSignIns:
    def test_recorded_once_per_client_per_minute_and_never_the_key(
        self, client: TestClient
    ) -> None:
        for _ in range(5):
            assert (
                client.get("/organizations", headers={"X-API-Key": "hk_guess"}).status_code == 401
            )
        events = client.get("/admin/security-events", headers=_operator(client)).json()
        failures = [e for e in events if e["action"] == "auth.failed"]
        assert len(failures) == 1
        assert failures[0]["actor_type"] == "anonymous"
        assert failures[0]["details"] == {"reason": "invalid", "path": "/organizations"}
        assert "hk_guess" not in str(events)


class TestMembers:
    def test_member_changes_and_who_can_read_them(self, client: TestClient) -> None:
        owner, _, org = _account(client)
        member, member_id, _ = _account(client)
        outsider, _, _ = _account(client)
        path = f"/organizations/{org}/members"

        client.post(path, headers=owner, json={"account_id": member_id, "role": "viewer"})
        client.post(path, headers=owner, json={"account_id": member_id, "role": "viewer"})
        client.post(path, headers=owner, json={"account_id": member_id, "role": "owner"})
        client.delete(f"{path}/{member_id}", headers=owner)

        events = client.get(f"/organizations/{org}/security-events", headers=owner).json()
        member_events = [e for e in events if e["target_id"] == member_id]
        assert _actions(member_events)[::-1] == [
            "member.added",  # the identical second POST changed nothing: no event
            "member.role_changed",
            "member.removed",
        ]
        assert member_events[1]["details"] == {"previous_role": "viewer", "role": "owner"}
        # The member sees what concerned them on their own account view.
        assert "member.added" in _actions(_mine(client, member))
        # IDOR: an outsider learns nothing, the API never confirms the org exists.
        response = client.get(f"/organizations/{org}/security-events", headers=outsider)
        assert response.status_code == 404

    def test_a_viewer_cannot_read_the_organization_log(self, client: TestClient) -> None:
        owner, _, org = _account(client)
        viewer, viewer_id, _ = _account(client)
        client.post(
            f"/organizations/{org}/members",
            headers=owner,
            json={"account_id": viewer_id, "role": "viewer"},
        )
        response = client.get(f"/organizations/{org}/security-events", headers=viewer)
        assert response.status_code == 403

    def test_a_new_organization_is_recorded_in_it(self, client: TestClient) -> None:
        owner, _, _ = _account(client)
        org = client.post("/organizations", headers=owner, json={"name": "Client B"}).json()
        events = client.get(
            f"/organizations/{org['organization_id']}/security-events", headers=owner
        ).json()
        assert _actions(events) == ["organization.created"]


class TestIntegrations:
    def test_webhooks_record_only_the_host(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def allow(url: str) -> tuple[bool, str, str]:
            return True, "", "93.184.216.34"

        monkeypatch.setattr(webhooks_router, "validate_webhook_destination", allow)
        headers, _, _ = _account(client)
        secret_path = "/services/T000/B000/XXXXSECRETXXXX"
        hook = client.post(
            "/webhooks",
            headers=headers,
            json={
                "url": f"https://hooks.slack.com{secret_path}",
                "event_types": ["monitoring.changed"],
                "kind": "slack",
            },
        ).json()
        client.delete(f"/webhooks/{hook['webhook_id']}", headers=headers)

        events = _mine(client, headers)
        created = next(e for e in events if e["action"] == "webhook.created")
        assert created["details"] == {"host": "hooks.slack.com", "kind": "slack"}
        assert "webhook.deleted" in _actions(events)
        assert "XXXXSECRETXXXX" not in str(events) and hook["secret"] not in str(events)

    def test_ticketing_integrations_never_record_the_credential(
        self, client: TestClient, jira: str
    ) -> None:
        owner, _, org = _account(client)
        integration = _connect_jira(client, owner, org, jira).json()
        client.delete(
            f"/organizations/{org}/integrations/{integration['integration_id']}", headers=owner
        )

        events = client.get(f"/organizations/{org}/security-events", headers=owner).json()
        assert _actions(events)[:2] == ["integration.removed", "integration.created"]
        assert events[1]["details"]["provider"] == "jira"
        assert all(str(value) not in str(events) for value in JIRA_CREDENTIAL.values())


class TestOperators:
    def test_admin_access_needs_an_operator_and_is_recorded(self, client: TestClient) -> None:
        plain, _, _ = _account(client)
        assert client.get("/admin/security-events", headers=plain).status_code == 404
        assert client.get("/admin/wompi/unmatched", headers=plain).status_code == 404

        operator = _operator(client)
        assert client.get("/admin/wompi/unmatched", headers=operator).status_code == 200
        events = client.get("/admin/security-events", headers=operator).json()
        listed = next(e for e in events if e["action"] == "admin.payments_listed")
        assert listed["actor_type"] == "operator" and listed["actor_account_id"]

    def test_the_cli_grants_revokes_and_lists(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        db = client.app.state.control_db
        headers, account_id, _ = _account(client)
        email = next(e for a, e in [(account_id, db.get_account(account_id).email)] if a)
        monkeypatch.setattr(operators, "_control_db", lambda: db)

        assert operators.main(["grant", email.upper()]) == 0
        assert db.is_operator(account_id)
        assert operators.main(["list"]) == 0
        assert operators.main(["revoke", account_id]) == 0
        assert not db.is_operator(account_id)
        assert operators.main(["grant", "nobody@example.com"]) == 1

        out = capsys.readouterr()
        assert account_id in out.out and "no account" in out.err
        events = _mine(client, headers)
        granted = next(e for e in events if e["action"] == "operator.granted")
        assert granted["actor_type"] == "host" and granted["details"]["host_user"]
        assert "operator.revoked" in _actions(events)
