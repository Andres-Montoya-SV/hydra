"""Productization Phase 08b: Jira / Linear / ServiceNow ticketing.

Wire formats are checked against each provider's documented request and
response shapes; end-to-end runs point a Jira integration at a real local
HTTPS server standing in for the Jira site (no real service is called)."""

from __future__ import annotations

import base64
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from _verified_account import create_verified_account
from _webhook_test_server import (
    WebhookTestHandler,
    reset_webhook_test_state,
    start_webhook_test_server,
    stop_webhook_test_server,
)
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from test_api_exposure_operations import _seed_exposure

from api import integration_worker
from api.control_db import ControlDB
from api.integration_worker import run_integration_delivery_cycle
from api.main import create_app
from api.secrets_box import SecretBox
from api.settings import APISettings
from api.ticketing import (
    LINEAR_API_URL,
    TicketingConfigError,
    build_request,
    parse_response,
    validate,
)
from api.webhooks import generate_webhook_secret

KEY = Fernet.generate_key().decode()
JIRA_CREDENTIAL = {"email": "bot@acme.example", "api_token": "jira-token-DO-NOT-LEAK"}
EXPOSURE = {
    "exposure_id": "exp-1",
    "asset_id": "asset-1",
    "title": "Admin exposed",
    "severity": "high",
}


class TestValidation:
    def test_valid_configs_are_normalized(self) -> None:
        assert (
            validate(
                "jira",
                {"site_url": "https://acme.atlassian.net/", "project_key": "SEC"},
                JIRA_CREDENTIAL,
            )["site_url"]
            == "https://acme.atlassian.net"
        )
        assert validate("linear", {"team_id": "team-uuid"}, {"api_key": "lin_api_x"})
        assert validate(
            "servicenow",
            {"instance_url": "https://acme.service-now.com"},
            {"username": "u", "password": "p"},
        )

    @pytest.mark.parametrize(
        ("provider", "config", "credential", "message"),
        [
            ("github", {}, {}, "unknown provider"),
            ("jira", {"site_url": "https://a.example"}, JIRA_CREDENTIAL, "project_key"),
            (
                "jira",
                {"site_url": "https://a.example", "project_key": "SEC"},
                {"email": "e"},
                "api_token",
            ),
            (
                "jira",
                {"site_url": "http://a.example", "project_key": "SEC"},
                JIRA_CREDENTIAL,
                "https",
            ),
            (
                "jira",
                {"site_url": "https://a.example", "project_key": "sec; DROP"},
                JIRA_CREDENTIAL,
                "project key",
            ),
            (
                "servicenow",
                {"instance_url": "https://a.example?x=1"},
                {"username": "u", "password": "p"},
                "https",
            ),
        ],
    )
    def test_invalid_configs_are_rejected(
        self, provider: str, config: dict, credential: dict, message: str
    ) -> None:
        with pytest.raises(TicketingConfigError, match=message):
            validate(provider, config, credential)


class TestWireFormats:
    def test_jira_create_issue(self) -> None:
        config = {"site_url": "https://acme.atlassian.net", "project_key": "SEC"}

        request = build_request("jira", config, JIRA_CREDENTIAL, "exposure.opened", EXPOSURE)

        body = json.loads(request.body)
        assert request.url == "https://acme.atlassian.net/rest/api/3/issue"
        assert base64.b64decode(request.headers["Authorization"].split()[1]).decode() == (
            "bot@acme.example:jira-token-DO-NOT-LEAK"
        )
        assert body["fields"]["project"] == {"key": "SEC"}
        assert body["fields"]["issuetype"] == {"name": "Task"}
        assert body["fields"]["summary"] == "[Hydra] Admin exposed (high)"
        assert body["fields"]["description"]["type"] == "doc"
        assert parse_response("jira", config, 201, b'{"id": "10001", "key": "SEC-7"}') == (
            "SEC-7",
            "https://acme.atlassian.net/browse/SEC-7",
        )

    def test_linear_issue_create(self) -> None:
        request = build_request(
            "linear", {"team_id": "team-1"}, {"api_key": "lin_api_x"}, "exposure.opened", EXPOSURE
        )

        body = json.loads(request.body)
        assert (request.url, request.headers["Authorization"]) == (LINEAR_API_URL, "lin_api_x")
        assert "issueCreate" in body["query"]
        assert body["variables"]["input"]["teamId"] == "team-1"
        ok = (
            b'{"data": {"issueCreate": {"success": true, "issue": '
            b'{"identifier": "SEC-3", "url": "https://linear.app/acme/issue/SEC-3"}}}}'
        )
        assert parse_response("linear", {}, 200, ok) == (
            "SEC-3",
            "https://linear.app/acme/issue/SEC-3",
        )
        with pytest.raises(ValueError, match="rejected"):
            parse_response("linear", {}, 200, b'{"errors": [{"message": "bad team"}]}')

    def test_servicenow_incident(self) -> None:
        config = {"instance_url": "https://acme.service-now.com"}

        request = build_request(
            "servicenow",
            config,
            {"username": "u", "password": "p"},
            "exposure.opened",
            {**EXPOSURE, "severity": "critical"},
        )

        assert request.url == "https://acme.service-now.com/api/now/table/incident"
        assert json.loads(request.body)["urgency"] == "1"
        assert parse_response(
            "servicenow", config, 201, b'{"result": {"sys_id": "abc123", "number": "INC0010"}}'
        ) == ("INC0010", "https://acme.service-now.com/nav_to.do?uri=incident.do?sys_id=abc123")

    @pytest.mark.parametrize("status,content", [(401, b"{}"), (201, b"not json"), (201, b"{}")])
    def test_failures_never_echo_credentials(self, status: int, content: bytes) -> None:
        config = {"site_url": "https://acme.atlassian.net", "project_key": "SEC"}
        with pytest.raises(ValueError) as exc:
            parse_response("jira", config, status, content)
        assert "DO-NOT-LEAK" not in str(exc.value)


@pytest.fixture
def jira_site(monkeypatch: pytest.MonkeyPatch):
    import api.webhooks as webhooks_module

    httpd, port, thread, tmp_dir = start_webhook_test_server()
    reset_webhook_test_state(status=201, body=b'{"id": "10001", "key": "SEC-1"}')

    async def loopback(url: str):
        return True, "", "127.0.0.1"

    monkeypatch.setattr(webhooks_module, "validate_webhook_destination", loopback)
    monkeypatch.setattr("api.routers.integrations.validate_webhook_destination", loopback)
    try:
        yield f"https://localhost:{port}"
    finally:
        stop_webhook_test_server(httpd, thread, tmp_dir)


def _client(tmp_path: Path, *, keys: str | None = KEY) -> TestClient:
    return TestClient(
        create_app(
            APISettings(data_dir=tmp_path / "api", secrets_keys=keys, max_concurrent_scans=0)
        )
    )


def _owner(client: TestClient) -> tuple[dict[str, str], str, str]:
    key, account_id = create_verified_account(client)
    org = client.app.state.control_db.default_organization_id_for_account(account_id)
    return {"X-API-Key": key}, account_id, org


def _connect_jira(client: TestClient, headers: dict[str, str], org: str, site: str):  # noqa: ANN202
    return client.post(
        f"/organizations/{org}/integrations",
        headers=headers,
        json={
            "provider": "jira",
            "name": "Security board",
            "config": {"site_url": site, "project_key": "SEC"},
            "credential": JIRA_CREDENTIAL,
            "event_types": ["exposure.opened", "exposure.reopened"],
        },
    )


def _cycle(client: TestClient) -> dict[str, int]:
    import asyncio

    return asyncio.run(run_integration_delivery_cycle(client.app.state.control_db, verify=False))


class TestEndToEnd:
    def test_an_opened_exposure_becomes_one_linked_jira_issue(
        self, tmp_path: Path, jira_site: str
    ) -> None:
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            integration = _connect_jira(client, headers, org, jira_site).json()
            db = client.app.state.control_db
            exposure_id = _seed_exposure(client, account_id, org, run_id="run-1")
            db.enqueue_exposure_lifecycle_events(org, "run-1")

            stats = _cycle(client)
            remediation = client.get(
                f"/organizations/{org}/exposures/{exposure_id}/remediation", headers=headers
            ).json()
            events = client.get(
                f"/organizations/{org}/exposures/{exposure_id}/remediation/events", headers=headers
            ).json()

            request = WebhookTestHandler.requests[0]
            assert stats["delivered"] == 1
            assert request["path"] == "/rest/api/3/issue"
            assert request["body"]["fields"]["project"] == {"key": "SEC"}
            assert remediation["ticket_url"] == f"{jira_site}/browse/SEC-1"
            assert events[0]["actor_account_id"] == f"integration:{integration['integration_id']}"

    def test_the_same_exposure_never_gets_a_second_ticket(
        self, tmp_path: Path, jira_site: str
    ) -> None:
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            _connect_jira(client, headers, org, jira_site)
            db = client.app.state.control_db
            exposure_id = _seed_exposure(client, account_id, org, run_id="run-1")
            db.enqueue_exposure_lifecycle_events(org, "run-1")
            _cycle(client)
            db.enqueue_integration_event(
                account_id=None,
                organization_id=org,
                event_type="exposure.reopened",
                data={"exposure_id": exposure_id, "title": "x", "severity": "high"},
                dedup_key="reopen-1",
            )

            second = _cycle(client)

            assert second["delivered"] == 1
            assert len(WebhookTestHandler.requests) == 1  # no second issue created

    def test_an_existing_ticket_link_is_not_overwritten(
        self, tmp_path: Path, jira_site: str
    ) -> None:
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            _connect_jira(client, headers, org, jira_site)
            db = client.app.state.control_db
            exposure_id = _seed_exposure(client, account_id, org, run_id="run-1")
            client.patch(
                f"/organizations/{org}/exposures/{exposure_id}/remediation",
                headers=headers,
                json={"ticket_url": "https://tracker.acme/SEC-99"},
            )
            db.enqueue_exposure_lifecycle_events(org, "run-1")

            _cycle(client)
            remediation = client.get(
                f"/organizations/{org}/exposures/{exposure_id}/remediation", headers=headers
            ).json()

            assert remediation["ticket_url"] == "https://tracker.acme/SEC-99"

    def test_a_rejecting_api_retries_then_disables_nothing_leaks(
        self, tmp_path: Path, jira_site: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(integration_worker, "MAX_ATTEMPTS", 2)
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            integration = _connect_jira(client, headers, org, jira_site).json()
            db = client.app.state.control_db
            _seed_exposure(client, account_id, org, run_id="run-1")
            db.enqueue_exposure_lifecycle_events(org, "run-1")
            reset_webhook_test_state(status=401, body=b'{"errorMessages": ["unauthorized"]}')

            first = _cycle(client)
            with sqlite3.connect(db.db_path) as conn:
                conn.execute("UPDATE integration_deliveries SET next_attempt_at = '2000-01-01'")
            second = _cycle(client)
            log = client.get(
                f"/organizations/{org}/integrations/" f"{integration['integration_id']}/deliveries",
                headers=headers,
            ).json()
            listed = client.get(f"/organizations/{org}/integrations", headers=headers).json()

            assert (first["retrying"], second["dead"]) == (1, 1)
            assert (log[0]["status"], log[0]["last_error"]) == ("dead", "HTTP 401")
            assert listed[0]["consecutive_failures"] == 1
            assert "DO-NOT-LEAK" not in json.dumps(log) + json.dumps(listed)


class TestApiAndSecrets:
    def test_the_credential_is_sealed_write_only_and_erased_on_removal(
        self, tmp_path: Path, jira_site: str
    ) -> None:
        with _client(tmp_path) as client:
            headers, _, org = _owner(client)
            created = _connect_jira(client, headers, org, jira_site)
            integration_id = created.json()["integration_id"]
            db = client.app.state.control_db
            with sqlite3.connect(db.db_path) as conn:
                stored = conn.execute("SELECT credential FROM ticketing_integrations").fetchone()[0]

            removed = client.delete(
                f"/organizations/{org}/integrations/{integration_id}", headers=headers
            )
            with sqlite3.connect(db.db_path) as conn:
                after = conn.execute(
                    "SELECT credential, status FROM ticketing_integrations"
                ).fetchone()

            assert created.status_code == 201
            assert "DO-NOT-LEAK" not in created.text and "credential" not in created.json()
            assert stored.startswith("enc:v1:") and "DO-NOT-LEAK" not in stored
            assert removed.status_code == 204
            assert after == ("", "disabled")

    def test_no_server_key_means_no_integrations(self, tmp_path: Path, jira_site: str) -> None:
        with _client(tmp_path, keys=None) as client:
            headers, _, org = _owner(client)

            resp = _connect_jira(client, headers, org, jira_site)

            assert resp.status_code == 503
            assert resp.json()["detail"]["error"] == "secrets_key_not_configured"

    def test_invalid_config_and_a_refused_host_are_422(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def refuse(url: str):
            return False, "Destination refused: private address", ""

        monkeypatch.setattr("api.routers.integrations.validate_webhook_destination", refuse)
        with _client(tmp_path) as client:
            headers, _, org = _owner(client)

            bad = client.post(
                f"/organizations/{org}/integrations",
                headers=headers,
                json={
                    "provider": "jira",
                    "name": "x",
                    "config": {"site_url": "https://a.example"},
                    "credential": JIRA_CREDENTIAL,
                },
            )
            private = _connect_jira(client, headers, org, "https://jira.internal.example")

            assert (bad.status_code, private.status_code) == (422, 422)
            assert "private address" in private.text

    def test_roles_and_tenancy(self, tmp_path: Path, jira_site: str) -> None:
        with _client(tmp_path) as client:
            headers, _, org = _owner(client)
            integration_id = _connect_jira(client, headers, org, jira_site).json()["integration_id"]
            viewer_key, viewer_id = create_verified_account(client)
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            viewer = {"X-API-Key": viewer_key}
            foreign, _, _ = _owner(client)
            base = f"/organizations/{org}/integrations"

            assert client.get(base, headers=viewer).status_code == 200
            assert _connect_jira(client, viewer, org, jira_site).status_code == 403
            assert client.delete(f"{base}/{integration_id}", headers=viewer).status_code == 403
            assert [
                client.get(base, headers=foreign).status_code,
                client.get(f"{base}/{integration_id}/deliveries", headers=foreign).status_code,
                client.delete(f"{base}/{integration_id}", headers=foreign).status_code,
                _connect_jira(client, foreign, org, jira_site).status_code,
            ] == [404, 404, 404, 404]


def test_organization_events_reach_only_that_organizations_integrations(tmp_path: Path) -> None:
    db = ControlDB(tmp_path / "c.db", secret_box=SecretBox([KEY]))
    account = db.create_account(email=f"t-{secrets.token_hex(3)}@example.com")
    org = db.default_organization_id_for_account(account)
    other = db.create_account(email=f"u-{secrets.token_hex(3)}@example.com")
    other_org = db.default_organization_id_for_account(other)
    mine = db.create_ticketing_integration(
        organization_id=org,
        actor_account_id=account,
        provider="linear",
        name="L",
        config={"team_id": "t"},
        credential={"api_key": "k"},
        event_types=("exposure.opened",),
    )
    db.create_ticketing_integration(
        organization_id=other_org,
        actor_account_id=other,
        provider="linear",
        name="L2",
        config={"team_id": "t"},
        credential={"api_key": "k"},
        event_types=("exposure.opened",),
    )

    db.enqueue_integration_event(
        account_id=None,
        organization_id=org,
        event_type="exposure.opened",
        data={"exposure_id": "e"},
        dedup_key="x",
    )

    with sqlite3.connect(db.db_path) as conn:
        routed = conn.execute(
            "SELECT webhook_id, destination_type FROM integration_deliveries"
        ).fetchall()
    assert routed == [(mine.integration_id, "ticketing")]


class TestReviewFollowUps:
    def test_a_429_waits_at_least_retry_after(self, tmp_path: Path, jira_site: str) -> None:
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            _connect_jira(client, headers, org, jira_site)
            db = client.app.state.control_db
            _seed_exposure(client, account_id, org, run_id="run-1")
            db.enqueue_exposure_lifecycle_events(org, "run-1")
            reset_webhook_test_state(status=429, body=b"{}")
            WebhookTestHandler.extra_headers = {"Retry-After": "900"}
            try:
                stats = _cycle(client)
            finally:
                WebhookTestHandler.extra_headers = {}

            with sqlite3.connect(db.db_path) as conn:
                row = conn.execute(
                    "SELECT last_error, next_attempt_at FROM integration_deliveries"
                ).fetchone()
            wait = datetime.fromisoformat(row[1]) - datetime.now(timezone.utc)
            assert stats["retrying"] == 1
            assert row[0] == "HTTP 429 (rate limited)"
            assert timedelta(seconds=880) < wait <= timedelta(seconds=900)  # not the 30s step

    def test_a_dead_delivery_log_names_its_destination(
        self,
        tmp_path: Path,
        jira_site: str,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setattr(integration_worker, "MAX_ATTEMPTS", 1)
        with _client(tmp_path) as client:
            headers, account_id, org = _owner(client)
            integration_id = _connect_jira(client, headers, org, jira_site).json()["integration_id"]
            _seed_exposure(client, account_id, org, run_id="run-1")
            client.app.state.control_db.enqueue_exposure_lifecycle_events(org, "run-1")
            reset_webhook_test_state(status=500)

            with caplog.at_level("WARNING", logger="hydra.api.integrations"):
                _cycle(client)

            assert f"to jira integration {integration_id} is dead" in caplog.text
            assert "DO-NOT-LEAK" not in caplog.text

    def test_sealing_touches_only_unsealed_rows(self, tmp_path: Path) -> None:
        box = SecretBox([KEY])
        db = ControlDB(tmp_path / "c.db", secret_box=box)
        account = db.create_account(email="seal-sql@example.com")
        sealed_hook = db.create_webhook(
            account_id=account,
            url="https://a.example/h",
            secret=generate_webhook_secret(),
            event_types=("monitoring.changed",),
        )
        with sqlite3.connect(db.db_path) as conn:
            before = conn.execute("SELECT secret FROM webhooks").fetchone()[0]
            conn.execute(
                "INSERT INTO webhooks (webhook_id, account_id, url, secret, "
                "event_types_json, created_at, updated_at) VALUES "
                "('legacy', ?, 'https://b.example/h', 'plain', '[]', 'x', 'x')",
                (account,),
            )

        assert db.seal_plaintext_secrets() == 1
        with sqlite3.connect(db.db_path) as conn:
            rows = dict(conn.execute("SELECT webhook_id, secret FROM webhooks").fetchall())
        assert rows[sealed_hook.webhook_id] == before  # never re-sealed
        assert box.reveal(rows["legacy"]) == "plain"
