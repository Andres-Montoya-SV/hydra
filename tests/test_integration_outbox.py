"""Productization Phase 08: the canonical integration outbox and its durable
delivery worker. Real deliveries go to a real local HTTPS server (the same
one tests/test_webhook_delivery.py uses); only the SSRF gate's resolved IP
is pointed at loopback, as there."""

from __future__ import annotations

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
from fastapi.testclient import TestClient
from test_api_exposure_operations import _account, _client, _seed_exposure

from api import integration_worker
from api.control_db import ControlDB, IntegrationEventRecord
from api.integration_worker import (
    MAX_ATTEMPTS,
    RETRY_SCHEDULE_SECONDS,
    render_body,
    run_integration_delivery_cycle,
)
from api.main import create_app
from api.settings import APISettings
from api.webhooks import (
    DELIVERY_ID_HEADER,
    DISABLE_AFTER_CONSECUTIVE_FAILURES,
    EVENT_ID_HEADER,
    generate_webhook_secret,
    verify_signature,
)


@pytest.fixture
def control_db(tmp_path: Path) -> ControlDB:
    return ControlDB(APISettings(data_dir=tmp_path / "api_data").control_db_path)


@pytest.fixture
def account_id(control_db: ControlDB) -> str:
    account_id = control_db.create_account(email=f"ob-{secrets.token_hex(6)}@example.com")
    control_db.create_default_subscription(account_id, tier="pro")
    return account_id


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch):
    import api.webhooks as webhooks_module

    httpd, port, thread, tmp_dir = start_webhook_test_server()
    reset_webhook_test_state()

    async def loopback(url: str):
        return True, "", "127.0.0.1"

    monkeypatch.setattr(webhooks_module, "validate_webhook_destination", loopback)
    # The registration endpoint imports it by name; point that at loopback too.
    monkeypatch.setattr("api.routers.webhooks.validate_webhook_destination", loopback)
    try:
        yield port
    finally:
        stop_webhook_test_server(httpd, thread, tmp_dir)


def _webhook(
    control_db: ControlDB,
    account_id: str,
    port: int = 1,
    *,
    kind: str = "generic",
    events: tuple[str, ...] = ("monitoring.changed",),
):  # noqa: ANN202
    return control_db.create_webhook(
        account_id=account_id,
        url=f"https://localhost:{port}/hook",
        secret=generate_webhook_secret(),
        event_types=events,
        kind=kind,
    )


def _enqueue(
    control_db: ControlDB,
    account_id: str,
    key: str = "k1",
    event_type: str = "monitoring.changed",
    organization_id: str | None = None,
):  # noqa: ANN202
    return control_db.enqueue_integration_event(
        account_id=account_id,
        organization_id=organization_id,
        event_type=event_type,
        data={"domain": "example.com", "hosts_added": ["b.example.com"]},
        dedup_key=key,
    )


def _deliveries(control_db: ControlDB) -> list[sqlite3.Row]:
    with sqlite3.connect(control_db.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM integration_deliveries ORDER BY created_at").fetchall()


def _make_due(control_db: ControlDB) -> None:
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with sqlite3.connect(control_db.db_path) as conn:
        conn.execute(
            "UPDATE integration_deliveries SET next_attempt_at = ? " "WHERE status = 'pending'",
            (past,),
        )


def _cycle(control_db: ControlDB) -> dict[str, int]:
    import asyncio

    return asyncio.run(run_integration_delivery_cycle(control_db, verify=False))


class TestEnqueue:
    def test_the_same_dedup_key_is_enqueued_once(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        _webhook(control_db, account_id)

        first, second = _enqueue(control_db, account_id), _enqueue(control_db, account_id)

        assert first is not None and second is None
        assert len(_deliveries(control_db)) == 1

    def test_fan_out_only_to_active_subscribed_destinations(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        subscribed = _webhook(control_db, account_id)
        _webhook(control_db, account_id, events=("finding.high_severity",))
        disabled = _webhook(control_db, account_id)
        control_db.record_webhook_delivery_failure(disabled.webhook_id, error="x", disable_after=1)
        stranger = control_db.create_account(email="stranger@example.com")
        _webhook(control_db, stranger)

        _enqueue(control_db, account_id)

        assert [d["webhook_id"] for d in _deliveries(control_db)] == [subscribed.webhook_id]

    def test_organization_events_go_to_that_organizations_webhooks_only(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        own = _webhook(control_db, account_id, events=("exposure.resolved",))
        other_account = control_db.create_account(email="other-org@example.com")
        _webhook(control_db, other_account, events=("exposure.resolved",))
        org = control_db.default_organization_id_for_account(account_id)

        _enqueue(
            control_db,
            account_id=None,
            event_type="exposure.resolved",
            organization_id=org,
        )

        assert [d["webhook_id"] for d in _deliveries(control_db)] == [own.webhook_id]


class TestDelivery:
    def test_a_generic_delivery_is_signed_enveloped_and_identified(
        self, control_db: ControlDB, account_id: str, server: int
    ) -> None:
        hook = _webhook(control_db, account_id, server)
        event_id = _enqueue(control_db, account_id)

        stats = _cycle(control_db)

        request = WebhookTestHandler.requests[0]
        assert stats["delivered"] == 1
        assert verify_signature(
            hook.secret, request["raw_body"], request["headers"]["X-Hydra-Signature"]
        )
        assert request["headers"][EVENT_ID_HEADER] == event_id
        assert request["headers"][DELIVERY_ID_HEADER] == _deliveries(control_db)[0]["delivery_id"]
        assert request["body"]["event_id"] == event_id
        assert request["body"]["data"]["domain"] == "example.com"
        assert _deliveries(control_db)[0]["status"] == "delivered"

    @pytest.mark.parametrize("kind", ["slack", "teams"])
    def test_chat_destinations_get_a_summary_not_the_data(
        self, control_db: ControlDB, account_id: str, server: int, kind: str
    ) -> None:
        _webhook(control_db, account_id, server, kind=kind)
        _enqueue(control_db, account_id)

        _cycle(control_db)

        body = WebhookTestHandler.requests[0]["body"]
        text = (
            body["text"]
            if kind == "slack"
            else body["attachments"][0]["content"]["body"][0]["text"]
        )
        assert text.startswith("[Hydra] monitoring.changed: example.com")
        assert "hosts_added" not in str(body) and "b.example.com" not in str(body)

    def test_a_failing_receiver_is_retried_on_schedule_then_dead(
        self, control_db: ControlDB, account_id: str, server: int
    ) -> None:
        hook = _webhook(control_db, account_id, server)
        _enqueue(control_db, account_id)
        reset_webhook_test_state(status=500)

        first = _cycle(control_db)
        after_first = _deliveries(control_db)[0]
        not_due_yet = _cycle(control_db)
        for _ in range(MAX_ATTEMPTS - 1):
            _make_due(control_db)
            _cycle(control_db)

        final = _deliveries(control_db)[0]
        assert first == {"delivered": 0, "retrying": 1, "dead": 0, "errors": 0}
        assert (after_first["status"], after_first["attempts"], after_first["last_error"]) == (
            "pending",
            1,
            "HTTP 500",
        )
        due = datetime.fromisoformat(after_first["next_attempt_at"])
        assert (
            timedelta(seconds=RETRY_SCHEDULE_SECONDS[0] - 5)
            < due - datetime.now(timezone.utc)
            <= timedelta(seconds=RETRY_SCHEDULE_SECONDS[0])
        )
        assert sum(not_due_yet.values()) == 0
        assert (final["status"], final["attempts"]) == ("dead", MAX_ATTEMPTS)
        assert len(WebhookTestHandler.requests) == MAX_ATTEMPTS
        assert control_db.get_webhook(hook.webhook_id, account_id).consecutive_failures == 1

    def test_dead_deliveries_disable_the_destination(
        self, control_db: ControlDB, account_id: str, server: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(integration_worker, "MAX_ATTEMPTS", 1)
        hook = _webhook(control_db, account_id, server)
        reset_webhook_test_state(status=500)
        for i in range(DISABLE_AFTER_CONSECUTIVE_FAILURES):
            _enqueue(control_db, account_id, key=f"k{i}")
            _cycle(control_db)

        assert control_db.get_webhook(hook.webhook_id, account_id).status == "disabled"
        _enqueue(control_db, account_id, key="after-disable")
        assert len(_deliveries(control_db)) == DISABLE_AFTER_CONSECUTIVE_FAILURES

    def test_a_worker_that_dies_mid_send_loses_nothing(
        self, control_db: ControlDB, account_id: str, server: int
    ) -> None:
        _webhook(control_db, account_id, server)
        event_id = _enqueue(control_db, account_id)
        claimed = control_db.claim_due_deliveries(
            now=datetime.now(timezone.utc), limit=10, lease_seconds=60
        )  # ...and then it crashed

        while_leased = _cycle(control_db)
        with sqlite3.connect(control_db.db_path) as conn:  # the lease runs out
            conn.execute(
                "UPDATE integration_deliveries SET lease_until = ?",
                ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
            )
        after_lease = _cycle(control_db)

        assert len(claimed) == 1 and sum(while_leased.values()) == 0
        assert after_lease["delivered"] == 1
        assert WebhookTestHandler.requests[0]["headers"][EVENT_ID_HEADER] == event_id

    def test_a_delivery_is_claimed_by_one_worker_only(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        _webhook(control_db, account_id)
        _enqueue(control_db, account_id)
        now = datetime.now(timezone.utc)

        first = control_db.claim_due_deliveries(now=now, limit=10, lease_seconds=60)
        second = control_db.claim_due_deliveries(now=now, limit=10, lease_seconds=60)

        assert len(first) == 1 and second == []

    def test_a_removed_destination_makes_its_queued_deliveries_dead(
        self, control_db: ControlDB, account_id: str
    ) -> None:
        hook = _webhook(control_db, account_id)
        _enqueue(control_db, account_id)
        control_db.delete_webhook(hook.webhook_id, account_id)

        claimed = control_db.claim_due_deliveries(
            now=datetime.now(timezone.utc), limit=10, lease_seconds=60
        )

        assert claimed == []
        assert _deliveries(control_db)[0]["status"] == "dead"


class TestApi:
    def test_kind_delivery_log_and_redeliver(
        self, tmp_path: Path, server: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(integration_worker, "MAX_ATTEMPTS", 1)
        with TestClient(_app(tmp_path)) as client:
            key, account_id = _key_and_account(client)
            headers = {"X-API-Key": key}
            db = client.app.state.control_db
            hook = client.post(
                "/webhooks",
                headers=headers,
                json={
                    "url": f"https://localhost:{server}/hook",
                    "kind": "slack",
                    "event_types": ["monitoring.changed"],
                },
            ).json()
            _enqueue(db, account_id)
            reset_webhook_test_state(status=503)
            _cycle(db)

            log = client.get(f"/webhooks/{hook['webhook_id']}/deliveries", headers=headers).json()
            reset_webhook_test_state(status=200)
            redeliver = client.post(
                f"/webhooks/{hook['webhook_id']}/deliveries/" f"{log[0]['delivery_id']}/redeliver",
                headers=headers,
            )
            _cycle(db)
            after = client.get(f"/webhooks/{hook['webhook_id']}/deliveries", headers=headers)

            assert hook["kind"] == "slack"
            assert (log[0]["status"], log[0]["last_error"]) == ("dead", "HTTP 503")
            assert redeliver.status_code == 202
            assert after.json()[0]["status"] == "delivered"

    def test_invalid_kind_and_foreign_access(self, tmp_path: Path) -> None:
        with TestClient(_app(tmp_path)) as client:
            key, account_id = _key_and_account(client)
            foreign_key, _ = _key_and_account(client)
            db = client.app.state.control_db
            hook = _webhook(db, account_id)
            _enqueue(db, account_id)
            delivery_id = _deliveries(db)[0]["delivery_id"]
            foreign = {"X-API-Key": foreign_key}

            bad_kind = client.post(
                "/webhooks",
                headers={"X-API-Key": key},
                json={
                    "url": "https://example.com/h",
                    "kind": "discord",
                    "event_types": ["monitoring.changed"],
                },
            )
            log = client.get(f"/webhooks/{hook.webhook_id}/deliveries", headers=foreign)
            redo = client.post(
                f"/webhooks/{hook.webhook_id}/deliveries/{delivery_id}/redeliver", headers=foreign
            )

            assert (bad_kind.status_code, log.status_code, redo.status_code) == (422, 404, 404)


def _app(tmp_path: Path):  # noqa: ANN202
    return create_app(APISettings(data_dir=tmp_path / "api", max_concurrent_scans=0))


def _key_and_account(client: TestClient) -> tuple[str, str]:
    return create_verified_account(client)


class TestProducers:
    def _org_webhook(self, client: TestClient, account_id: str) -> None:
        _webhook(
            client.app.state.control_db,
            account_id,
            events=(
                "exposure.opened",
                "exposure.resolved",
                "remediation.state_changed",
                "remediation.assigned",
            ),
        )

    @staticmethod
    def _events(client: TestClient) -> list[tuple[str, str]]:
        with sqlite3.connect(client.app.state.control_db.db_path) as conn:
            return conn.execute(
                "SELECT e.event_type, json_extract(e.payload_json, '$.exposure_id') "
                "FROM integration_events e JOIN integration_deliveries d "
                "ON d.event_id = e.event_id ORDER BY e.created_at, e.event_type"
            ).fetchall()

    def test_exposure_lifecycle_events_are_enqueued_once(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "prod-open@example.com")
            self._org_webhook(client, account_id)
            exposure_id = _seed_exposure(client, account_id, org, run_id="run-1")
            db = client.app.state.control_db

            first = db.enqueue_exposure_lifecycle_events(org, "run-1")
            again = db.enqueue_exposure_lifecycle_events(org, "run-1")

            assert (first, again) == (1, 0)
            assert self._events(client) == [("exposure.opened", exposure_id)]

    def test_resolve_and_remediation_changes_emit_events(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "prod-rem@example.com")
            self._org_webhook(client, account_id)
            exposure_id = _seed_exposure(client, account_id, org)
            headers = {"X-API-Key": key}
            base = f"/organizations/{org}/exposures/{exposure_id}"

            client.post(
                f"{base}/remediation/transition", headers=headers, json={"to_state": "in_progress"}
            )
            client.patch(
                f"{base}/remediation", headers=headers, json={"assignee_account_id": account_id}
            )
            client.post(f"{base}/resolve", headers=headers, json={"reason": "patched"})

            assert self._events(client) == [
                ("remediation.state_changed", exposure_id),
                ("remediation.assigned", exposure_id),
                ("exposure.resolved", exposure_id),
            ]

    def test_a_rejected_change_enqueues_nothing(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "prod-rollback@example.com")
            self._org_webhook(client, account_id)
            exposure_id = _seed_exposure(client, account_id, org)

            conflict = client.post(
                f"/organizations/{org}/exposures/{exposure_id}/remediation/transition",
                headers={"X-API-Key": key},
                json={"to_state": "fixed_pending_verification"},
            )

            assert conflict.status_code == 409
            assert self._events(client) == []


def test_chat_summary_shapes_are_stable() -> None:
    event = IntegrationEventRecord(
        event_id="e1",
        organization_id="o1",
        account_id=None,
        event_type="remediation.state_changed",
        created_at="2026-09-30T00:00:00+00:00",
        payload={"title": "Admin exposed", "from_state": "triage", "to_state": "in_progress"},
    )

    assert b"Admin exposed" in render_body("slack", event)
    assert b"triage -> in_progress" in render_body("teams", event)
    assert b'"event_id": "e1"' in render_body("generic", event)
