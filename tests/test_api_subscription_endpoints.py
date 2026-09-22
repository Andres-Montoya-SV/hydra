"""Full HTTP end-to-end tests for Round 3 (docs/PAID_API_DESIGN.md Part
B/D) through the real FastAPI app (`TestClient`): tier gating on
`assess-reportability`/`suggest-hypotheses`, the Wompi webhook (real
HMAC signature verification, real local server standing in for
`api.wompi.sv`'s transaction double-check), scan-quota enforcement, and
tier-change consequences. Task 5's six required test scenarios are all
covered here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")

from _dns_test_server import start_dns_test_server, stop_dns_test_server  # noqa: E402
from _fake_wompi_server import (  # noqa: E402
    reset_fake_wompi_state,
    start_fake_wompi_server,
    stop_fake_wompi_server,
)
from _verified_account import create_verified_account  # noqa: E402
from _verified_domain import seed_verified_domain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.domain_verification import dns_record_name, dns_record_value  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402

WEBHOOK_SECRET = "test-wompi-api-secret"  # noqa: S105 - test fixture, not a real secret
DOMAIN = "subscription-test.example"


@pytest.fixture
def wompi_backed_client(tmp_path: Path):
    """A real TestClient with a real local server standing in for
    `id.wompi.sv`/`api.wompi.sv` (thread-based `socketserver`, immune to
    the TestClient/asyncio event-loop-starvation bug documented in
    tests/_dns_test_server.py — this server was never asyncio-based in
    the first place) and all three tier payment links configured."""
    reset_fake_wompi_state()
    httpd, port, thread = start_fake_wompi_server()
    base_url = f"http://127.0.0.1:{port}"
    settings = APISettings(
        data_dir=tmp_path / "api_data",
        wompi_client_id="test-client-id",
        wompi_client_secret=WEBHOOK_SECRET,
        dev_wompi_id_base_url=base_url,
        dev_wompi_api_base_url=base_url,
        wompi_link_url_medium="https://pay.example/medium",
        wompi_link_url_pro="https://pay.example/pro",
        wompi_link_url_ultra="https://pay.example/ultra",
        admin_token="admin-secret",  # noqa: S106 - test fixture, not a real secret
    )
    try:
        with TestClient(create_app(settings)) as client:
            yield client
    finally:
        stop_fake_wompi_server(httpd, thread)


def _create_account(client: TestClient) -> tuple[str, str]:
    return create_verified_account(client)


def _sign(body: bytes) -> str:
    return hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _webhook_payload(
    *, transaction_id: str, email: str, product_name: str, result: str = "ExitosaAprobada"
) -> bytes:
    return json.dumps(
        {
            "IdCuenta": "acc-1",
            "IdTransaccion": transaction_id,
            "Monto": 99.0,
            "ResultadoTransaccion": result,
            "EnlacePago": {"Id": 66, "NombreProducto": product_name},
            "cliente": {"Nombre": "Test User", "Email": email},
        }
    ).encode("utf-8")


class TestFreeTierRouteGatingReturnsNotFound:
    """Task 5, test 1: the route must not merely error for Free — it
    must be indistinguishable from a route that was never registered."""

    def test_reportability_estimate_is_404_for_a_free_account(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, _ = _create_account(wompi_backed_client)
        resp = wompi_backed_client.post(
            "/scans/does-not-exist/reportability-estimate",
            json={"program_rules_text": "anything"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 404

    def test_hypotheses_estimate_is_404_for_a_free_account(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, _ = _create_account(wompi_backed_client)
        resp = wompi_backed_client.post(
            "/scans/does-not-exist/hypotheses-estimate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 404

    def test_hypotheses_estimate_is_also_404_for_medium(
        self, wompi_backed_client: TestClient
    ) -> None:
        """Medium has reportability but NOT hypotheses (the task's own
        table) — same 404, not merely a 403, for the same reason."""
        api_key, account_id = _create_account(wompi_backed_client)
        control_db = wompi_backed_client.app.state.control_db
        control_db.set_tier(account_id, "medium")
        resp = wompi_backed_client.post(
            "/scans/does-not-exist/hypotheses-estimate",
            json={},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 404

    def test_a_real_scan_id_owned_by_the_account_is_still_404_on_free(
        self, wompi_backed_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even a scan_id that genuinely exists and belongs to this
        account must not change the outcome — the gate runs before scan
        resolution, exactly like a truly nonexistent route would."""
        api_key, account_id = _create_account(wompi_backed_client)
        control_db = wompi_backed_client.app.state.control_db
        seed_verified_domain(wompi_backed_client, account_id, DOMAIN)
        control_db.create_scan(
            scan_id="real-scan-1", account_id=account_id, domain=DOMAIN, db_path="/tmp/x"
        )
        resp = wompi_backed_client.post(
            "/scans/real-scan-1/reportability-estimate",
            json={"program_rules_text": "anything"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 404


class TestWompiWebhook:
    def test_valid_signature_activates_the_correct_tier(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, account_id = _create_account(wompi_backed_client)
        register = wompi_backed_client.post(
            "/account/subscription",
            json={"tier": "pro", "billing_email": "buyer@example.com"},
            headers={"X-API-Key": api_key},
        )
        assert register.status_code == 200
        assert register.json()["payment_url"] == "https://pay.example/pro"

        body = _webhook_payload(
            transaction_id="txn-100", email="buyer@example.com", product_name="Hydra Pro"
        )
        resp = wompi_backed_client.post(
            "/webhooks/wompi", content=body, headers={"wompi_hash": _sign(body)}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "activated"

        sub = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub["tier"] == "pro"
        assert sub["status"] == "active"

    def test_invalid_signature_is_rejected_and_never_activates(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, _ = _create_account(wompi_backed_client)
        wompi_backed_client.post(
            "/account/subscription",
            json={"tier": "pro", "billing_email": "buyer2@example.com"},
            headers={"X-API-Key": api_key},
        )
        body = _webhook_payload(
            transaction_id="txn-101", email="buyer2@example.com", product_name="Hydra Pro"
        )
        resp = wompi_backed_client.post(
            "/webhooks/wompi", content=body, headers={"wompi_hash": "0" * 64}
        )
        assert resp.status_code == 401

        sub = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub["tier"] == "free"

    def test_missing_signature_header_is_rejected(self, wompi_backed_client: TestClient) -> None:
        body = _webhook_payload(
            transaction_id="txn-102", email="nobody@example.com", product_name="Hydra Pro"
        )
        resp = wompi_backed_client.post("/webhooks/wompi", content=body)
        assert resp.status_code == 401

    def test_a_replayed_webhook_is_idempotent_not_double_processed(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, _ = _create_account(wompi_backed_client)
        wompi_backed_client.post(
            "/account/subscription",
            json={"tier": "medium", "billing_email": "replay@example.com"},
            headers={"X-API-Key": api_key},
        )
        body = _webhook_payload(
            transaction_id="txn-103", email="replay@example.com", product_name="Hydra Medium"
        )
        first = wompi_backed_client.post(
            "/webhooks/wompi", content=body, headers={"wompi_hash": _sign(body)}
        )
        second = wompi_backed_client.post(
            "/webhooks/wompi", content=body, headers={"wompi_hash": _sign(body)}
        )
        assert first.json()["status"] == "activated"
        assert second.json()["status"] == "already_processed"

    def test_unknown_reference_goes_to_manual_reconciliation_never_guessed(
        self, wompi_backed_client: TestClient
    ) -> None:
        """Task 5, test 5: a webhook with a real, valid signature but an
        email that matches no pending enrollment must never be discarded
        and never auto-assigned — it lands in the manual queue."""
        api_key, account_id = _create_account(wompi_backed_client)
        body = _webhook_payload(
            transaction_id="txn-104",
            email="nobody-registered-this-email@example.com",
            product_name="Hydra Ultra",
        )
        resp = wompi_backed_client.post(
            "/webhooks/wompi", content=body, headers={"wompi_hash": _sign(body)}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "unmatched_pending_manual_reconciliation"

        # Still free — nothing was guessed.
        sub = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub["tier"] == "free"

        unmatched = wompi_backed_client.get(
            "/admin/wompi/unmatched", headers={"X-Admin-Token": "admin-secret"}
        ).json()
        assert len(unmatched) == 1
        assert unmatched[0]["transaction_id"] == "txn-104"

        reconcile = wompi_backed_client.post(
            "/admin/wompi/reconcile",
            json={
                "unmatched_id": unmatched[0]["unmatched_id"],
                "account_id": account_id,
                "tier": "ultra",
            },
            headers={"X-Admin-Token": "admin-secret"},
        )
        assert reconcile.status_code == 200
        sub_after = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub_after["tier"] == "ultra"

    def test_admin_endpoints_require_the_admin_token(self, wompi_backed_client: TestClient) -> None:
        resp = wompi_backed_client.get("/admin/wompi/unmatched")
        assert resp.status_code == 401
        resp2 = wompi_backed_client.get(
            "/admin/wompi/unmatched", headers={"X-Admin-Token": "wrong"}
        )
        assert resp2.status_code == 401

    def test_a_transaction_check_failure_prevents_activation(
        self, wompi_backed_client: TestClient
    ) -> None:
        """Part D.2's belt-and-suspenders: even a validly-signed webhook
        must not be trusted alone if the independent TransaccionCompra
        lookup does not confirm approval."""
        from _fake_wompi_server import FakeWompiHandler

        api_key, _ = _create_account(wompi_backed_client)
        wompi_backed_client.post(
            "/account/subscription",
            json={"tier": "pro", "billing_email": "doublecheck@example.com"},
            headers={"X-API-Key": api_key},
        )
        FakeWompiHandler.transaction_response = {"esAprobada": False}
        body = _webhook_payload(
            transaction_id="txn-105", email="doublecheck@example.com", product_name="Hydra Pro"
        )
        resp = wompi_backed_client.post(
            "/webhooks/wompi", content=body, headers={"wompi_hash": _sign(body)}
        )
        assert resp.status_code == 400
        sub = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub["tier"] == "free"

    def test_payment_failure_webhook_starts_grace_period_for_an_active_subscriber(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, _ = _create_account(wompi_backed_client)
        wompi_backed_client.post(
            "/account/subscription",
            json={"tier": "medium", "billing_email": "gracecase@example.com"},
            headers={"X-API-Key": api_key},
        )
        activate_body = _webhook_payload(
            transaction_id="txn-106", email="gracecase@example.com", product_name="Hydra Medium"
        )
        wompi_backed_client.post(
            "/webhooks/wompi", content=activate_body, headers={"wompi_hash": _sign(activate_body)}
        )

        failure_body = _webhook_payload(
            transaction_id="txn-107",
            email="gracecase@example.com",
            product_name="Hydra Medium",
            result="Rechazada",
        )
        resp = wompi_backed_client.post(
            "/webhooks/wompi", content=failure_body, headers={"wompi_hash": _sign(failure_body)}
        )
        assert resp.json()["status"] == "grace_period_started"

        sub = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub["status"] == "past_due"
        assert sub["grace_period_started_at"] is not None

        # Still medium, and scans still work during grace (Part D.3).
        assert sub["tier"] == "medium"


class TestScanQuota:
    def test_quota_reached_gives_a_clear_upgrade_message(
        self, wompi_backed_client: TestClient
    ) -> None:
        """Task 5, test 3."""
        api_key, account_id = _create_account(wompi_backed_client)
        seed_verified_domain(wompi_backed_client, account_id, DOMAIN)

        first = wompi_backed_client.post(
            "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
        )
        assert first.status_code == 202  # free tier's 1/month

        second = wompi_backed_client.post(
            "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
        )
        assert second.status_code == 403
        detail = second.json()["detail"].lower()
        assert "quota" in detail
        assert "medium" in detail  # names the tier that would resolve it

    def test_a_suspended_account_gets_402_not_403(self, wompi_backed_client: TestClient) -> None:
        api_key, account_id = _create_account(wompi_backed_client)
        control_db = wompi_backed_client.app.state.control_db
        control_db.set_subscription_status(account_id, "suspended")
        resp = wompi_backed_client.post(
            "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 402

    def test_past_due_grace_period_still_allows_scanning(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, account_id = _create_account(wompi_backed_client)
        control_db = wompi_backed_client.app.state.control_db
        control_db.set_subscription_status(
            account_id, "past_due", grace_period_started_at="2026-01-01T00:00:00+00:00"
        )
        seed_verified_domain(wompi_backed_client, account_id, DOMAIN)
        resp = wompi_backed_client.post(
            "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 202


class TestTierChangeConsequences:
    def test_upgrade_via_free_downgrade_endpoint_applies_immediately(
        self, wompi_backed_client: TestClient
    ) -> None:
        """Task 5, test 6 (the free/no-payment half — the paid half is
        exercised by the webhook-activation test above, since a real
        upgrade only ever completes via a confirmed webhook)."""
        api_key, account_id = _create_account(wompi_backed_client)
        control_db = wompi_backed_client.app.state.control_db
        control_db.set_tier(account_id, "pro")

        resp = wompi_backed_client.post(
            "/account/subscription", json={"tier": "free"}, headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["tier"] == "free"
        assert body["previous_tier"] == "pro"

        sub = wompi_backed_client.get(
            "/account/subscription", headers={"X-API-Key": api_key}
        ).json()
        assert sub["tier"] == "free"
        assert sub["scans_limit"] == 1

    def test_downgrade_with_excess_verified_domains_is_reported_not_silent(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, account_id = _create_account(wompi_backed_client)
        control_db = wompi_backed_client.app.state.control_db
        control_db.set_tier(account_id, "pro")
        for i in range(3):
            seed_verified_domain(wompi_backed_client, account_id, f"excess{i}.example")

        resp = wompi_backed_client.post(
            "/account/subscription", json={"tier": "free"}, headers={"X-API-Key": api_key}
        )
        body = resp.json()
        assert body["exceeds_domain_limit"] is True

        # Nothing was silently revoked — all 3 domains are still active.
        assert len(control_db.get_verified_domains_for_account(account_id)) == 3

    def test_paid_tier_without_billing_email_is_rejected(
        self, wompi_backed_client: TestClient
    ) -> None:
        api_key, _ = _create_account(wompi_backed_client)
        resp = wompi_backed_client.post(
            "/account/subscription", json={"tier": "pro"}, headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 422


class TestVerifiedDomainLimitWiredIntoTheRealVerifyEndpoint:
    """Confirms `api/routers/domains.py`'s actual call to
    `check_verified_domain_limit` — not just the pure-logic unit test in
    tests/test_api_tiers_and_subscriptions_logic.py — by driving a real
    DNS TXT verification (Round 2's local DNS test server) against an
    account already at its tier's limit."""

    def test_free_account_at_its_one_domain_limit_cannot_verify_a_second(
        self, tmp_path: Path
    ) -> None:
        dns_server, dns_thread = start_dns_test_server()
        try:
            settings = APISettings(
                data_dir=tmp_path / "api_data",
                dev_dns_nameserver="127.0.0.1",
                dev_dns_port=dns_server.port,
            )
            with TestClient(create_app(settings)) as client:
                api_key, account_id = _create_account(client)
                seed_verified_domain(client, account_id, "already-verified.example")

                second_domain = "second-domain.example"
                register = client.post(
                    "/domains", json={"domain": second_domain}, headers={"X-API-Key": api_key}
                )
                token = register.json()["token"]
                dns_server.txt_records[dns_record_name(second_domain)] = dns_record_value(token)

                verify = client.post(
                    f"/domains/{second_domain}/verify",
                    json={"method": "dns_txt"},
                    headers={"X-API-Key": api_key},
                )
                # The real DNS check succeeded (the record was correct) —
                # the tier's domain-count limit is what blocks this, a
                # 403, not the 422 a failed DNS check would produce.
                assert verify.status_code == 403
                assert "verified domain" in verify.json()["detail"].lower()
        finally:
            stop_dns_test_server(dns_server, dns_thread)
