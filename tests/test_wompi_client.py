"""`api/wompi_client.py` — OAuth2 client-credentials token fetch/cache
and webhook signature verification, against a real local HTTP server
standing in for `id.wompi.sv`/`api.wompi.sv` (this project's established
"real server as arbiter" pattern — the same thread-based
`socketserver.TCPServer` `tests/test_httpx_confinement_live.py` already
uses via `tests/_fake_wompi_server.py`), never a mocked `httpx` call.
Real, live calls to the actual `id.wompi.sv`/`api.wompi.sv` (using the
operator's real `WOMPI_CLIENT_ID`/`WOMPI_CLIENT_SECRET`) are exercised
separately, once, as part of this round's own live-demonstration
write-up in docs/PAID_API_DESIGN.md — never inside the automated test
suite.
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")

from _fake_wompi_server import (  # noqa: E402
    FakeWompiHandler,
    reset_fake_wompi_state,
    start_fake_wompi_server,
    stop_fake_wompi_server,
)

from api.wompi_client import (  # noqa: E402
    WompiAuthError,
    WompiClient,
    tier_for_product_name,
    verify_webhook_signature,
)


@pytest.fixture
def wompi_server():
    reset_fake_wompi_state(expires_in=2)  # short, to make cache-expiry tests fast
    httpd, port, thread = start_fake_wompi_server()
    try:
        yield port
    finally:
        stop_fake_wompi_server(httpd, thread)


def _client(port: int) -> WompiClient:
    base = f"http://127.0.0.1:{port}"
    return WompiClient(
        client_id="test-client-id",
        client_secret="test-client-secret",  # noqa: S106 - test fixture, not a real secret
        id_base_url=base,
        api_base_url=base,
    )


class TestOAuthTokenExchange:
    @pytest.mark.asyncio
    async def test_fetches_a_real_token_via_the_documented_form_encoded_request(
        self, wompi_server: int
    ) -> None:
        client = _client(wompi_server)
        token = await client.get_access_token()
        assert token == "fake-access-token"
        assert len(FakeWompiHandler.token_requests) == 1
        sent = FakeWompiHandler.token_requests[0]
        assert sent["grant_type"] == "client_credentials"
        assert sent["audience"] == "wompi_api"
        assert sent["client_id"] == "test-client-id"
        assert sent["client_secret"] == "test-client-secret"

    @pytest.mark.asyncio
    async def test_caches_the_token_never_refetching_before_expiry(self, wompi_server: int) -> None:
        FakeWompiHandler.expires_in = 3600  # long-lived, cache should hold
        client = _client(wompi_server)
        await client.get_access_token()
        await client.get_access_token()
        await client.get_access_token()
        assert len(FakeWompiHandler.token_requests) == 1

    @pytest.mark.asyncio
    async def test_refetches_once_the_cached_token_is_near_expiry(self, wompi_server: int) -> None:
        import asyncio

        FakeWompiHandler.expires_in = 1  # shorter than the 60s refresh skew
        client = _client(wompi_server)
        await client.get_access_token()
        await asyncio.sleep(0.05)
        await client.get_access_token()
        # expires_in (1s) is already inside the 60s refresh-skew window at
        # the very next call — a real Wompi token this short-lived would
        # never be usable otherwise; this confirms the skew logic, not a
        # timing race.
        assert len(FakeWompiHandler.token_requests) == 2

    @pytest.mark.asyncio
    async def test_raises_a_clear_error_when_credentials_are_not_configured(self) -> None:
        client = WompiClient(client_id=None, client_secret=None)
        with pytest.raises(WompiAuthError):
            await client.get_access_token()


class TestTransactionLookup:
    @pytest.mark.asyncio
    async def test_confirms_an_approved_transaction(self, wompi_server: int) -> None:
        client = _client(wompi_server)
        result = await client.get_transaction("txn-1")
        assert result["esAprobada"] is True

    @pytest.mark.asyncio
    async def test_reports_a_non_approved_transaction_honestly(self, wompi_server: int) -> None:
        FakeWompiHandler.transaction_response = {"esAprobada": False}
        client = _client(wompi_server)
        result = await client.get_transaction("txn-2")
        assert result["esAprobada"] is False


class TestWebhookSignatureVerification:
    def test_a_correctly_computed_hmac_verifies(self) -> None:
        import hashlib
        import hmac

        body = b'{"IdTransaccion": "1"}'
        secret = "shh"  # noqa: S105 - test fixture, not a real secret
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(body, signature, secret) is True

    def test_a_wrong_signature_is_rejected(self) -> None:
        body = b'{"IdTransaccion": "1"}'
        assert verify_webhook_signature(body, "0" * 64, "shh") is False

    def test_a_missing_signature_is_rejected(self) -> None:
        assert verify_webhook_signature(b"{}", None, "shh") is False

    def test_a_body_modified_after_signing_fails_verification(self) -> None:
        import hashlib
        import hmac

        secret = "shh"  # noqa: S105 - test fixture, not a real secret
        original_body = b'{"IdTransaccion": "1", "Monto": 10.0}'
        signature = hmac.new(secret.encode(), original_body, hashlib.sha256).hexdigest()
        tampered_body = b'{"IdTransaccion": "1", "Monto": 999999.0}'
        assert verify_webhook_signature(tampered_body, signature, secret) is False


class TestTierForProductName:
    def test_recognizes_each_configured_product_name(self) -> None:
        assert tier_for_product_name("Hydra Medium") == "medium"
        assert tier_for_product_name("Hydra Pro") == "pro"
        assert tier_for_product_name("Hydra Ultra") == "ultra"

    def test_case_insensitive(self) -> None:
        assert tier_for_product_name("hydra pro") == "pro"

    def test_unknown_product_name_returns_none(self) -> None:
        assert tier_for_product_name("Something Else") is None

    def test_none_returns_none(self) -> None:
        assert tier_for_product_name(None) is None
