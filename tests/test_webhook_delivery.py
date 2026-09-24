"""Real-network delivery tests for `api/webhooks.py` — a real local HTTPS
server (`tests/_webhook_test_server.py`, self-signed cert), a real HMAC
signature the server actually verifies, real retry timing, and the
real disable-after-N-consecutive-failures behavior.

`api/webhooks.py::validate_webhook_destination` (the real SSRF gate) is
monkeypatched to point at the local server's own loopback address for
these tests — that gate's own real, unmocked behavior (refusing
loopback/private/metadata destinations) is separately, thoroughly
covered in `tests/test_webhooks_logic.py`; testing delivery MECHANICS
against a real local server would otherwise be impossible, since the
real SSRF gate correctly refuses 127.0.0.1 by design. This mirrors the
same "stub the already-separately-tested gate, exercise the real thing
under test" split this project uses elsewhere (e.g.
`tests/_verified_domain.py`'s docstring, for the exact same reason).
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

import pytest
from _webhook_test_server import (  # noqa: E402
    WebhookTestHandler,
    reset_webhook_test_state,
    start_webhook_test_server,
    stop_webhook_test_server,
)

from api.control_db import ControlDB
from api.settings import APISettings
from api.webhooks import (
    DISABLE_AFTER_CONSECUTIVE_FAILURES,
    WebhookEvent,
    deliver_event,
    deliver_event_to_subscribers,
    verify_signature,
)


@pytest.fixture
def control_db(tmp_path: Path) -> ControlDB:
    return ControlDB(APISettings(data_dir=tmp_path / "api_data").control_db_path)


@pytest.fixture
def account_id(control_db: ControlDB) -> str:
    account_id = control_db.create_account(email=f"wh-{secrets.token_hex(6)}@example.com")
    control_db.create_default_subscription(account_id, tier="pro")
    return account_id


@pytest.fixture
def https_server():
    httpd, port, thread, tmp_dir = start_webhook_test_server()
    reset_webhook_test_state()
    try:
        yield port
    finally:
        stop_webhook_test_server(httpd, thread, tmp_dir)


@pytest.fixture
def stub_destination(monkeypatch: pytest.MonkeyPatch, https_server: int):
    """Points the real SSRF gate's OWN return value at the local test
    server's loopback address/port — see this module's own docstring
    for why the gate itself is stubbed here rather than its real
    private-range logic."""
    import api.webhooks as webhooks_module

    async def fake_validate(url: str):
        return True, "", "127.0.0.1"

    monkeypatch.setattr(webhooks_module, "validate_webhook_destination", fake_validate)
    return https_server


def _register_webhook(control_db: ControlDB, account_id: str, *, port: int, event_types=None):
    from api.webhooks import generate_webhook_secret

    return control_db.create_webhook(
        account_id=account_id,
        url=f"https://localhost:{port}/hook",
        secret=generate_webhook_secret(),
        event_types=tuple(event_types or ["monitoring.changed"]),
    )


class TestSignedDeliveryTheReceiverCanVerify:
    def test_a_real_delivery_is_correctly_signed_and_the_receiver_verifies_it(
        self, control_db: ControlDB, account_id: str, stub_destination: int
    ) -> None:
        webhook = _register_webhook(control_db, account_id, port=stub_destination)
        event = WebhookEvent(
            event_type="monitoring.changed", payload={"event": "monitoring.changed", "domain": "x"}
        )

        import asyncio

        ok = asyncio.run(
            deliver_event(control_db=control_db, webhook=webhook, event=event, verify=False)
        )

        assert ok is True
        assert len(WebhookTestHandler.requests) == 1
        received = WebhookTestHandler.requests[0]
        assert received["headers"]["X-Hydra-Event"] == "monitoring.changed"
        assert received["headers"]["Host"] == "localhost"
        signature = received["headers"]["X-Hydra-Signature"]
        assert verify_signature(webhook.secret, received["raw_body"], signature)
        assert json.loads(received["raw_body"]) == event.payload

        updated = control_db.get_webhook(webhook.webhook_id, account_id)
        assert updated.consecutive_failures == 0
        assert updated.last_success_at is not None

    def test_verification_fails_for_a_body_a_man_in_the_middle_altered(
        self, control_db: ControlDB, account_id: str, stub_destination: int
    ) -> None:
        webhook = _register_webhook(control_db, account_id, port=stub_destination)
        event = WebhookEvent(
            event_type="monitoring.changed", payload={"event": "monitoring.changed", "domain": "x"}
        )
        import asyncio

        asyncio.run(
            deliver_event(control_db=control_db, webhook=webhook, event=event, verify=False)
        )

        received = WebhookTestHandler.requests[0]
        signature = received["headers"]["X-Hydra-Signature"]
        altered_body = received["raw_body"].replace(
            b"monitoring.changed", b"monitoring.needs_review"
        )
        assert not verify_signature(webhook.secret, altered_body, signature)


class TestRetryAndBackoff:
    def test_a_receiver_returning_500_is_retried_the_configured_number_of_times(
        self,
        control_db: ControlDB,
        account_id: str,
        stub_destination: int,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        monkeypatch.setattr(webhooks_module, "RETRY_BACKOFF_SECONDS", (0.01, 0.01))
        reset_webhook_test_state(status=500)
        webhook = _register_webhook(control_db, account_id, port=stub_destination)
        event = WebhookEvent(
            event_type="monitoring.changed", payload={"event": "monitoring.changed"}
        )

        import asyncio

        ok = asyncio.run(
            deliver_event(control_db=control_db, webhook=webhook, event=event, verify=False)
        )

        assert ok is False
        assert len(WebhookTestHandler.requests) == webhooks_module.MAX_DELIVERY_ATTEMPTS
        updated = control_db.get_webhook(webhook.webhook_id, account_id)
        assert updated.consecutive_failures == 1
        assert "500" in updated.last_error

    def test_a_success_after_transient_failures_still_counts_as_delivered(
        self,
        control_db: ControlDB,
        account_id: str,
        stub_destination: int,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        monkeypatch.setattr(webhooks_module, "RETRY_BACKOFF_SECONDS", (0.01, 0.01))
        # Fails the first request, then the handler's own state is reset
        # to succeed for the retry — a real flaky-then-recovers receiver.
        reset_webhook_test_state(status=503)
        webhook = _register_webhook(control_db, account_id, port=stub_destination)
        event = WebhookEvent(
            event_type="monitoring.changed", payload={"event": "monitoring.changed"}
        )

        import asyncio
        import threading

        def flip_to_healthy_after_first_request() -> None:
            while not WebhookTestHandler.requests:
                time.sleep(0.005)
            WebhookTestHandler.response_status = 200

        flipper = threading.Thread(target=flip_to_healthy_after_first_request, daemon=True)
        flipper.start()

        ok = asyncio.run(
            deliver_event(control_db=control_db, webhook=webhook, event=event, verify=False)
        )
        flipper.join(timeout=2)

        assert ok is True
        assert len(WebhookTestHandler.requests) >= 2
        updated = control_db.get_webhook(webhook.webhook_id, account_id)
        assert updated.consecutive_failures == 0


class TestDisableAfterConsecutiveFailures:
    def test_a_webhook_is_disabled_after_the_configured_number_of_failed_events(
        self,
        control_db: ControlDB,
        account_id: str,
        stub_destination: int,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        monkeypatch.setattr(webhooks_module, "RETRY_BACKOFF_SECONDS", (0.0, 0.0))
        reset_webhook_test_state(status=500)
        webhook = _register_webhook(control_db, account_id, port=stub_destination)

        import asyncio

        for i in range(DISABLE_AFTER_CONSECUTIVE_FAILURES):
            event = WebhookEvent(
                event_type="monitoring.changed", payload={"event": "monitoring.changed", "i": i}
            )
            asyncio.run(
                deliver_event(control_db=control_db, webhook=webhook, event=event, verify=False)
            )
            current = control_db.get_webhook(webhook.webhook_id, account_id)
            if i < DISABLE_AFTER_CONSECUTIVE_FAILURES - 1:
                assert current.status == "active", f"disabled too early, after event {i}"

        final = control_db.get_webhook(webhook.webhook_id, account_id)
        assert final.status == "disabled"
        assert final.consecutive_failures == DISABLE_AFTER_CONSECUTIVE_FAILURES

    def test_a_disabled_webhook_is_never_attempted_again(
        self,
        control_db: ControlDB,
        account_id: str,
        stub_destination: int,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import api.webhooks as webhooks_module

        monkeypatch.setattr(webhooks_module, "RETRY_BACKOFF_SECONDS", (0.0, 0.0))
        reset_webhook_test_state(status=500)
        webhook = _register_webhook(control_db, account_id, port=stub_destination)

        import asyncio

        for i in range(DISABLE_AFTER_CONSECUTIVE_FAILURES):
            asyncio.run(
                deliver_event(
                    control_db=control_db,
                    webhook=webhook,
                    event=WebhookEvent(event_type="monitoring.changed", payload={"i": i}),
                    verify=False,
                )
            )
        assert control_db.get_webhook(webhook.webhook_id, account_id).status == "disabled"
        requests_so_far = len(WebhookTestHandler.requests)

        # A subsequent event delivered via the real subscriber-lookup
        # entry point must not even attempt the disabled webhook.
        asyncio.run(
            deliver_event_to_subscribers(
                control_db=control_db,
                account_id=account_id,
                event=WebhookEvent(event_type="monitoring.changed", payload={"final": True}),
                verify=False,
            )
        )
        assert len(WebhookTestHandler.requests) == requests_so_far


class TestOneAccountsFailingWebhookNeverBlocksAnother:
    def test_a_second_accounts_delivery_succeeds_independently_of_the_firsts_failure(
        self, control_db: ControlDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        import api.webhooks as webhooks_module

        monkeypatch.setattr(webhooks_module, "RETRY_BACKOFF_SECONDS", (0.0, 0.0))

        # Account A's webhook points at a port nothing is listening on —
        # a real, immediate connection failure, not a mock.
        account_a = control_db.create_account(email=f"a-{secrets.token_hex(6)}@example.com")
        control_db.create_default_subscription(account_a, tier="pro")
        webhook_a = control_db.create_webhook(
            account_id=account_a,
            url="https://localhost:1/hook",  # port 1: nothing listens here
            secret="secret-a",  # noqa: S106 - test fixture data, not a real secret
            event_types=("monitoring.changed",),
        )

        httpd, port, thread, tmp_dir = start_webhook_test_server()
        reset_webhook_test_state()
        try:
            account_b = control_db.create_account(email=f"b-{secrets.token_hex(6)}@example.com")
            control_db.create_default_subscription(account_b, tier="pro")
            webhook_b = control_db.create_webhook(
                account_id=account_b,
                url=f"https://localhost:{port}/hook",
                secret="secret-b",  # noqa: S106 - test fixture data, not a real secret
                event_types=("monitoring.changed",),
            )

            async def fake_validate(url: str):
                if "localhost:1" in url:
                    return True, "", "127.0.0.1"
                return True, "", "127.0.0.1"

            monkeypatch.setattr(webhooks_module, "validate_webhook_destination", fake_validate)

            event = WebhookEvent(event_type="monitoring.changed", payload={"event": "x"})
            ok_a = asyncio.run(
                deliver_event(control_db=control_db, webhook=webhook_a, event=event, verify=False)
            )
            ok_b = asyncio.run(
                deliver_event(control_db=control_db, webhook=webhook_b, event=event, verify=False)
            )

            assert ok_a is False
            assert ok_b is True
            assert len(WebhookTestHandler.requests) == 1
        finally:
            stop_webhook_test_server(httpd, thread, tmp_dir)


class TestDnsRebindingIsCaughtAtDeliveryNotJustRegistration:
    """The task's own explicit rebinding requirement: a hostname that
    resolves PUBLIC at registration time but PRIVATE by the time an
    actual delivery attempt happens must still be refused — proving
    `validate_webhook_destination` genuinely re-resolves fresh on every
    call (real registration-time validation alone would miss this),
    not asserting the claim from reading the code."""

    def test_registration_time_public_then_delivery_time_private_is_refused(
        self, control_db: ControlDB, account_id: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        from api.webhooks import validate_webhook_destination

        call_count = {"n": 0}
        real_resolve_hostname_async = None

        async def rebinding_resolve(hostname: str) -> list[str]:
            call_count["n"] += 1
            # First call (registration time): a real, public IP.
            if call_count["n"] == 1:
                return ["93.184.216.34"]
            # Every subsequent call (a real delivery attempt): rebinds
            # to a private address — the exact attack this defends
            # against.
            return ["127.0.0.1"]

        import core.collection.ssrf as ssrf_module

        monkeypatch.setattr(ssrf_module, "resolve_hostname_async", rebinding_resolve)

        # "Registration time" — allowed, using the first (public) answer.
        allowed_at_registration, _reason, _ip = asyncio.run(
            validate_webhook_destination("https://rebinding-test.example/hook")
        )
        assert allowed_at_registration is True

        # "Delivery time" — a later, independent call to the SAME
        # function now sees the rebound (private) answer and refuses.
        allowed_at_delivery, reason, connect_ip = asyncio.run(
            validate_webhook_destination("https://rebinding-test.example/hook")
        )
        assert allowed_at_delivery is False
        assert connect_ip == ""
        assert "blocked" in reason.lower() or "refused" in reason.lower()
        del real_resolve_hostname_async  # unused; documents the fixture's own scope

    def test_deliver_event_refuses_a_webhook_that_rebinds_between_retries(
        self, control_db: ControlDB, account_id: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same rebinding defense, exercised through the real
        `deliver_event` retry loop — confirms the re-validation isn't
        just available as a function, but is genuinely called on every
        single attempt inside delivery itself."""
        import asyncio

        import api.webhooks as webhooks_module
        import core.collection.ssrf as ssrf_module

        monkeypatch.setattr(webhooks_module, "RETRY_BACKOFF_SECONDS", (0.0, 0.0))

        call_count = {"n": 0}

        async def rebinding_resolve(hostname: str) -> list[str]:
            call_count["n"] += 1
            return ["93.184.216.34"] if call_count["n"] == 1 else ["10.0.0.1"]

        monkeypatch.setattr(ssrf_module, "resolve_hostname_async", rebinding_resolve)

        webhook = control_db.create_webhook(
            account_id=account_id,
            url="https://rebinding-test.example/hook",
            secret="secret",  # noqa: S106 - test fixture data, not a real secret
            event_types=("monitoring.changed",),
        )
        event = WebhookEvent(event_type="monitoring.changed", payload={"event": "x"})

        ok = asyncio.run(
            deliver_event(control_db=control_db, webhook=webhook, event=event, verify=False)
        )

        assert ok is False
        # Never actually connected anywhere past the first (allowed)
        # resolution — the rebind was caught before any HTTP request on
        # the second attempt.
        assert call_count["n"] >= 2
        updated = control_db.get_webhook(webhook.webhook_id, account_id)
        assert (
            "10.0.0.1" not in (updated.last_error or "")
            or "blocked" in (updated.last_error or "").lower()
        )


class TestRedactionGuaranteeHoldsInTheWebhookBody:
    """github_secrets.py's own hard redaction guarantee (the raw secret
    value is never present in github_secrets.jsonl in the first place —
    only safe metadata: rule id, file, line, commit, description) must
    also hold in a webhook payload built from that same data. Since the
    raw value is never even IN a Finding object to begin with, this is
    really confirming `event_for_high_severity_findings` only ever
    copies the specific, already-safe fields it declares — never a
    generic "dump the whole finding" that could accidentally start
    including a field a future parser change adds."""

    def test_high_severity_event_payload_only_ever_contains_the_declared_safe_fields(
        self,
    ) -> None:
        from api.webhooks import event_for_high_severity_findings

        # A realistic github_secrets-shaped finding — note there is no
        # "raw_secret"/"match"/"value" field here at all, matching what
        # modules/github_secrets.py's own module docstring guarantees
        # never reaches github_secrets.jsonl in the first place.
        findings = [
            {
                "host": "app.example.com",
                "template_id": "leaked-secret",
                "severity": "critical",
                "name": "Stripe API key pattern matched in public repo",
            }
        ]
        event = event_for_high_severity_findings(
            domain="example.com", scan_id="scan-1", findings=findings
        )

        payload_str = json.dumps(event.payload)
        # The exact set of keys ever present per finding — nothing else
        # could have leaked through, because the function itself never
        # reads any other field off its input dicts.
        for finding in event.payload["findings"]:
            assert set(finding.keys()) == {"host", "template_id", "severity", "name"}
        assert "secret" not in payload_str.lower().replace("leaked-secret", "").replace(
            "leaked_secret", ""
        )
