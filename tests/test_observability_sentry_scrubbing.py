"""Sentry error-tracking scrubbing (docs/PAID_API_DESIGN.md's "Basic
observability" section) — proven with a REAL intercepted payload, not
asserted from reading `api/observability.py`. Intercepts the SDK's own
`Transport.capture_envelope` (the real, current transport interface in
this pinned `sentry-sdk` version — confirmed directly against the
installed package, not assumed), triggers a real captured exception
carrying a realistic fake secret, and inspects exactly what the
transport actually received.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("sentry_sdk")

import sentry_sdk  # noqa: E402
from sentry_sdk.transport import Transport  # noqa: E402

from api.observability import make_before_send  # noqa: E402

FAKE_POSTMARK_TOKEN = "postmark-real-secret-abc123xyz"  # noqa: S105
FAKE_WOMPI_SECRET = "wompi-real-secret-def456uvw"  # noqa: S105
FAKE_API_KEY = "hydra_live_totally_real_looking_customer_api_key_789"  # noqa: S105


class _CapturingTransport(Transport):
    """A real `sentry_sdk.transport.Transport` subclass — not a mock of
    the SDK's own behavior, an actual implementation of its real
    interface, capturing whatever `sentry_sdk.init()`'s pipeline
    (including `before_send`) actually decided to hand to a transport."""

    def __init__(self) -> None:
        super().__init__()
        self.captured_events: list[dict] = []

    def capture_envelope(self, envelope) -> None:  # noqa: ANN001
        event = envelope.get_event()
        if event is not None:
            self.captured_events.append(event)


@pytest.fixture
def capturing_sentry():
    transport = _CapturingTransport()
    client = sentry_sdk.Client(
        dsn="https://fakepublickey@fake.ingest.sentry.io/1",
        transport=transport,
        before_send=make_before_send([FAKE_POSTMARK_TOKEN, FAKE_WOMPI_SECRET]),
    )
    scope = sentry_sdk.Scope.get_current_scope()
    old_client = scope.client
    sentry_sdk.Scope.get_global_scope().set_client(client)
    try:
        yield transport
    finally:
        sentry_sdk.Scope.get_global_scope().set_client(old_client)
        client.close()


def _full_text(events: list[dict]) -> str:
    return json.dumps(events)


class TestKnownStaticSecretsAreScrubbedFromRealCapturedEvents:
    def test_a_secret_embedded_in_the_exception_message_never_appears(
        self, capturing_sentry: _CapturingTransport
    ) -> None:
        try:
            raise RuntimeError(f"Postmark call failed using token {FAKE_POSTMARK_TOKEN}")
        except RuntimeError:
            sentry_sdk.capture_exception()

        assert len(capturing_sentry.captured_events) == 1
        full_text = _full_text(capturing_sentry.captured_events)
        assert FAKE_POSTMARK_TOKEN not in full_text
        assert "[Filtered]" in full_text

    def test_a_secret_embedded_in_a_local_variable_never_appears(
        self, capturing_sentry: _CapturingTransport
    ) -> None:
        def _do_wompi_call() -> None:
            wompi_client_secret = FAKE_WOMPI_SECRET  # noqa: F841 - deliberately captured via locals
            raise ValueError("webhook signature check failed")

        try:
            _do_wompi_call()
        except ValueError:
            sentry_sdk.capture_exception()

        full_text = _full_text(capturing_sentry.captured_events)
        assert FAKE_WOMPI_SECRET not in full_text

    def test_a_secret_embedded_in_extra_context_never_appears(
        self, capturing_sentry: _CapturingTransport
    ) -> None:
        sentry_sdk.set_extra("last_wompi_secret_used", FAKE_WOMPI_SECRET)
        try:
            raise RuntimeError("something unrelated failed")
        except RuntimeError:
            sentry_sdk.capture_exception()

        full_text = _full_text(capturing_sentry.captured_events)
        assert FAKE_WOMPI_SECRET not in full_text


class TestSensitiveHeadersAreStrippedRegardlessOfValue:
    """`X-API-Key` is per-request — its VALUE isn't known ahead of time
    the way a static secret is, so this must be scrubbed by HEADER NAME,
    not by matching a specific known value."""

    def test_x_api_key_header_value_is_redacted_even_though_its_value_was_never_in_the_secrets_list(
        self, capturing_sentry: _CapturingTransport
    ) -> None:
        fake_event = {
            "request": {"headers": {"X-Api-Key": FAKE_API_KEY, "Content-Type": "application/json"}}
        }
        hook = make_before_send([])
        scrubbed = hook(fake_event, {})

        assert scrubbed["request"]["headers"]["X-Api-Key"] == "[Filtered]"
        assert scrubbed["request"]["headers"]["Content-Type"] == "application/json"
        full_text = json.dumps(scrubbed)
        assert FAKE_API_KEY not in full_text

    def test_list_shaped_headers_are_also_scrubbed(self) -> None:
        fake_event = {
            "request": {
                "headers": [
                    ["Authorization", "Bearer " + FAKE_API_KEY],
                    ["Content-Type", "application/json"],
                ]
            }
        }
        hook = make_before_send([])
        scrubbed = hook(fake_event, {})

        headers = dict(scrubbed["request"]["headers"])
        assert headers["Authorization"] == "[Filtered]"
        assert headers["Content-Type"] == "application/json"


class TestZeroConfigStaysOff:
    def test_no_sentry_dsn_means_init_sentry_does_nothing(self, tmp_path) -> None:  # noqa: ANN001
        from api.observability import init_sentry
        from api.settings import APISettings

        settings = APISettings(data_dir=tmp_path / "api_data")
        assert settings.sentry_dsn is None
        assert init_sentry(settings) is False
