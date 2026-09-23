"""`api/email_sender.py::PostmarkEmailSender` — against a real local HTTP
server standing in for `api.postmarkapp.com`
(`tests/_fake_postmark_server.py`), this project's established "real
server as arbiter" pattern (the same one `tests/test_wompi_client.py`
already uses for Wompi), never a mocked `httpx` call. Real, live calls
to the actual `api.postmarkapp.com` are out of scope entirely — this
task ships with no real Postmark credentials on purpose (the operator
supplies those after merge), so there is nothing to call live even once,
unlike the Wompi OAuth exchange's one real demonstration call.
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")

from _fake_postmark_server import (  # noqa: E402
    FakePostmarkHandler,
    reset_fake_postmark_state,
    start_fake_postmark_server,
    stop_fake_postmark_server,
)

from api.email_sender import PostmarkEmailSender  # noqa: E402

# Obviously-fake placeholder values — never a realistic-looking real
# secret, per this task's own explicit requirement.
FAKE_SERVER_TOKEN = "postmark-server-token-placeholder"  # noqa: S105
FAKE_FROM = "noreply@example.com"


@pytest.fixture
def postmark_server():
    reset_fake_postmark_state()
    httpd, port, thread = start_fake_postmark_server()
    try:
        yield f"http://127.0.0.1:{port}/email"
    finally:
        stop_fake_postmark_server(httpd, thread)


def _sender(send_url: str, **overrides: object) -> PostmarkEmailSender:
    kwargs: dict[str, object] = {
        "server_token": FAKE_SERVER_TOKEN,
        "from_address": FAKE_FROM,
        "from_name": "Hydra",
        "send_url": send_url,
        "timeout_seconds": 0.3,
    }
    kwargs.update(overrides)
    return PostmarkEmailSender(**kwargs)  # type: ignore[arg-type]


class TestSuccessfulSend:
    def test_sends_the_correct_request_shape(self, postmark_server: str) -> None:
        sender = _sender(postmark_server)
        sender.send_verification_email(
            to="user@example.com", account_id="acct-1", token="tok-123"  # noqa: S106
        )

        assert len(FakePostmarkHandler.requests) == 1
        request = FakePostmarkHandler.requests[0]
        assert request["headers"]["X-Postmark-Server-Token"] == FAKE_SERVER_TOKEN
        assert request["headers"]["Content-Type"] == "application/json"
        body = request["body"]
        assert body["To"] == "user@example.com"
        assert body["From"] == f"Hydra <{FAKE_FROM}>"
        assert "tok-123" in body["TextBody"]
        assert "Subject" in body

    def test_never_sends_a_clickable_link_only_the_token(self, postmark_server: str) -> None:
        """No public frontend exists yet to build a link against — the
        email must tell a real person the token/endpoint, not a URL."""
        sender = _sender(postmark_server)
        sender.send_verification_email(
            to="user@example.com", account_id="acct-1", token="tok-456"  # noqa: S106
        )
        body = FakePostmarkHandler.requests[0]["body"]
        assert "http://" not in body["TextBody"]
        assert "https://" not in body["TextBody"]
        assert "/accounts/verify-email" in body["TextBody"]


class TestAccountSuspendedEmail:
    """The second email kind (`api/reconciliation_worker.py`'s
    grace-period job) — same request shape/failure handling as
    verification email (shared via `PostmarkEmailSender._send`), a
    different subject/body."""

    def test_sends_the_correct_request_shape(self, postmark_server: str) -> None:
        sender = _sender(postmark_server)
        sender.send_account_suspended_email(to="user@example.com", account_id="acct-9")

        assert len(FakePostmarkHandler.requests) == 1
        request = FakePostmarkHandler.requests[0]
        body = request["body"]
        assert body["To"] == "user@example.com"
        assert "acct-9" in body["TextBody"]
        assert "suspend" in body["Subject"].lower()

    def test_a_failure_does_not_raise_and_never_leaks_the_token(
        self, postmark_server: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        reset_fake_postmark_state(status=422, body={"ErrorCode": 300, "Message": "bad"})
        sender = _sender(postmark_server)
        with caplog.at_level("ERROR"):
            sender.send_account_suspended_email(to="user@example.com", account_id="acct-10")
        full_log = "\n".join(record.message for record in caplog.records)
        assert "acct-10" in full_log
        assert FAKE_SERVER_TOKEN not in full_log


class TestFailureNeverBreaksAccountCreation:
    """The documented decision: a send failure is logged, never raised —
    POST /accounts must always succeed regardless."""

    def test_a_401_bad_token_response_does_not_raise(
        self, postmark_server: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        reset_fake_postmark_state(
            status=401, body={"ErrorCode": 10, "Message": "Invalid API token."}
        )
        sender = _sender(postmark_server)
        with caplog.at_level("ERROR"):
            sender.send_verification_email(
                to="user@example.com", account_id="acct-1", token="t"  # noqa: S106
            )
        assert any("acct-1" in record.message for record in caplog.records)

    def test_a_401_response_never_logs_the_server_token(
        self, postmark_server: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        reset_fake_postmark_state(
            status=401, body={"ErrorCode": 10, "Message": "Invalid API token."}
        )
        sender = _sender(postmark_server)
        with caplog.at_level("ERROR"):
            sender.send_verification_email(
                to="user@example.com", account_id="acct-1", token="t"  # noqa: S106
            )
        full_log = "\n".join(record.message for record in caplog.records)
        assert FAKE_SERVER_TOKEN not in full_log

    def test_a_422_invalid_recipient_response_does_not_raise(self, postmark_server: str) -> None:
        reset_fake_postmark_state(
            status=422,
            body={"ErrorCode": 300, "Message": "Invalid email request: Invalid 'To' address."},
        )
        sender = _sender(postmark_server)
        # No exception — this is the assertion.
        sender.send_verification_email(
            to="not-a-real-address", account_id="acct-2", token="t"  # noqa: S106
        )

    def test_a_network_error_does_not_raise(self) -> None:
        # Nothing listening on this port at all.
        sender = _sender("http://127.0.0.1:1/email", timeout_seconds=0.3)
        sender.send_verification_email(
            to="user@example.com", account_id="acct-3", token="t"  # noqa: S106
        )

    def test_a_network_error_never_leaks_the_server_token_in_a_log_line(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        sender = _sender("http://127.0.0.1:1/email", timeout_seconds=0.3)
        with caplog.at_level("ERROR"):
            sender.send_verification_email(
                to="user@example.com", account_id="acct-4", token="t"  # noqa: S106
            )
        full_log = "\n".join(record.message for record in caplog.records)
        assert FAKE_SERVER_TOKEN not in full_log


class TestTimeoutIsReal:
    def test_a_slow_server_past_the_timeout_does_not_hang_or_raise(
        self, postmark_server: str
    ) -> None:
        import time

        reset_fake_postmark_state(delay_seconds=1.0)
        sender = _sender(postmark_server, timeout_seconds=0.2)

        started = time.monotonic()
        sender.send_verification_email(
            to="user@example.com", account_id="acct-5", token="t"  # noqa: S106
        )
        elapsed = time.monotonic() - started

        # Must have timed out near the configured 0.2s, never waited out
        # the server's full 1.0s delay.
        assert elapsed < 0.9
