"""Email-verification delivery (Hallazgo 1: `POST /accounts` must not
create an immediately-usable account without proving the client controls
a real, distinct email address). `EmailSender` is a `Protocol`, not a
concrete dependency — the same "structural interface, no shared base
class" choice `core/reportability/provider.py::ReportabilityProvider`
already made, since every implementation shares nothing but this one
method's shape.

**Two implementations now exist, selected automatically by
`api/main.py`'s `lifespan` based on which environment variables are
present** (`ConsoleEmailSender` when Postmark isn't configured,
`PostmarkEmailSender` when it is — see that module for the exact
selection logic and the startup log line that states which one is
active):

- **`ConsoleEmailSender`** — logs the verification token/instructions via
  the standard `logging` module. This is the unconditional default with
  zero configuration, and stays that way forever for local dev/tests —
  nothing about adding Postmark support changes this path's behavior.
- **`PostmarkEmailSender`** — sends a real transactional email via
  Postmark's REST API (`postmarkapp.com`). Confirmed directly against
  Postmark's own current API documentation before writing this (not
  assumed from memory), the same "confirmed against current docs"
  discipline `api/wompi_client.py` already established for Wompi:
  - `POST https://api.postmarkapp.com/email`
    (`postmarkapp.com/developer/api/email-api`) — JSON body, auth via
    the `X-Postmark-Server-Token` header (not a bearer token, not a
    query param).
  - Error shape (`postmarkapp.com/developer/api/overview`): `401` for a
    missing/invalid server token, `422` for a validation failure
    (malformed recipient, suppressed address, etc.), `429` for rate
    limiting — body `{"ErrorCode": <int>, "Message": <str>}` on any
    non-2xx.
  - No clickable link in the email body — same reasoning
    `ConsoleEmailSender` already had: this service has no public web
    frontend of its own yet to host one, so the email tells a real
    person, in plain language, which endpoint to call and which field
    the token goes in. `_verification_email_content()` builds the
    subject/text body in one place specifically so a future frontend
    base URL is a one-line change there, not a restructuring of the
    sender.

**The failure-handling decision, made and stated explicitly (not left
as a reflexive try/except)**: a `PostmarkEmailSender` failure —
non-2xx from Postmark, or the request itself raising (timeout, DNS,
connection refused) — is caught INSIDE `send_verification_email` and
never propagates. `POST /accounts` (`api/routers/accounts.py`) always
succeeds and returns a real, usable `api_key` regardless of whether the
email actually sent; the failure is logged at `ERROR` with enough
detail to diagnose it (the HTTP status, Postmark's own `ErrorCode`/
`Message`, or the exception type/message for a network failure).
Reasoning: `POST /accounts/resend-verification` already exists as the
exact recovery path for "the email never arrived" — a transient
Postmark outage or a not-yet-fixed misconfiguration (wrong server
token, unverified sender) blocking the ENTIRE account-creation endpoint
would be a strictly worse failure mode than an account that exists,
authenticates, and can retry verification once the underlying problem
is fixed. This mirrors the existing precedent in this codebase for a
degraded-but-not-fatal external dependency (Part D.3's payment-failure
grace period: a third party being unreliable is never treated as the
CLIENT's fault). **The one hard rule regardless of any of the above:
the Postmark server token itself must never appear in a log line, an
exception message, or anything that could end up in `control_db` or an
HTTP response body** — every error path below builds its log message
from Postmark's own returned `ErrorCode`/`Message`/HTTP status or the
exception's type name, never by interpolating the token or the raw
request itself (which contains the token in its headers).

**Explicit non-goals for this pass** (deferred, not silently skipped):
bounce/complaint/suppression webhook handling from Postmark; any email
besides this one verification message (scan-complete, billing, password
reset — none of that exists yet); a clickable link (no frontend base
URL exists to build one against); choosing between Postmark's
transactional/broadcast message streams (only one kind of email is sent
today, so there is nothing to choose between yet — the default stream
is used, unconfigured).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger("hydra.api.email")

_POSTMARK_SEND_URL = "https://api.postmarkapp.com/email"
# A hung Postmark call must never hang POST /accounts — short and
# explicit rather than left at whatever httpx's own default is. 10s is
# generous for a single small JSON POST to a well-provisioned
# transactional API; long enough to absorb ordinary latency, short
# enough that a real outage fails fast instead of tying up a request
# thread.
_POSTMARK_TIMEOUT_SECONDS = 10.0


class EmailSender(Protocol):
    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None: ...


class ConsoleEmailSender:
    """Logs the verification instructions instead of sending real email.
    A developer/tester completes the flow by reading this log line and
    calling `POST /accounts/verify-email` with the printed token
    directly — there is no clickable link because this service has no
    public web frontend of its own to host one; a real deployment's
    frontend would construct that link using its own base URL and this
    same token. The unconditional default with zero configuration —
    see `api/main.py`'s `lifespan` for the selection logic."""

    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None:
        logger.info(
            "[DEV EMAIL — no real provider configured] To: %s | Verify account %s by calling "
            'POST /accounts/verify-email {"token": %r}',
            to,
            account_id,
            token,
        )


def _verification_email_content(*, token: str) -> tuple[str, str]:
    """Returns (subject, text_body) — factored out on its own so a
    future clickable-link version only ever needs to change this one
    function, never `PostmarkEmailSender` itself. Written as an actual
    email a real, non-technical recipient would receive, not a copy of
    `ConsoleEmailSender`'s log-line phrasing."""
    subject = "Confirm your Hydra account"
    body = (
        "Thanks for signing up for Hydra.\n\n"
        "To confirm this is your email address and activate scanning on your "
        "account, send the confirmation code below to our API:\n\n"
        f"    {token}\n\n"
        "If you're using the Hydra API directly, confirm by calling:\n"
        f'    POST /accounts/verify-email  {{"token": "{token}"}}\n\n'
        "If you didn't create a Hydra account, you can safely ignore this email.\n"
    )
    return subject, body


class PostmarkEmailSender:
    """Sends the verification email for real, via Postmark
    (`postmarkapp.com/developer/api/email-api`). Selected automatically
    only when both a server token and a from-address are configured
    (`api/main.py`'s `lifespan`) — never partially configured, see
    `api/settings.py::load_api_settings`'s startup check."""

    def __init__(
        self,
        *,
        server_token: str,
        from_address: str,
        from_name: str,
        send_url: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self._server_token = server_token
        self._from_address = from_address
        self._from_name = from_name
        # Both overridable ONLY for tests (a real local HTTP server
        # standing in for api.postmarkapp.com — this project's
        # established "real server as arbiter" pattern, the same
        # dev-override shape `api/wompi_client.py::WompiClient`'s
        # `api_base_url` already uses) — never set by any real
        # deployment path. `timeout_seconds` lets a test exercise the
        # real timeout path in well under a second instead of actually
        # waiting `_POSTMARK_TIMEOUT_SECONDS`.
        self._send_url = send_url or _POSTMARK_SEND_URL
        self._timeout_seconds = timeout_seconds or _POSTMARK_TIMEOUT_SECONDS

    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None:
        import httpx as _httpx

        subject, text_body = _verification_email_content(token=token)
        try:
            response = _httpx.post(
                self._send_url,
                json={
                    "From": f"{self._from_name} <{self._from_address}>",
                    "To": to,
                    "Subject": subject,
                    "TextBody": text_body,
                },
                headers={
                    "X-Postmark-Server-Token": self._server_token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=self._timeout_seconds,
            )
        except _httpx.RequestError as exc:
            # Network-level failure (timeout, DNS, connection refused,
            # ...) — never the exception's own str(exc) verbatim if it
            # could ever echo request internals; log only the exception
            # TYPE, which carries no header/token content.
            logger.error(
                "Failed to send verification email for account %s via Postmark: "
                "network error (%s). The account was still created; "
                "POST /accounts/resend-verification will retry once this is resolved.",
                account_id,
                type(exc).__name__,
            )
            return

        if response.status_code != 200:
            # Built entirely from POSTMARK'S OWN response body/status —
            # never from the request we sent, which carried the server
            # token in its headers.
            self._log_postmark_error(account_id, response)
            return

        body = response.json()
        if body.get("ErrorCode", 0) != 0:
            self._log_postmark_error(account_id, response)

    def _log_postmark_error(self, account_id: str, response: httpx.Response) -> None:
        try:
            body = response.json()
            error_code = body.get("ErrorCode")
            message = body.get("Message")
        except ValueError:
            error_code, message = None, response.text[:200]
        logger.error(
            "Failed to send verification email for account %s via Postmark: "
            "HTTP %s, ErrorCode=%s, Message=%s. The account was still created; "
            "POST /accounts/resend-verification will retry once this is resolved.",
            account_id,
            response.status_code,
            error_code,
            message,
        )
