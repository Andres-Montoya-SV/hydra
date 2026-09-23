"""Transactional email delivery — account-email verification (Hallazgo 1:
`POST /accounts` must not create an immediately-usable account without
proving the client controls a real, distinct email address) and, since
the "Automatic billing enforcement and data retention purge" task,
account-suspension notices too. `EmailSender` is a `Protocol`, not a
concrete dependency — the same "structural interface, no shared base
class" choice `core/reportability/provider.py::ReportabilityProvider`
already made.

**Why a second Protocol method (`send_account_suspended_email`) instead
of one generic "send this content" method**: every other typed method
here (`send_verification_email`) takes structured, purpose-specific
arguments (`token`, not a pre-rendered body) so each implementation
decides its own subject/body/formatting — a generic
`send(subject, body)` method would push that decision onto every
CALLER instead, meaning `api/reconciliation_worker.py` would need to
know how to write a suspension email itself, duplicating the same
"one content-builder function per email kind" pattern
(`_verification_email_content`/`_account_suspended_email_content`/
`_monitoring_alert_email_content`) this module already uses. Typed
methods sharing one Protocol keeps that consistent, at the cost of a new
method per email kind added later — judged the right tradeoff while
there are only a handful of kinds of email total (three, as of the
continuous-monitoring task's `send_monitoring_alert`).

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
besides the two built so far (verification, suspension — scan-complete
and password reset still don't exist); a clickable link (no frontend
base URL exists to build one against); choosing between Postmark's
transactional/broadcast message streams (both emails sent today are
transactional in nature, so there is still nothing to choose between —
the default stream is used, unconfigured).
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

    def send_account_suspended_email(self, *, to: str, account_id: str) -> None: ...

    def send_monitoring_alert(
        self, *, to: str, account_id: str, summary_lines: list[str], truncated_count: int
    ) -> None: ...


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

    def send_account_suspended_email(self, *, to: str, account_id: str) -> None:
        logger.info(
            "[DEV EMAIL — no real provider configured] To: %s | Account %s was suspended "
            "(grace period expired with no successful payment).",
            to,
            account_id,
        )

    def send_monitoring_alert(
        self, *, to: str, account_id: str, summary_lines: list[str], truncated_count: int
    ) -> None:
        logger.info(
            "[DEV EMAIL — no real provider configured] To: %s | Monitoring alert for "
            "account %s:\n%s%s",
            to,
            account_id,
            "\n".join(summary_lines),
            f"\n…and {truncated_count} more." if truncated_count else "",
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


def _account_suspended_email_content(*, account_id: str) -> tuple[str, str]:
    """The grace-period-enforcement job's suspension notice
    (docs/PAID_API_DESIGN.md's "Automatic billing enforcement and data
    retention purge" section) — the real self-service UX gap this task
    closed: without this, a customer whose card failed silently loses
    `POST /scans` access (`402`) with no explanation anywhere but an API
    error response they may never see until they try to run a scan."""
    subject = "Your Hydra account has been suspended"
    body = (
        "Your Hydra account has been suspended because a payment could not be "
        "completed and the 3-day grace period has now expired.\n\n"
        "While suspended, new scans cannot be started (POST /scans returns 402). "
        "Reports you already have keep working normally — nothing already "
        "delivered to you is affected.\n\n"
        "To restore access, complete payment for your subscription tier; your "
        "account is reactivated automatically as soon as a successful payment "
        "is confirmed.\n\n"
        f"Account reference: {account_id}\n"
    )
    return subject, body


def _monitoring_alert_email_content(
    *, summary_lines: list[str], truncated_count: int
) -> tuple[str, str]:
    """The continuous-monitoring task's capped/summarized notification —
    `summary_lines` is already ordered and truncated by the caller
    (`api/monitoring_worker.py`, using `api/monitoring.py::significance_rank`
    and `APISettings.monitoring_max_domains_per_email`); this function only
    ever renders what it's given, never re-sorts or re-truncates, so the
    ordering/cap decision lives in exactly one place."""
    subject = "Hydra monitoring: changes detected"
    body_lines = [
        "Your Hydra continuous monitoring detected changes across one or more "
        "of your monitored domains:\n",
    ]
    body_lines.extend(summary_lines)
    if truncated_count:
        body_lines.append(f"\n…and {truncated_count} more domain(s) with changes this cycle.")
    body_lines.append(
        "\nSign in via the API (GET /domains/{domain}/monitoring) for the full detail "
        "on any of these."
    )
    return subject, "\n".join(body_lines)


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
        subject, text_body = _verification_email_content(token=token)
        self._send(
            to=to,
            account_id=account_id,
            subject=subject,
            text_body=text_body,
            purpose="verification email",
            retry_hint="POST /accounts/resend-verification will retry once this is resolved.",
        )

    def send_account_suspended_email(self, *, to: str, account_id: str) -> None:
        subject, text_body = _account_suspended_email_content(account_id=account_id)
        self._send(
            to=to,
            account_id=account_id,
            subject=subject,
            text_body=text_body,
            purpose="suspension notice",
            # There is no equivalent resend endpoint for this one — the
            # account is already suspended regardless of whether the
            # email landed, and the next reconciliation cycle does not
            # re-suspend an already-suspended account (only 'past_due'
            # ones), so a failed send here is simply lost, not retried.
            retry_hint="No automatic retry exists for this notice.",
        )

    def send_monitoring_alert(
        self, *, to: str, account_id: str, summary_lines: list[str], truncated_count: int
    ) -> None:
        subject, text_body = _monitoring_alert_email_content(
            summary_lines=summary_lines, truncated_count=truncated_count
        )
        self._send(
            to=to,
            account_id=account_id,
            subject=subject,
            text_body=text_body,
            purpose="monitoring alert",
            # Same reasoning as the suspension notice: the next
            # monitoring cycle simply reports fresh changes on its own
            # schedule — there is nothing here to "resend."
            retry_hint="No automatic retry exists for this notice.",
        )

    def _send(
        self,
        *,
        to: str,
        account_id: str,
        subject: str,
        text_body: str,
        purpose: str,
        retry_hint: str,
    ) -> None:
        """Shared by both `EmailSender` methods — the request shape,
        failure handling (never raise, log at ERROR, never leak the
        server token), and success-vs-Postmark-level-error checks are
        identical regardless of which email is being sent; only the
        subject/body and the log wording differ."""
        import httpx as _httpx

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
                "Failed to send %s for account %s via Postmark: network error (%s). %s",
                purpose,
                account_id,
                type(exc).__name__,
                retry_hint,
            )
            return

        if response.status_code != 200:
            # Built entirely from POSTMARK'S OWN response body/status —
            # never from the request we sent, which carried the server
            # token in its headers.
            self._log_postmark_error(account_id, response, purpose=purpose, retry_hint=retry_hint)
            return

        body = response.json()
        if body.get("ErrorCode", 0) != 0:
            self._log_postmark_error(account_id, response, purpose=purpose, retry_hint=retry_hint)

    def _log_postmark_error(
        self, account_id: str, response: httpx.Response, *, purpose: str, retry_hint: str
    ) -> None:
        try:
            body = response.json()
            error_code = body.get("ErrorCode")
            message = body.get("Message")
        except ValueError:
            error_code, message = None, response.text[:200]
        logger.error(
            "Failed to send %s for account %s via Postmark: HTTP %s, ErrorCode=%s, "
            "Message=%s. %s",
            purpose,
            account_id,
            response.status_code,
            error_code,
            message,
            retry_hint,
        )
