"""Email-verification delivery (Hallazgo 1: `POST /accounts` must not
create an immediately-usable account without proving the client controls
a real, distinct email address). `EmailSender` is a `Protocol`, not a
concrete dependency — the same "structural interface, no shared base
class" choice `core/reportability/provider.py::ReportabilityProvider`
already made, since every implementation shares nothing but this one
method's shape.

**Stated explicitly, as this round's task required**: `ConsoleEmailSender`
below is the only implementation that exists. It logs the verification
token/instructions via the standard `logging` module (console by
default; a real deployment's own log-file configuration captures it
from there, same as any other application log line — no separate
file-writing code needed). **Connecting a real provider (SendGrid, AWS
SES, Postmark, etc.) is NOT built and must happen before this account-
verification flow is exposed to real, non-operator users** — until then,
every "sent" email is only ever visible in this process's own logs,
which is fine for development/internal testing and actively wrong for
production.
"""

from __future__ import annotations

import logging
from typing import Protocol

logger = logging.getLogger("hydra.api.email")


class EmailSender(Protocol):
    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None: ...


class ConsoleEmailSender:
    """Logs the verification instructions instead of sending real email.
    A developer/tester completes the flow by reading this log line and
    calling `POST /accounts/verify-email` with the printed token
    directly — there is no clickable link because this service has no
    public web frontend of its own to host one; a real deployment's
    frontend would construct that link using its own base URL and this
    same token."""

    def send_verification_email(self, *, to: str, account_id: str, token: str) -> None:
        logger.info(
            "[DEV EMAIL — no real provider configured] To: %s | Verify account %s by calling "
            'POST /accounts/verify-email {"token": %r}',
            to,
            account_id,
            token,
        )
