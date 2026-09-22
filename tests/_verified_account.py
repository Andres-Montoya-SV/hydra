"""Shared test-support helper — deliberately NOT `conftest.py` (see
tests/_httpx_verification.py's docstring for why). `POST /accounts` now
requires a real, distinct email per account and leaves it unverified
until `POST /accounts/verify-email` confirms it (the account-abuse fix);
most existing tests' actual subject is something else entirely (scan
lifecycle, tiers, reportability, ...), so they create an account through
the real endpoint (exercising the real email-required/uniqueness
constraint) and then mark it verified directly via `ControlDB` —
the same "seed the precondition, exercise the real thing under test"
split `tests/_verified_domain.py` already established for Round 2.
The actual email-verification FLOW itself (token issuance, expiry,
resend) is exercised end-to-end in
tests/test_api_account_verification.py, never bypassed there.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


def unique_email() -> str:
    """A fresh, never-repeating address — `accounts.email` has a unique
    index, so any test creating more than one account within the same
    control_db needs distinct values, not a fixed literal."""
    return f"test-{secrets.token_hex(8)}@example.com"


def create_verified_account(client: TestClient, *, email: str | None = None) -> tuple[str, str]:
    """Returns (api_key, account_id) for a freshly created, already-
    email-verified account — via the real POST /accounts (so the
    email-required/uniqueness contract is still genuinely exercised),
    with verification itself short-circuited directly in the control DB
    rather than round-tripping through the console `EmailSender`."""
    response = client.post("/accounts", json={"email": email or unique_email()})
    body = response.json()
    account_id = body["account_id"]
    client.app.state.control_db.mark_email_verified(account_id)
    return body["api_key"], account_id
