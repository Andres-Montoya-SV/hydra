"""Shared test-support helper — deliberately NOT `conftest.py` (see
tests/_httpx_verification.py's docstring for why). Round 1's scan/
client-report tests were written before Round 2's mandatory domain-
verification gate (api/routers/scans.py's `_require_verified_domain_or_
403`) existed; they are not testing verification itself, so rather than
spinning up a real DNS/HTTP server in every one of them, they seed an
already-verified row directly into the control DB — the exact same
persisted state `POST /domains/{domain}/verify` would have produced, via
the same `ControlDB` methods that endpoint uses. The verification
mechanism itself (real DNS/HTTP checks) is exercised end-to-end in
tests/test_api_domain_verification_endpoints.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from api.domain_verification import DEFAULT_EXPIRY_DAYS, normalize_domain

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


def seed_verified_domain(client: TestClient, account_id: str, domain: str) -> None:
    """Marks `domain` as currently, validly verified for `account_id` —
    bypassing the real DNS/HTTP check on purpose, for tests whose subject
    is something other than verification itself."""
    control_db = client.app.state.control_db  # type: ignore[attr-defined]
    record = control_db.create_domain_verification(
        account_id=account_id,
        domain=normalize_domain(domain),
        token="seeded-for-test",  # noqa: S106 - test fixture data, not a real secret
    )
    now = datetime.now(timezone.utc)
    control_db.mark_verification_succeeded(
        record.verification_id,
        method="dns_txt",
        verified_at=now.isoformat(),
        expires_at=(now + timedelta(days=DEFAULT_EXPIRY_DAYS)).isoformat(),
    )
