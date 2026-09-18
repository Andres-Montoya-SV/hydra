"""The `X-API-Key` authentication dependency — every route that touches
account-scoped data depends on `require_api_key`, never on trusting a
header value directly. Declared as a plain `def` (not `async def`) so
FastAPI runs it in its threadpool automatically, since the underlying
SQLite lookups are blocking calls (see `api/control_db.py`).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

from api.control_db import ControlDB
from api.rate_limit import RateLimitExceededError, TokenBucketLimiter
from api.security import is_currently_valid, lookup_hash_for, verify_key


@dataclass(frozen=True)
class AuthContext:
    account_id: str
    key_id: str


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _rate_limiter(request: Request) -> TokenBucketLimiter:
    return request.app.state.rate_limiter  # type: ignore[no-any-return]


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthContext:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    control_db = _control_db(request)
    found = control_db.find_key_by_lookup_hash(lookup_hash_for(x_api_key))
    if found is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    record, verify_hash = found

    if not verify_key(x_api_key, verify_hash):
        # Extremely unlikely (would mean a lookup_hash collision), but
        # the actual authentication decision is always the Argon2id
        # match, never the fast lookup alone.
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not is_currently_valid(record):
        raise HTTPException(status_code=401, detail="API key revoked or expired")

    try:
        _rate_limiter(request).check(record.key_id)
    except RateLimitExceededError as exc:
        raise HTTPException(status_code=429, detail="Rate limit exceeded") from exc

    control_db.touch_key_last_used(record.key_id)
    return AuthContext(account_id=record.account_id, key_id=record.key_id)
