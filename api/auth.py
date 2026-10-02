"""The `X-API-Key` authentication dependency — every route that touches
account-scoped data depends on `require_api_key`, never on trusting a
header value directly. Declared as a plain `def` (not `async def`) so
FastAPI runs it in its threadpool automatically, since the underlying
SQLite lookups are blocking calls (see `api/control_db.py`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from fastapi import Depends, Header, HTTPException, Request

from api.control_db import ControlDB
from api.rate_limit import RateLimitExceededError, TokenBucketLimiter
from api.security import is_currently_valid, lookup_hash_for, verify_key
from api.security_audit import record_auth_failure
from api.subscriptions import access_blocked_by_billing


@dataclass(frozen=True)
class AuthContext:
    account_id: str
    key_id: str


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _rate_limiter(request: Request) -> TokenBucketLimiter:
    return request.app.state.rate_limiter  # type: ignore[no-any-return]


def _refuse(control_db: ControlDB, request: Request, reason: str, detail: str) -> NoReturn:
    """401, recorded in the security audit log (throttled; Phase 11b)."""
    record_auth_failure(control_db, request, reason)
    raise HTTPException(status_code=401, detail=detail)


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthContext:
    control_db = _control_db(request)
    if not x_api_key:
        _refuse(control_db, request, "missing", "Missing X-API-Key header")

    found = control_db.find_key_by_lookup_hash(lookup_hash_for(x_api_key))
    if found is None:
        _refuse(control_db, request, "invalid", "Invalid API key")
    record, verify_hash = found

    if not verify_key(x_api_key, verify_hash):
        # Extremely unlikely (would mean a lookup_hash collision), but
        # the actual authentication decision is always the Argon2id
        # match, never the fast lookup alone.
        _refuse(control_db, request, "invalid", "Invalid API key")

    if not is_currently_valid(record):
        _refuse(control_db, request, "revoked_or_expired", "API key revoked or expired")

    try:
        _rate_limiter(request).check(record.key_id)
    except RateLimitExceededError as exc:
        raise HTTPException(status_code=429, detail="Rate limit exceeded") from exc

    control_db.touch_key_last_used(record.key_id)
    _refuse_writes_while_suspended(control_db, request, record.account_id)
    return AuthContext(account_id=record.account_id, key_id=record.key_id)


_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# What a suspended account may still change (decision 2026-10-02): its
# keys, its billing, its own deletion (and its organizations'), plus the
# operator surface. Matched on route templates, never raw paths.
_ALLOWED_WHILE_SUSPENDED: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/keys/{key_id}/rotate"),
        ("POST", "/keys/{key_id}/revoke"),
        ("POST", "/account/subscription"),
        ("DELETE", "/account"),
        ("POST", "/account/deletion/cancel"),
        ("DELETE", "/organizations/{organization_id}"),
        ("POST", "/organizations/{organization_id}/deletion/cancel"),
    }
)


def _refuse_writes_while_suspended(
    control_db: ControlDB, request: Request, account_id: str
) -> None:
    """Productization Phase 12b: a billing-suspended account is read-only.
    Checked here, on every authenticated request, so no route can forget
    it; reads never pay for the lookup."""
    if request.method in _READ_METHODS:
        return
    template = getattr(request.scope.get("route"), "path", "")
    if (request.method, template) in _ALLOWED_WHILE_SUSPENDED or template.startswith("/admin/"):
        return
    subscription = control_db.get_subscription(account_id)
    if subscription is not None and access_blocked_by_billing(subscription):
        raise HTTPException(
            status_code=402,
            detail={
                "error": "account_suspended",
                "message": "This account is suspended for non-payment and is read-only. "
                "Resolve billing via POST /account/subscription to resume.",
            },
        )


_AUTHENTICATED = Depends(require_api_key)


def require_operator(request: Request, auth: AuthContext = _AUTHENTICATED) -> AuthContext:
    """Admin endpoints (Phase 11b): a valid API key whose account is an
    operator (granted from the host, `python -m api.operators`). Anyone
    else gets 404, so the admin surface is not discoverable."""
    if not _control_db(request).is_operator(auth.account_id):
        raise HTTPException(status_code=404, detail="Not Found")
    return auth
