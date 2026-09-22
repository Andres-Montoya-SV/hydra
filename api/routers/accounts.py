"""`POST /accounts` / `POST /accounts/verify-email` /
`POST /accounts/resend-verification` — account + initial API key
creation, and the email-verification flow that gates real usage of it.

Round 1 scope, stated explicitly and not to be missed: `POST /accounts`
is **unauthenticated on purpose** — there is no tier or billing gate to
sit behind yet, and it exists so the core multi-tenant plumbing can be
exercised end-to-end without a manual database-seeding step.

**Hallazgo 1 (frontend-team review) closed here**: an unauthenticated,
unlimited account-creation endpoint combined with Free's 1-scan/month
quota let anyone create a fresh account per exhausted quota and scan for
free indefinitely. Two independent, complementary defenses, neither of
which blocks a real user creating their one real account:

1. **Per-source-IP rate limit** (`_require_account_creation_not_rate_
   limited`) — a low ceiling on how many accounts one IP can create in a
   rolling 24h window, stopping bulk/scripted creation outright.
2. **Email verification before the account is usable** — `POST
   /accounts` still returns a working `api_key` immediately (so the
   multi-tenant plumbing keeps working exactly as before for anyone who
   completes verification), but `POST /scans`
   (`api/routers/scans.py::_require_billing_and_quota_ok`) refuses to
   run anything until `POST /accounts/verify-email` confirms the token
   sent to that address — raising the cost of EACH abusive account
   individually (a real, distinct, receivable email per account), not
   just the rate of creating them.

This still must be removed/hardened further (a real admin auth system,
a real email provider — see `api/email_sender.py`) before this service
is exposed publicly outside of trusted testing, same honest caveat
Round 1 already carried.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, DuplicateEmailError
from api.email_sender import EmailSender
from api.schemas import (
    CreateAccountRequest,
    CreateAccountResponse,
    ResendVerificationResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from api.security import generate_raw_key, hash_for_storage, lookup_hash_for
from api.settings import APISettings

router = APIRouter(prefix="/accounts", tags=["accounts"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _email_sender(request: Request) -> EmailSender:
    return request.app.state.email_sender  # type: ignore[no-any-return]


def _client_ip(request: Request) -> str:
    # Direct TCP peer address — this service is not yet documented as
    # deployed behind a reverse proxy/load balancer; if it is, trusting
    # `X-Forwarded-For` blindly would let a client spoof its own rate
    # limit, so that header is deliberately NOT read here. Revisit if a
    # real reverse-proxy deployment is confirmed, trusting only a
    # specifically-configured trusted-proxy hop, not any client-supplied
    # header verbatim.
    return request.client.host if request.client is not None else "unknown"


def _require_account_creation_not_rate_limited(request: Request) -> None:
    control_db = _control_db(request)
    api_settings = _api_settings(request)
    ip = _client_ip(request)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    recent = control_db.count_recent_account_creations_from_ip(ip, since=since)
    if recent >= api_settings.account_creation_rate_limit_per_ip_per_day:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Too many accounts created from this network recently "
                f"(limit: {api_settings.account_creation_rate_limit_per_ip_per_day} per "
                "24 hours). Try again later."
            ),
        )


def _new_verification_token() -> str:
    return secrets.token_urlsafe(32)


@router.post(
    "",
    response_model=CreateAccountResponse,
    status_code=201,
    dependencies=[Depends(_require_account_creation_not_rate_limited)],
)
def create_account(body: CreateAccountRequest, request: Request) -> CreateAccountResponse:
    control_db = _control_db(request)
    api_settings = _api_settings(request)
    ip = _client_ip(request)

    # Recorded BEFORE the creation attempt itself (including one that
    # fails on a duplicate email) — otherwise probing for already-
    # registered emails would never count against the rate limit.
    control_db.record_account_creation_attempt(ip)

    token = _new_verification_token()
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=api_settings.email_verification_token_ttl_hours)
    ).isoformat()
    try:
        account_id = control_db.create_account(
            email=body.email,
            email_verification_token=token,
            email_verification_token_expires_at=expires_at,
        )
    except DuplicateEmailError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    control_db.create_default_subscription(account_id, tier="free")

    raw_key, prefix = generate_raw_key()
    key_id = uuid.uuid4().hex
    control_db.insert_api_key(
        key_id=key_id,
        account_id=account_id,
        lookup_hash=lookup_hash_for(raw_key),
        verify_hash=hash_for_storage(raw_key),
        prefix=prefix,
    )

    _email_sender(request).send_verification_email(
        to=body.email, account_id=account_id, token=token
    )

    return CreateAccountResponse(account_id=account_id, api_key=raw_key, key_id=key_id)


@router.post("/verify-email", response_model=VerifyEmailResponse)
def verify_email(body: VerifyEmailRequest, request: Request) -> VerifyEmailResponse:
    control_db = _control_db(request)
    account = control_db.get_account_by_verification_token(body.token)
    if account is None:
        raise HTTPException(status_code=404, detail="Invalid or already-used verification token.")
    if account.email_verification_token_expires_at is not None:
        expires_at = datetime.fromisoformat(account.email_verification_token_expires_at)
        if datetime.now(timezone.utc) >= expires_at:
            raise HTTPException(
                status_code=400,
                detail="This verification token has expired — "
                "POST /accounts/resend-verification for a new one.",
            )
    control_db.mark_email_verified(account.account_id)
    return VerifyEmailResponse(account_id=account.account_id, status="verified")


@router.post("/resend-verification", response_model=ResendVerificationResponse)
def resend_verification(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> ResendVerificationResponse:
    """Authenticated by the account's own (already-issued) api_key —
    an unverified account can still authenticate, it just can't scan yet
    (`api/auth.py::require_api_key` has no email-verification check of
    its own, by design: that gate is scoped to `POST /scans` only, per
    the task's own instructions). Regenerating always replaces the
    previous token outright, so an old, possibly-already-seen link never
    stays valid alongside a new one."""
    control_db = _control_db(request)
    api_settings = _api_settings(request)
    account = control_db.get_account(auth.account_id)
    if account is None or account.email is None:
        raise HTTPException(status_code=404, detail="Account has no email on file.")
    if account.is_email_verified:
        raise HTTPException(status_code=400, detail="This account's email is already verified.")

    token = _new_verification_token()
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=api_settings.email_verification_token_ttl_hours)
    ).isoformat()
    control_db.set_email_verification_token(account.account_id, token=token, expires_at=expires_at)
    _email_sender(request).send_verification_email(
        to=account.email, account_id=account.account_id, token=token
    )
    return ResendVerificationResponse(
        account_id=account.account_id, status="verification_email_resent"
    )
