"""`POST /domains` / `POST /domains/{domain}/verify` —
docs/PAID_API_DESIGN.md Part A. The non-negotiable gate `POST /scans`
depends on (api/routers/scans.py) — no scan is ever queued for a domain
without a current, successful verification for the requesting account.

Both verification methods perform a real, active check
(api/domain_verification.py) every time `POST /domains/{domain}/verify`
is called — never a check against anything the client's request body
claims.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request

if TYPE_CHECKING:
    import dns.asyncresolver

from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.domain_verification import (
    DEFAULT_EXPIRY_DAYS,
    dns_record_name,
    dns_record_value,
    generate_token,
    normalize_domain,
    verify_dns_txt,
    verify_well_known_file,
    well_known_file_path,
)
from api.schemas import (
    DnsInstructions,
    FileInstructions,
    RegisterDomainRequest,
    RegisterDomainResponse,
    VerifyDomainRequest,
    VerifyDomainResponse,
)
from api.settings import APISettings

router = APIRouter(prefix="/domains", tags=["domains"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _dev_dns_resolver(settings: APISettings) -> dns.asyncresolver.Resolver | None:
    """None (real internet DNS) unless HYDRA_API_DEV_DNS_NAMESERVER is
    explicitly set — see api/settings.py's own comment; this is never
    the default, local-dev/demo only."""
    if not settings.dev_dns_nameserver:
        return None
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [settings.dev_dns_nameserver]
    if settings.dev_dns_port:
        resolver.port = settings.dev_dns_port
    return resolver


@router.post("", response_model=RegisterDomainResponse, status_code=201)
def register_domain(
    body: RegisterDomainRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> RegisterDomainResponse:
    domain = normalize_domain(body.domain)
    control_db = _control_db(request)
    record = control_db.create_domain_verification(
        account_id=auth.account_id, domain=domain, token=generate_token()
    )
    return RegisterDomainResponse(
        domain=domain,
        token=record.token,
        dns_instructions=DnsInstructions(
            name=dns_record_name(domain), value=dns_record_value(record.token)
        ),
        file_instructions=FileInstructions(
            path=well_known_file_path(record.token), content=record.token
        ),
    )


@router.post("/{domain}/verify", response_model=VerifyDomainResponse)
async def verify_domain(
    domain: str,
    body: VerifyDomainRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> VerifyDomainResponse:
    domain = normalize_domain(domain)
    control_db = _control_db(request)
    settings = _api_settings(request)

    pending = control_db.get_latest_pending_verification(auth.account_id, domain)
    if pending is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No pending verification for {domain!r} on this account. "
                f"POST /domains {{'domain': '{domain}'}} first to get a token."
            ),
        )

    if body.method == "dns_txt":
        success, detail = await verify_dns_txt(
            domain, pending.token, resolver=_dev_dns_resolver(settings)
        )
    else:
        success, detail = await verify_well_known_file(
            domain, pending.token, base_url=settings.dev_well_known_base_url
        )

    if not success:
        control_db.mark_verification_failed(
            pending.verification_id, method=body.method, error=detail
        )
        raise HTTPException(
            status_code=422,
            detail=f"Verification check failed: {detail}. The pending token is still valid — fix the record/file and try again.",
        )

    # Task 3.2: first successful verification wins. A conflicting,
    # currently-active verification by a DIFFERENT account blocks this
    # one even though the real DNS/HTTP check just succeeded — proving
    # control now does not retroactively undo someone else's earlier,
    # still-valid claim (see api/domain_verification.py's module
    # docstring for why this round chose "first wins" over "current
    # control wins").
    existing = control_db.get_active_verification_for_domain(domain)
    if existing is not None and existing.account_id != auth.account_id:
        control_db.mark_verification_failed(
            pending.verification_id,
            method=body.method,
            error="Domain already verified by a different account",
        )
        raise HTTPException(
            status_code=409,
            detail=(
                f"{domain!r} is already verified by another account. If you "
                "believe this is an error, contact support — the DNS/file "
                "proof you just provided was valid, but this domain was "
                "already claimed first."
            ),
        )

    subscription = subscriptions.get_or_create_subscription(control_db, auth.account_id)
    limits = subscriptions.effective_limits(subscription)
    ok, reason = subscriptions.check_verified_domain_limit(
        control_db, auth.account_id, limits, renewing_domain=domain
    )
    if not ok:
        control_db.mark_verification_failed(
            pending.verification_id, method=body.method, error=reason or "tier domain limit reached"
        )
        raise HTTPException(status_code=403, detail=reason)

    verified_at = datetime.now(timezone.utc)
    expires_at = verified_at + timedelta(days=DEFAULT_EXPIRY_DAYS)
    control_db.mark_verification_succeeded(
        pending.verification_id,
        method=body.method,
        verified_at=verified_at.isoformat(),
        expires_at=expires_at.isoformat(),
    )
    control_db.supersede_other_verifications(
        auth.account_id, domain, keep_verification_id=pending.verification_id
    )

    return VerifyDomainResponse(
        domain=domain,
        status="verified",
        method=body.method,
        verified_at=verified_at.isoformat(),
        expires_at=expires_at.isoformat(),
    )
