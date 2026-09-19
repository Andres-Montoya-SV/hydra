"""`GET`/`POST /account/subscription`, `POST /webhooks/wompi`, and the
manual-reconciliation admin endpoints (docs/PAID_API_DESIGN.md Part B/D,
Round 3).

**`POST /webhooks/wompi` is deliberately NOT behind `require_api_key`**
— Wompi has no Hydra API key, and never will; trusting a request here
means trusting the `wompi_hash` HMAC signature (Part D.2), never an
`X-API-Key` header, and never anything the client's own browser/frontend
claims about its payment flow. This is the one route in the whole
service that authenticates a caller by something other than
`api/auth.py::require_api_key` — worth calling out explicitly rather
than looking like a missed dependency.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.schemas import (
    CreateSubscriptionRequest,
    CreateSubscriptionResponse,
    SubscriptionResponse,
    WompiReconcileRequest,
    WompiReconcileResponse,
)
from api.settings import APISettings
from api.tiers import retention_days_for
from api.wompi_client import WompiClient, tier_for_product_name, verify_webhook_signature

router = APIRouter(tags=["subscription"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _wompi_client(request: Request) -> WompiClient:
    return request.app.state.wompi_client  # type: ignore[no-any-return]


@router.get("/account/subscription", response_model=SubscriptionResponse)
def get_subscription(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> SubscriptionResponse:
    control_db = _control_db(request)
    subscription = subscriptions.get_or_create_subscription(control_db, auth.account_id)
    limits = subscriptions.effective_limits(subscription)
    usage = control_db.get_monthly_usage(auth.account_id, subscriptions.current_period_key())
    verified_count = len(control_db.get_verified_domains_for_account(auth.account_id))

    return SubscriptionResponse(
        tier=subscription.tier,  # type: ignore[arg-type]
        status=subscription.status,  # type: ignore[arg-type]
        scans_used_this_period=usage.scans_used,
        scans_limit=limits.scans_per_month,
        verified_domains_count=verified_count,
        verified_domains_limit=limits.max_concurrent_verified_domains,
        grace_period_started_at=subscription.grace_period_started_at,
        retention_days=retention_days_for(
            limits, retention_days_override=subscription.retention_days_override
        ),
    )


@router.post("/account/subscription", response_model=CreateSubscriptionResponse)
def create_or_change_subscription(
    body: CreateSubscriptionRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CreateSubscriptionResponse:
    control_db = _control_db(request)
    subscriptions.get_or_create_subscription(control_db, auth.account_id)

    if body.tier == "free":
        # No payment involved — Part D.1's "Starter is $0 and needs no
        # Wompi link at all" reasoning, reused verbatim for this round's
        # Free tier. Applies immediately (module docstring point 2).
        result = subscriptions.apply_tier_change(control_db, auth.account_id, "free")
        return CreateSubscriptionResponse(
            tier="free",
            status="active",
            payment_url=None,
            previous_tier=result.previous_tier,
            exceeds_domain_limit=result.exceeds_domain_limit,
            exceeds_scan_limit=result.exceeds_scan_limit,
        )

    if not body.billing_email:
        raise HTTPException(
            status_code=422,
            detail="billing_email is required to upgrade to a paid tier — it's how the "
            "resulting Wompi payment webhook gets matched back to this account.",
        )

    api_settings = _api_settings(request)
    link_by_tier = {
        "medium": api_settings.wompi_link_url_medium,
        "pro": api_settings.wompi_link_url_pro,
        "ultra": api_settings.wompi_link_url_ultra,
    }
    payment_url = link_by_tier[body.tier]
    if not payment_url:
        raise HTTPException(
            status_code=503,
            detail=f"The {body.tier!r} tier's Wompi payment link is not configured on this "
            "deployment yet.",
        )

    control_db.create_pending_enrollment(
        account_id=auth.account_id, tier=body.tier, billing_email=body.billing_email
    )
    current = subscriptions.get_or_create_subscription(control_db, auth.account_id)
    return CreateSubscriptionResponse(
        tier=current.tier,  # type: ignore[arg-type]
        status=current.status,  # type: ignore[arg-type]
        payment_url=payment_url,
    )


# --- Wompi webhook -------------------------------------------------------

_SUCCESS_RESULT = "ExitosaAprobada"


@router.post("/webhooks/wompi", status_code=200)
async def wompi_webhook(
    request: Request,
    wompi_hash: str | None = Header(default=None, alias="wompi_hash"),
) -> dict[str, str]:
    control_db = _control_db(request)
    api_settings = _api_settings(request)
    wompi_client = _wompi_client(request)

    raw_body = await request.body()

    if not api_settings.wompi_client_secret:
        raise HTTPException(status_code=503, detail="Webhook verification is not configured.")
    if not verify_webhook_signature(raw_body, wompi_hash, api_settings.wompi_client_secret):
        # Never persisted to wompi_webhook_events — that table's
        # dedup/audit guarantee only makes sense for requests already
        # confirmed to genuinely be from Wompi (module docstring).
        raise HTTPException(status_code=401, detail="Invalid or missing webhook signature.")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Malformed webhook body.") from exc

    transaction_id = str(payload.get("IdTransaccion", ""))
    if not transaction_id:
        raise HTTPException(status_code=400, detail="Missing IdTransaccion.")

    if control_db.webhook_event_already_processed(transaction_id):
        # Wompi's own retry behavior (or a replay) — already handled,
        # tell it so without doing anything a second time.
        return {"status": "already_processed"}

    # Part D.2's belt-and-suspenders second check: independently confirm
    # via the API itself, never act on the webhook body alone even once
    # its signature verifies.
    try:
        transaction = await wompi_client.get_transaction(transaction_id)
    except Exception as exc:  # noqa: BLE001 - any Wompi-side failure is treated the same: don't act
        raise HTTPException(
            status_code=502, detail=f"Could not independently confirm this transaction: {exc}"
        ) from exc
    if not transaction.get("esAprobada"):
        control_db.record_webhook_event(
            transaction_id=transaction_id,
            outcome="rejected_transaction_check_failed",
            matched_account_id=None,
            raw_body=raw_body.decode("utf-8", errors="replace"),
        )
        raise HTTPException(
            status_code=400,
            detail="The webhook's own signature verified, but the independent "
            "TransaccionCompra lookup does not confirm approval — refusing to act on it.",
        )

    result = payload.get("ResultadoTransaccion")
    email = (payload.get("cliente") or {}).get("Email")
    product_name = (payload.get("EnlacePago") or {}).get("NombreProducto")
    amount = payload.get("Monto")
    tier = tier_for_product_name(product_name)

    if result != _SUCCESS_RESULT:
        # A reported FAILURE on a RECURRING charge for an existing paid
        # subscriber (Part D.3) — correlate by the billing_email already
        # on file from this account's original activation (the ephemeral
        # `wompi_pending_enrollments` row from signup time has long since
        # been consumed and isn't queried again here).
        account_id = control_db.find_account_id_by_billing_email(email) if email else None
        if account_id is not None:
            subscriptions.start_grace_period(control_db, account_id)
            control_db.record_webhook_event(
                transaction_id=transaction_id,
                outcome="payment_failure_grace_started",
                matched_account_id=account_id,
                raw_body=raw_body.decode("utf-8", errors="replace"),
            )
            return {"status": "grace_period_started"}
        control_db.record_webhook_event(
            transaction_id=transaction_id,
            outcome="payment_failure_unmatched",
            matched_account_id=None,
            raw_body=raw_body.decode("utf-8", errors="replace"),
        )
        return {"status": "unmatched_failure_logged"}

    # A reported SUCCESS. First try the NEW-enrollment path (pending
    # enrollment matched by email+tier); if that's empty, this might be a
    # recurring charge succeeding for an ALREADY-active subscriber
    # (clears any grace period, per D.3's "resolve the past-due state").
    enrollment = (
        control_db.find_pending_enrollment_by_email(email, tier=tier) if email and tier else None
    )
    if enrollment is not None:
        control_db.mark_enrollment_matched(enrollment.enrollment_id)
        control_db.set_tier(
            enrollment.account_id, enrollment.tier, status="active", billing_email=email
        )
        control_db.record_webhook_event(
            transaction_id=transaction_id,
            outcome="activated",
            matched_account_id=enrollment.account_id,
            raw_body=raw_body.decode("utf-8", errors="replace"),
        )
        return {"status": "activated"}

    existing_account_id = control_db.find_account_id_by_billing_email(email) if email else None
    if existing_account_id is not None:
        subscriptions.restore_active_status(control_db, existing_account_id)
        control_db.record_webhook_event(
            transaction_id=transaction_id,
            outcome="renewal_confirmed",
            matched_account_id=existing_account_id,
            raw_body=raw_body.decode("utf-8", errors="replace"),
        )
        return {"status": "renewal_confirmed"}

    # Genuinely unmatchable — the manual-reconciliation backstop, never
    # discarded and never guessed (task's own explicit requirement).
    control_db.create_unmatched_payment(
        transaction_id=transaction_id,
        payer_email=email,
        product_name=product_name,
        amount=amount,
        raw_body=raw_body.decode("utf-8", errors="replace"),
    )
    control_db.record_webhook_event(
        transaction_id=transaction_id,
        outcome="unmatched",
        matched_account_id=None,
        raw_body=raw_body.decode("utf-8", errors="replace"),
    )
    return {"status": "unmatched_pending_manual_reconciliation"}


# --- Manual reconciliation (admin) ---------------------------------------


def _require_admin(request: Request, x_admin_token: str | None = Header(default=None)) -> None:
    api_settings = _api_settings(request)
    if not api_settings.admin_token or x_admin_token != api_settings.admin_token:
        raise HTTPException(status_code=401, detail="Missing or invalid admin token.")


@router.get("/admin/wompi/unmatched", dependencies=[Depends(_require_admin)])
def list_unmatched_payments(request: Request) -> list[dict]:
    return _control_db(request).get_unresolved_payments()


@router.post(
    "/admin/wompi/reconcile",
    response_model=WompiReconcileResponse,
    dependencies=[Depends(_require_admin)],
)
def reconcile_unmatched_payment(
    body: WompiReconcileRequest, request: Request
) -> WompiReconcileResponse:
    control_db = _control_db(request)
    if not control_db.account_exists(body.account_id):
        raise HTTPException(status_code=404, detail="account_id not found.")
    resolved = control_db.resolve_unmatched_payment(body.unmatched_id, account_id=body.account_id)
    if not resolved:
        raise HTTPException(status_code=404, detail="unmatched_id not found or already resolved.")
    subscriptions.apply_tier_change(control_db, body.account_id, body.tier)
    return WompiReconcileResponse(
        unmatched_id=body.unmatched_id,
        account_id=body.account_id,
        tier=body.tier,
        status="resolved",
    )
