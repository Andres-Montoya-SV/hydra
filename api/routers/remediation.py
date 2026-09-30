"""Productization Phase 07: the remediation workflow over exposures.

DISCOVER and UNDERSTAND are the exposure, its evidence, risk and
explanation endpoints; this router adds PRIORITIZE (the worklist, soonest
due first), ASSIGN (assignee, due date, ticket link), REMEDIATE / VERIFY
(state transitions, with re-detection after a fix claim failing
verification automatically), accepted risk / false positive (reason
required, acceptance expires), comments, and all-or-nothing bulk changes.
CLOSE and REOPEN remain the exposure's own resolve / reopen endpoints: a
remediation decision never changes detection truth or evidence.

Any member can read; only an owner can change anything. Another
organization's ids are indistinguishable from missing ones (404).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from api.auth import AuthContext, require_api_key
from api.control_db import (
    ControlDB,
    ExposureRecord,
    RemediationNotFoundError,
    RemediationRecord,
)
from api.routers.org_access import control_db, require_member, require_owner
from api.schemas import (
    RemediationBulkRequest,
    RemediationCommentRequest,
    RemediationEventResponse,
    RemediationFieldsRequest,
    RemediationResponse,
    RemediationState,
    RemediationTransitionRequest,
    WorklistItemResponse,
)
from core.remediation import (
    EffectiveState,
    RemediationFacts,
    TransitionConflictError,
    effective_remediation,
)

router = APIRouter(prefix="/organizations", tags=["remediation"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _response(
    exposure: ExposureRecord, record: RemediationRecord, now: datetime
) -> RemediationResponse:
    effective = effective_remediation(
        RemediationFacts(
            stored_state=record.state,
            state_changed_at=record.state_changed_at,
            accepted_until=record.accepted_until,
            exposure_status=exposure.status,
            exposure_last_seen_at=exposure.last_seen_at,
            first_seen_at=exposure.first_seen_at,
            severity=exposure.severity,
            due_at=record.due_at,
        ),
        now=now,
    )
    return RemediationResponse(
        exposure_id=exposure.exposure_id,
        state=cast(EffectiveState, effective.state),
        stored_state=cast(RemediationState, record.state),
        derived_reason=effective.derived_reason,
        state_reason=record.state_reason,
        state_changed_at=record.state_changed_at,
        accepted_until=record.accepted_until,
        assignee_account_id=record.assignee_account_id,
        due_at=effective.due_at,
        sla_due_at=effective.sla_due_at,
        overdue=effective.overdue,
        ticket_url=record.ticket_url,
        updated_at=record.updated_at,
    )


def _exposure_or_404(db: ControlDB, organization_id: str, exposure_id: str) -> ExposureRecord:
    exposure = db.get_exposure_for_organization(organization_id, exposure_id)
    if exposure is None:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return exposure


def _current(db: ControlDB, organization_id: str, exposure_id: str) -> RemediationResponse:
    exposure = _exposure_or_404(db, organization_id, exposure_id)
    return _response(exposure, db.get_remediation(organization_id, exposure_id), _now())


def _field_changes(body: RemediationFieldsRequest) -> dict[str, str | None]:
    return {name: getattr(body, name) for name in body.model_fields_set}


def _apply(
    db: ControlDB,
    organization_id: str,
    exposure_ids: list[str],
    actor: str,
    *,
    transition: RemediationTransitionRequest | None = None,
    fields: RemediationFieldsRequest | None = None,
) -> None:
    """One write path for single and bulk changes, mapping domain errors
    to HTTP: foreign/missing -> 404, disallowed transition -> 409, bad
    input -> 422."""
    try:
        if transition is not None:
            db.transition_remediation(
                organization_id=organization_id,
                exposure_ids=exposure_ids,
                actor_account_id=actor,
                target=transition.to_state,
                reason=transition.reason,
                accepted_until=transition.accepted_until,
                now=_now(),
            )
        elif fields is not None:
            db.update_remediation_fields(
                organization_id=organization_id,
                exposure_ids=exposure_ids,
                actor_account_id=actor,
                changes=_field_changes(fields),
                now=_now(),
            )
    except RemediationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Exposure not found") from exc
    except TransitionConflictError as exc:
        raise HTTPException(
            status_code=409, detail={"error": "invalid_transition", "message": str(exc)}
        ) from exc
    except ValueError as exc:  # includes TransitionError: invalid input
        raise HTTPException(
            status_code=422, detail={"error": "invalid_remediation", "message": str(exc)}
        ) from exc


@router.get(
    "/{organization_id}/exposures/{exposure_id}/remediation",
    response_model=RemediationResponse,
)
def get_remediation(
    organization_id: str,
    exposure_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> RemediationResponse:
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    return _current(db, organization_id, exposure_id)


@router.post(
    "/{organization_id}/exposures/{exposure_id}/remediation/transition",
    response_model=RemediationResponse,
)
def transition_remediation(
    organization_id: str,
    exposure_id: str,
    body: RemediationTransitionRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> RemediationResponse:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    _apply(db, organization_id, [exposure_id], auth.account_id, transition=body)
    return _current(db, organization_id, exposure_id)


@router.patch(
    "/{organization_id}/exposures/{exposure_id}/remediation",
    response_model=RemediationResponse,
)
def update_remediation(
    organization_id: str,
    exposure_id: str,
    body: RemediationFieldsRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> RemediationResponse:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    _apply(db, organization_id, [exposure_id], auth.account_id, fields=body)
    return _current(db, organization_id, exposure_id)


@router.post("/{organization_id}/exposures/{exposure_id}/remediation/comments", status_code=201)
def add_comment(
    organization_id: str,
    exposure_id: str,
    body: RemediationCommentRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> Response:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    try:
        db.add_remediation_comment(
            organization_id=organization_id,
            exposure_id=exposure_id,
            actor_account_id=auth.account_id,
            body=body.body,
        )
    except RemediationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Exposure not found") from exc
    return Response(status_code=201)


@router.get(
    "/{organization_id}/exposures/{exposure_id}/remediation/events",
    response_model=list[RemediationEventResponse],
)
def list_events(
    organization_id: str,
    exposure_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[RemediationEventResponse]:
    """The append-only history: state changes, assignments, due dates,
    ticket links and comments, newest first."""
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    _exposure_or_404(db, organization_id, exposure_id)
    return [
        RemediationEventResponse.model_validate(event, from_attributes=True)
        for event in db.list_remediation_events(
            organization_id, exposure_id, limit=limit, offset=offset
        )
    ]


@router.get("/{organization_id}/remediation", response_model=list[WorklistItemResponse])
def worklist(
    organization_id: str,
    request: Request,
    state: str | None = Query(default=None, max_length=40),
    assignee_account_id: str | None = Query(default=None, max_length=64),
    overdue: bool | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[WorklistItemResponse]:
    """Exposures to work on, soonest due first, filtered on the effective
    remediation state (e.g. `state=triage&overdue=true`)."""
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    now = _now()
    rows = db.remediation_worklist(
        organization_id,
        now=now,
        state=state,
        assignee_account_id=assignee_account_id,
        overdue=overdue,
        limit=limit,
        offset=offset,
    )
    return [
        WorklistItemResponse(
            exposure_id=exposure.exposure_id,
            asset_id=exposure.asset_id,
            title=exposure.title,
            severity=exposure.severity,
            exposure_status=exposure.status,
            remediation=_response(exposure, record, now),
        )
        for exposure, record, _state in rows
    ]


@router.post("/{organization_id}/remediation/bulk", status_code=204)
def bulk_update(
    organization_id: str,
    body: RemediationBulkRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> Response:
    """One transition or one set of field changes across up to 100
    exposures, all or nothing: any foreign/missing id is 404 and any
    disallowed transition is 409, and then nothing was changed."""
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    _apply(
        db,
        organization_id,
        body.exposure_ids,
        auth.account_id,
        transition=body.transition,
        fields=body.fields,
    )
    return Response(status_code=204)
