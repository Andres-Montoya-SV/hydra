"""GET /organizations/{org}/explanations/{subject_type}/{subject_id}: why an
asset, exposure or relationship exists, in one shape for all three (see
`api/explanations.py`). Any member may read; a subject of another
organization is indistinguishable from a missing one (404)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth import AuthContext, require_api_key
from api.explanations import EXPLAINERS
from api.routers.org_access import control_db, require_member
from api.schemas import ExplanationResponse

router = APIRouter(prefix="/organizations", tags=["explanations"])


@router.get(
    "/{organization_id}/explanations/{subject_type}/{subject_id}",
    response_model=ExplanationResponse,
)
def get_explanation(
    organization_id: str,
    subject_type: Literal["asset", "exposure", "relationship"],
    subject_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ExplanationResponse:
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    explanation = EXPLAINERS[subject_type](db, organization_id, subject_id)
    if explanation is None:
        raise HTTPException(status_code=404, detail=f"{subject_type.capitalize()} not found")
    return ExplanationResponse(**asdict(explanation))
