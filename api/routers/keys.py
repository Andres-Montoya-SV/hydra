"""`POST /keys/{key_id}/rotate` / `POST /keys/{key_id}/revoke` —
docs/PAID_API_DESIGN.md Part C. Authenticated with any currently-valid
key on the account; the `key_id` acted on is checked against the
*authenticated* account, not against "is this the key used to sign this
request" — an account can rotate/revoke any of its own keys from any of
its other valid keys (e.g. use a dashboard-integration key to revoke a
leaked CI key), but never another account's key, ever.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.schemas import RotateKeyResponse
from api.security import generate_raw_key, hash_for_storage, lookup_hash_for
from api.settings import APISettings

router = APIRouter(prefix="/keys", tags=["keys"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


@router.post("/{key_id}/rotate", response_model=RotateKeyResponse)
def rotate_key(
    key_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> RotateKeyResponse:
    control_db = _control_db(request)
    old_key = control_db.get_key(key_id, auth.account_id)
    if old_key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    grace_hours = _api_settings(request).key_rotation_grace_hours
    old_key_valid_until = control_db.start_key_rotation_grace_period(
        key_id, auth.account_id, grace_hours=grace_hours
    )
    if old_key_valid_until is None:
        raise HTTPException(status_code=409, detail="API key is already revoked")

    new_raw_key, prefix = generate_raw_key()
    new_key_id = uuid.uuid4().hex
    control_db.insert_api_key(
        key_id=new_key_id,
        account_id=auth.account_id,
        lookup_hash=lookup_hash_for(new_raw_key),
        verify_hash=hash_for_storage(new_raw_key),
        prefix=prefix,
    )

    return RotateKeyResponse(
        old_key_id=key_id,
        old_key_valid_until=old_key_valid_until,
        new_key_id=new_key_id,
        new_api_key=new_raw_key,
    )


@router.post("/{key_id}/revoke", status_code=204)
def revoke_key(
    key_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> None:
    control_db = _control_db(request)
    revoked = control_db.revoke_key(key_id, auth.account_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
