"""`POST /accounts` — account + initial API key creation.

Round 1 scope, stated explicitly and not to be missed: this endpoint is
**unauthenticated on purpose**, because Round 1 has no billing (Part D)
or tier gate (Part B) to sit behind yet — there is nothing to protect it
with until Round 2/3 wire up Wompi. It exists so the core multi-tenant
plumbing (this round's actual subject) can be exercised end-to-end
without a manual database-seeding step. **This must be removed or gated
behind payment/tier logic before this service is exposed publicly** —
an open, free account-creation endpoint is fine for internal testing of
Round 1, never for production.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Request

from api.control_db import ControlDB
from api.schemas import CreateAccountResponse
from api.security import generate_raw_key, hash_for_storage, lookup_hash_for

router = APIRouter(prefix="/accounts", tags=["accounts"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


@router.post("", response_model=CreateAccountResponse, status_code=201)
def create_account(request: Request) -> CreateAccountResponse:
    control_db = _control_db(request)
    account_id = control_db.create_account()

    raw_key, prefix = generate_raw_key()
    key_id = uuid.uuid4().hex
    control_db.insert_api_key(
        key_id=key_id,
        account_id=account_id,
        lookup_hash=lookup_hash_for(raw_key),
        verify_hash=hash_for_storage(raw_key),
        prefix=prefix,
    )
    return CreateAccountResponse(account_id=account_id, api_key=raw_key, key_id=key_id)
