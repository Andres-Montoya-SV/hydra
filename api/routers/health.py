"""`GET /health` — deliberately NOT behind `require_api_key`, same
reasoning as `POST /webhooks/wompi`: an external uptime monitor cannot
authenticate, and there is no account-scoped data to protect here in
the first place. See `api/health.py` for what's actually checked and
why.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from api.control_db import ControlDB
from api.health import LoopHeartbeats, check_health
from api.settings import APISettings

router = APIRouter(tags=["health"])


@router.get("/health")
def health(request: Request) -> JSONResponse:
    control_db: ControlDB = request.app.state.control_db
    heartbeats: LoopHeartbeats = request.app.state.loop_heartbeats
    api_settings: APISettings = request.app.state.api_settings

    healthy, checks = check_health(
        control_db=control_db, heartbeats=heartbeats, api_settings=api_settings
    )
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "unhealthy", "checks": checks},
    )
