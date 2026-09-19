"""FastAPI application factory. A separate, independently-deployable
service — never imported by `app.py`, and imports only the module-level
functions it needs from `app.py` (deferred, inside
`api/scan_orchestrator.py`), never the reverse. Run locally with:

    uvicorn api.main:app --reload

(see docs/PAID_API_DESIGN.md's "Round 1 implemented" section for the
full local-run walkthrough, including how to create a test account).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.control_db import ControlDB
from api.rate_limit import TokenBucketLimiter
from api.routers import accounts, domains, keys, scans
from api.settings import APISettings, load_api_settings


def create_app(api_settings: APISettings | None = None) -> FastAPI:
    settings = api_settings or load_api_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.api_settings = settings
        app.state.control_db = ControlDB(settings.control_db_path)
        app.state.rate_limiter = TokenBucketLimiter(
            requests_per_minute=settings.rate_limit_per_minute
        )
        app.state.background_tasks = set()
        yield
        # Round 1 has no durable job queue (see scan_orchestrator's module
        # docstring) — in-flight background scan tasks are simply
        # abandoned on shutdown, same as a hard process kill would do.

    app = FastAPI(
        title="Hydra EASM API",
        description=(
            "Round 2: domain-ownership verification (DNS TXT or well-known "
            "file) now gates every scan — Round 1's multi-tenant core, "
            "X-API-Key auth, and async scan lifecycle underneath. Tiers/quotas "
            "and Wompi billing still not implemented — see docs/PAID_API_DESIGN.md."
        ),
        lifespan=lifespan,
    )
    app.include_router(accounts.router)
    app.include_router(keys.router)
    app.include_router(domains.router)
    app.include_router(scans.router)
    return app


app = create_app()
