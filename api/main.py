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
from api.routers import accounts, domains, hypotheses, keys, reportability, scans, subscription
from api.settings import APISettings, load_api_settings
from api.wompi_client import WompiClient


def create_app(api_settings: APISettings | None = None) -> FastAPI:
    settings = api_settings or load_api_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.api_settings = settings
        app.state.control_db = ControlDB(settings.control_db_path)
        app.state.rate_limiter = TokenBucketLimiter(
            requests_per_minute=settings.rate_limit_per_minute
        )
        app.state.wompi_client = WompiClient(
            client_id=settings.wompi_client_id,
            client_secret=settings.wompi_client_secret,
            id_base_url=settings.dev_wompi_id_base_url,
            api_base_url=settings.dev_wompi_api_base_url,
        )
        app.state.background_tasks = set()
        yield
        # Round 1 has no durable job queue (see scan_orchestrator's module
        # docstring) — in-flight background scan tasks are simply
        # abandoned on shutdown, same as a hard process kill would do.

    app = FastAPI(
        title="Hydra EASM API",
        description=(
            "Round 3: Free/Medium/Pro/Ultra tiers gate scan quotas, verified-"
            "domain counts, report formats/languages, and the assess-"
            "reportability/suggest-hypotheses LLM features; Wompi billing "
            "(OAuth client-credentials, webhook-signature-verified tier "
            "activation, payment-failure grace period) sits behind "
            "POST /account/subscription. Round 2's domain-ownership "
            "verification and Round 1's multi-tenant core/auth/async scans "
            "underneath — see docs/PAID_API_DESIGN.md."
        ),
        lifespan=lifespan,
    )
    app.include_router(accounts.router)
    app.include_router(keys.router)
    app.include_router(domains.router)
    app.include_router(scans.router)
    app.include_router(reportability.router)
    app.include_router(hypotheses.router)
    app.include_router(subscription.router)
    return app


app = create_app()
