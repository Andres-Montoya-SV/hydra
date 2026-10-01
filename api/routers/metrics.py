"""`GET /metrics` (Productization Phase 11d): Prometheus text format, for
operators only (an operator account's API key; everyone else 404).

Scrapes are not written to the security audit log: a scraper calls every
15 seconds or so, and the response holds aggregates only (api/metrics.py).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from api.auth import AuthContext, require_operator

router = APIRouter(tags=["metrics"])


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request, operator: AuthContext = Depends(require_operator)) -> Response:
    del operator  # the dependency is the access check
    return Response(
        generate_latest(request.app.state.metrics.registry), media_type=CONTENT_TYPE_LATEST
    )
