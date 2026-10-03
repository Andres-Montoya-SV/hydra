"""Shared test-support helper: lets `hydra_client` talk to an in-process
FastAPI `TestClient`, so the CLI is exercised against the real app with
no network. Only the socket is replaced; every request still goes through
the real routing, auth, edge middleware and error handlers."""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping

from fastapi.testclient import TestClient

from hydra_client.client import Response, Transport

BASE_URL = "http://127.0.0.1:8000"


def in_process_transport(client: TestClient) -> Transport:
    def send(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> Response:
        parts = urllib.parse.urlsplit(url)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        reply = client.request(method, target, headers=dict(headers), content=body)
        return Response(
            reply.status_code, {k.lower(): v for k, v in reply.headers.items()}, reply.content
        )

    return send
