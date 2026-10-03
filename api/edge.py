"""Productization Phase 11a: what every HTTP request passes through before
any router — one pure-ASGI middleware (so streaming and context variables
behave) plus the optional CORS policy.

- **Request id.** Each request gets an id, which is set in a context variable
  for the request's log records (`RequestIdFilter`) and returned as
  `X-Request-ID`. A caller's own `X-Request-ID` is kept when it is a short
  token of safe characters, so ids can be followed across a proxy;
  anything else is replaced, so the id is never a log-injection vector.
- **No NUL characters (Phase 11g).** A NUL in the path, the query or the
  body (raw or JSON-escaped) is refused with 400: no legitimate request
  carries one, and PostgreSQL rejects it deep inside a query.
- **Body limit.** A request body larger than the limit is refused with 413
  before the router sees it — by `Content-Length` when declared, and by
  counting as it streams otherwise. The import endpoints get the importer's
  own larger limit.
- **Security headers.** They are set on every response, without
  overriding a header a route set itself:
  - `nosniff`;
  - no framing;
  - no referrer;
  - `Cache-Control: no-store` (responses carry tenant data);
  - a CSP that loads nothing (the docs pages need their CDN, so they're
    exempt);
  - HSTS when configured. Turn it on only once TLS terminates in front of
    the API.
- **CORS.** None unless HYDRA_API_CORS_ORIGINS lists origins; then exactly
  those, without credentials.
- **One error shape (Phase 13a).** Every error, from a router, request
  validation, an unhandled exception or this middleware itself, keeps
  its `detail` and gains the `error` object of `api/errors.py`.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from collections.abc import Awaitable, Callable, MutableMapping
from contextvars import ContextVar
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.errors import error_body
from api.settings import APISettings

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

REQUEST_ID_HEADER = "X-Request-ID"
_SAFE_INCOMING_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_IMPORT_PATH = re.compile(r"^/organizations/[^/]+/imports/[^/]+$")
_DOCS_PATHS = ("/docs", "/redoc")

_request_id: ContextVar[str] = ContextVar("hydra_request_id", default="-")

_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"cross-origin-resource-policy", b"same-origin"),
)
_STRICT_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")


def current_request_id() -> str:
    return _request_id.get()


class RequestIdFilter(logging.Filter):
    """Adds `request_id` to every log record ("-" outside a request)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get()
        return True


class _BodyTooLargeError(HTTPException):
    """An HTTPException, so FastAPI's own body parsing re-raises it as a 413
    instead of turning it into a generic 400."""

    def __init__(self, limit: int) -> None:
        super().__init__(status_code=413, detail=f"Request body exceeds {limit} bytes")


class _InternalError(HTTPException):
    """An unhandled exception: the details stay in the server log."""

    def __init__(self) -> None:
        super().__init__(status_code=500, detail="Internal Server Error")


class _NulCharacterError(HTTPException):
    """Phase 11g: no legitimate request carries a NUL character, and
    PostgreSQL refuses one in text (a 500 deep in a query, found by the
    adversarial re-test). Refused at the edge instead."""

    def __init__(self) -> None:
        super().__init__(status_code=400, detail="Request contains a NUL character")


# A raw NUL byte, or one escaped in JSON (`\u0000`, any case).
_BODY_NUL_MARKERS = (b"\x00", b"\\u0000")
# Bytes kept from the previous chunk, so a marker split across chunks is
# still found: one less than the longest marker.
_NUL_MARKER_OVERLAP = max(len(marker) for marker in _BODY_NUL_MARKERS) - 1


def _has_nul_in_target(scope: Scope) -> bool:
    # No case to fold: `%00` and NUL have none, and JSON accepts only a
    # lowercase `\u` escape.
    query = bytes(scope.get("query_string", b""))
    return "\x00" in scope.get("path", "") or b"%00" in query or b"\x00" in query


class _BodyGuard:
    """Wraps `receive`: refuses a body past `limit` bytes or one carrying a
    NUL, as it streams (a marker split across chunks is still found)."""

    def __init__(self, receive: Receive, limit: int, scan_nul: bool = True) -> None:
        self.receive = receive
        self.limit = limit
        self.scan_nul = scan_nul
        self.received = 0
        self.tail = b""

    async def __call__(self) -> Message:
        message = await self.receive()
        if message["type"] == "http.request":
            chunk = bytes(message.get("body", b""))
            self.received += len(chunk)
            if self.received > self.limit:
                raise _BodyTooLargeError(self.limit)
            if self.scan_nul:
                window = self.tail + chunk
                if any(marker in window for marker in _BODY_NUL_MARKERS):
                    raise _NulCharacterError
                self.tail = window[-_NUL_MARKER_OVERLAP:]
        return message


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return bytes(value).decode("latin-1")
    return None


def _request_id_for(scope: Scope) -> str:
    incoming = _header(scope, b"x-request-id")
    if incoming and _SAFE_INCOMING_ID.match(incoming):
        return incoming
    return secrets.token_hex(16)


class EdgeMiddleware:
    def __init__(
        self, app: ASGIApp, *, max_body_bytes: int, max_import_bytes: int, hsts_seconds: int
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_import_bytes = max_import_bytes
        hsts = f"max-age={hsts_seconds}; includeSubDomains".encode()
        self.hsts = (b"strict-transport-security", hsts) if hsts_seconds > 0 else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = _request_id_for(scope)
        token = _request_id.set(request_id)
        try:
            await self._handle(scope, receive, send, request_id)
        finally:
            _request_id.reset(token)

    def _limit_for(self, scope: Scope) -> int:
        if _IMPORT_PATH.match(scope.get("path", "")):
            return self.max_import_bytes
        return self.max_body_bytes

    async def _handle(self, scope: Scope, receive: Receive, send: Send, request_id: str) -> None:
        limit = self._limit_for(scope)
        declared = _header(scope, b"content-length")
        extra = self._response_headers(scope, request_id)
        if declared and declared.isdigit() and int(declared) > limit:
            await _send_error(send, _BodyTooLargeError(limit), extra)
            return
        if _has_nul_in_target(scope):
            await _send_error(send, _NulCharacterError(), extra)
            return
        started = False

        async def decorating_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                present = {bytes(key).lower() for key, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [
                    (key, value) for key, value in extra if key not in present
                ]
            await send(message)

        # Imports keep their own body checks (a compressed upload gets its
        # clearer 422; the importer refuses NUL itself).
        scan_body = not _IMPORT_PATH.match(scope.get("path", ""))
        try:
            await self.app(scope, _BodyGuard(receive, limit, scan_body), decorating_send)
        except (_BodyTooLargeError, _NulCharacterError) as refused:
            if started:
                raise
            await _send_error(send, refused, extra)
        except Exception:
            # Starlette answers an unhandled exception in its outermost
            # layer, outside this one: without this, a 500 carried no
            # request id and no security headers. Answer here, then
            # re-raise so the server still logs it (and Sentry sees it);
            # Starlette sends nothing more once a response has started.
            if not started:
                await _send_error(send, _InternalError(), extra)
            raise

    def _response_headers(self, scope: Scope, request_id: str) -> list[tuple[bytes, bytes]]:
        headers = [*_SECURITY_HEADERS, (b"x-request-id", request_id.encode())]
        if not scope.get("path", "").startswith(_DOCS_PATHS):
            headers.append(_STRICT_CSP)
        if self.hsts:
            headers.append(self.hsts)
        return headers


async def _send_error(send: Send, error: HTTPException, extra: list[tuple[bytes, bytes]]) -> None:
    body = json.dumps(
        jsonable_encoder(
            error_body(error.status_code, error.detail, request_id=current_request_id())
        )
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": error.status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                *extra,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _no_body(status_code: int) -> bool:
    return status_code < 200 or status_code in (204, 304)


async def _http_error(request: Request, exc: Exception) -> Response:
    status_code = getattr(exc, "status_code", 500)
    headers = getattr(exc, "headers", None)
    if _no_body(status_code):
        return Response(status_code=status_code, headers=headers)
    body = error_body(
        status_code,
        getattr(exc, "detail", None),
        request_id=current_request_id(),
        code=getattr(exc, "code", None),
        headers=headers,
    )
    return JSONResponse(body, status_code=status_code, headers=headers)


async def _validation_error(request: Request, exc: Exception) -> Response:
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    body = error_body(422, jsonable_encoder(errors), request_id=current_request_id())
    return JSONResponse(body, status_code=422)


def install_edge(app: FastAPI, settings: APISettings) -> None:
    """Registered last, so it is the outermost layer: CORS preflights and
    413s carry the request id and security headers too."""
    from api.nmap_masscan_import import MAX_ARTIFACT_BYTES

    if settings.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["X-API-Key", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
        )
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_middleware(
        EdgeMiddleware,
        max_body_bytes=settings.max_body_bytes,
        max_import_bytes=max(MAX_ARTIFACT_BYTES, settings.max_body_bytes),
        hsts_seconds=settings.hsts_seconds,
    )
