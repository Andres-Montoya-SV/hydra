"""Productization Phase 13a: one error shape for every failure.

Every 4xx/5xx response keeps its `detail` exactly as before, so no
existing client breaks, and adds a top-level `error` object (decision
2026-10-02, "additive envelope"):

    {"detail": ..., "error": {"code": "email_not_verified",
                              "message": "...", "request_id": "...",
                              "retryable": false}}

- `code` is stable and machine-readable. It comes from, in order: an
  `ApiError`'s own code, the `error` key of a structured `detail`, or the
  HTTP status (`not_found`, `rate_limited`, ...).
- `message` is human-readable: a string `detail`, a structured detail's
  `message`, or a summary of a validation error.
- `request_id` matches the `X-Request-ID` header, for support.
- `retryable` says whether repeating the SAME request later can succeed
  without changing anything: 429, 502 and 504, and 503 only when it
  carries `Retry-After`. Today's 503s are missing configuration, which a
  retry won't fix. A 500 is a bug: report it with the request id.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any

from fastapi import HTTPException

STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthenticated",
    402: "payment_required",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    410: "gone",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_failed",
    429: "rate_limited",
    500: "internal_error",
    502: "upstream_failed",
    503: "unavailable",
    504: "upstream_timeout",
}
_ALWAYS_RETRYABLE = frozenset({429, 502, 504})


class ApiError(HTTPException):
    """An HTTPException with a specific, documented `code` for a failure a
    client should handle on its own (e.g. `email_not_verified`). `detail`
    is unchanged from what the endpoint always returned."""

    def __init__(
        self,
        status_code: int,
        detail: Any,
        *,
        code: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=dict(headers or {}))
        self.code = code


def code_for(status_code: int, detail: Any, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    if isinstance(detail, Mapping) and isinstance(detail.get("error"), str):
        return str(detail["error"])
    return STATUS_CODES.get(status_code, "client_error" if status_code < 500 else "server_error")


def message_for(status_code: int, detail: Any) -> str:
    if isinstance(detail, str) and detail:
        return detail
    if isinstance(detail, Mapping) and isinstance(detail.get("message"), str):
        return str(detail["message"])
    if isinstance(detail, Sequence) and detail and isinstance(detail[0], Mapping):
        return _validation_summary(detail)
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Error"


def _validation_summary(errors: Sequence[Any]) -> str:
    first = errors[0]
    where = ".".join(str(part) for part in first.get("loc", ()))
    more = f" (and {len(errors) - 1} more)" if len(errors) > 1 else ""
    return f"{where}: {first.get('msg', 'invalid')}{more}"


def is_retryable(status_code: int, headers: Mapping[str, str] | None) -> bool:
    if status_code in _ALWAYS_RETRYABLE:
        return True
    names = {name.lower() for name in (headers or {})}
    return status_code == 503 and "retry-after" in names


def error_body(
    status_code: int,
    detail: Any,
    *,
    request_id: str,
    code: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "detail": detail,
        "error": {
            "code": code_for(status_code, detail, code),
            "message": message_for(status_code, detail),
            "request_id": request_id,
            "retryable": is_retryable(status_code, headers),
        },
    }
