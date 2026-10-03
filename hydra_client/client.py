"""The HTTP side of the client: one request, the error shape, and retries.

- **Errors.** Every API error carries `error: {code, message, request_id,
  retryable}` (Phase 13a); it is raised as `ApiError` with those fields.
- **Retries** happen only when the server says the failure is
  `retryable` AND the request is safe to repeat: `GET`, `HEAD`, `PUT` and
  `DELETE` (docs/productization/13a_errors_and_diagnostics.md). A `POST`
  (e.g. a scan, which is created and counted per call) is never retried
  automatically. The wait is the server's `Retry-After`, capped, or an
  exponential backoff.
- **The key** is sent only in the `X-API-Key` header, and only to the
  configured base URL: redirects are never followed (a 3xx is an error),
  so the key can't be forwarded to another host.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

SAFE_TO_REPEAT = frozenset({"GET", "HEAD", "PUT", "DELETE"})
MAX_ATTEMPTS = 3
MAX_WAIT_SECONDS = 60.0
USER_AGENT = "hydra-client/1"


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]  # lower-case names
    body: bytes


Transport = Callable[[str, str, Mapping[str, str], bytes | None], Response]


class TransportError(Exception):
    """The API could not be reached at all."""


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        request_id: str | None,
        retryable: bool,
        retry_after: float | None,
    ) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.retryable = retryable
        self.retry_after = retry_after


def _http_only_opener() -> urllib.request.OpenerDirector:
    """HTTP and HTTPS handlers only: no `file:`, `ftp:` or `data:` URL can
    ever be opened (the base URL is also checked to be http(s))."""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.UnknownHandler(),  # any other scheme raises URLError
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def urllib_transport(timeout: float = 30.0) -> Transport:
    opener = _http_only_opener()

    def send(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> Response:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with opener.open(request, timeout=timeout) as reply:
                return Response(reply.status, _lower(reply.headers.items()), reply.read())
        except urllib.error.HTTPError as error:
            return Response(error.code, _lower(error.headers.items()), error.read())
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise TransportError(f"Could not reach {url}: {error}") from error

    return send


def _lower(items: Any) -> dict[str, str]:
    return {str(name).lower(): str(value) for name, value in items}


def validate_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"The API URL must be http(s)://host[:port], not {base_url!r}")
    return base_url.rstrip("/")


class HydraClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self.api_key = api_key
        self._transport = transport or urllib_transport()
        self._sleep = sleep

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """The decoded JSON response (None for an empty body), or ApiError."""
        method = method.upper()
        url = self._url(path, params)
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        attempt = 1
        while True:
            response = self._transport(method, url, headers, payload)
            if 200 <= response.status < 300:
                return json.loads(response.body) if response.body else None
            error = _api_error(response)
            if not (error.retryable and method in SAFE_TO_REPEAT and attempt < MAX_ATTEMPTS):
                raise error
            self._sleep(_wait(error, attempt))
            attempt += 1

    def sleep(self, seconds: float) -> None:
        self._sleep(seconds)

    def _url(self, path: str, params: Mapping[str, Any] | None) -> str:
        if not path.startswith("/"):
            raise ValueError(f"API paths start with '/', not {path!r}")
        query = {k: v for k, v in (params or {}).items() if v is not None}
        suffix = f"?{urllib.parse.urlencode(query)}" if query else ""
        return f"{self.base_url}{path}{suffix}"


def _wait(error: ApiError, attempt: int) -> float:
    if error.retry_after is not None:
        return min(error.retry_after, MAX_WAIT_SECONDS)
    return min(2.0**attempt, MAX_WAIT_SECONDS)


def _api_error(response: Response) -> ApiError:
    try:
        body = json.loads(response.body) if response.body else {}
    except ValueError:
        body = {}
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):  # not a Hydra API response (e.g. a proxy)
        error = {
            "code": f"http_{response.status}",
            "message": response.body[:200].decode("utf-8", "replace"),
        }
    retry_after = response.headers.get("retry-after")
    return ApiError(
        response.status,
        str(error.get("code", f"http_{response.status}")),
        str(error.get("message", "")),
        request_id=error.get("request_id") or response.headers.get("x-request-id"),
        retryable=bool(error.get("retryable", False)),
        retry_after=float(retry_after) if retry_after and retry_after.isdigit() else None,
    )
