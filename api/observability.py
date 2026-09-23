"""Basic observability, Parts 2 and 3 (docs/PAID_API_DESIGN.md's "Basic
observability" section): error tracking via Sentry, and an optional
JSON log formatter. See `api/health.py` for Part 1 (`GET /health`).

**Sentry — zero-config stays zero-config**: `SENTRY_DSN` unset means
`init_sentry` does nothing at all — no `sentry_sdk.init()` call, same
"absence is simply off, never a startup failure" discipline
`api/settings.py::validate_email_provider_config` already established
for Postmark. FastAPI/Starlette integration is auto-detected by
`sentry_sdk` itself once `fastapi` is importable (confirmed against
Sentry's own current FastAPI integration docs before writing this, not
assumed) — no separate integration class is passed here.

**Scrubbing, deliberate and tested, not the SDK's own defaults left
alone**: Sentry's SDK excludes some PII by default (confirmed against
Sentry's own docs: `send_default_pii` defaults to `False`, which
already excludes things like `Authorization`/cookie headers and IPs) —
this project never sets `send_default_pii=True`, keeping that default.
But `X-API-Key` is a custom header name, not one of Sentry's own
built-in denylist entries, so it is NOT safely covered by relying on
defaults alone — exactly the gap the task called out. Two independent
scrubbing passes run on every event before it would ever leave the
process, via `before_send`:

1. **Header-name scrubbing** — `X-API-Key`, `Authorization`, `Cookie`,
   and Wompi's `wompi_hash` signature header are stripped from
   `event["request"]["headers"]` unconditionally, regardless of what
   request happened to be in flight when an exception fired. This
   covers a header whose VALUE isn't known ahead of time (a real
   request's actual API key), which a value-based scrub can't catch.
2. **Known-static-secret value scrubbing** — `POSTMARK_SERVER_TOKEN`/
   `WOMPI_CLIENT_SECRET`'s actual configured values (known at process
   startup, unlike a per-request API key) are searched for and redacted
   ANYWHERE in the serialized event — exception messages, local
   variable reprs, extra context, not just headers — via a
   serialize-replace-deserialize sweep over the whole event structure.
   This is deliberately broad rather than trying to enumerate every
   possible place a secret could end up embedded.

Tested directly (`tests/test_observability_sentry_scrubbing.py`) by
intercepting the SDK's own `Transport.capture_envelope`, triggering a
REAL captured exception carrying a realistic fake secret in its
context, and asserting the value never appears anywhere in what the
transport actually received — not asserted from reading this code.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from api.settings import APISettings

_SENSITIVE_HEADER_NAMES = {"x-api-key", "authorization", "cookie", "wompi_hash"}
_REDACTED = "[Filtered]"


def _scrub_headers(headers: Any) -> Any:
    """Sentry's own `request.headers` shape varies by SDK version/
    integration — sometimes a dict, sometimes a list of `[name, value]`
    pairs. Handle both rather than assuming one."""
    if isinstance(headers, dict):
        return {
            key: (_REDACTED if key.lower() in _SENSITIVE_HEADER_NAMES else value)
            for key, value in headers.items()
        }
    if isinstance(headers, list):
        return [
            [
                key,
                (
                    _REDACTED
                    if isinstance(key, str) and key.lower() in _SENSITIVE_HEADER_NAMES
                    else value
                ),
            ]
            for key, value in headers
        ]
    return headers


def _scrub_known_secret_values(event: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
    if not secrets:
        return event
    # A blunt, deliberately broad instrument: serialize the WHOLE event,
    # replace every literal occurrence of a known secret anywhere in the
    # text, then deserialize — catches a secret embedded in an exception
    # message or a local variable's repr just as reliably as one sitting
    # in a header, without needing to enumerate every field shape Sentry
    # might use across SDK versions.
    text = json.dumps(event, default=str)
    for secret in secrets:
        text = text.replace(secret, _REDACTED)
    result: dict[str, Any] = json.loads(text)
    return result


def make_before_send(
    static_secrets: list[str],
):  # noqa: ANN201 - returns sentry_sdk's own before_send signature
    """Returns the actual `before_send` callable passed to
    `sentry_sdk.init()`. `static_secrets` should be every real,
    currently-configured secret value this process holds
    (`POSTMARK_SERVER_TOKEN`, `WOMPI_CLIENT_SECRET`, ...) — never
    logged, never stored beyond this closure."""
    secrets = [s for s in static_secrets if s]

    def before_send(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any]:
        request = event.get("request")
        if isinstance(request, dict) and "headers" in request:
            request["headers"] = _scrub_headers(request["headers"])
        return _scrub_known_secret_values(event, secrets)

    return before_send


def init_sentry(api_settings: APISettings) -> bool:
    """Returns whether Sentry was actually initialized (for the
    startup log line) — `False` and a complete no-op when
    `api_settings.sentry_dsn` is unset."""
    if not api_settings.sentry_dsn:
        return False

    import sentry_sdk

    static_secrets = [
        s for s in (api_settings.postmark_server_token, api_settings.wompi_client_secret) if s
    ]
    sentry_sdk.init(
        dsn=api_settings.sentry_dsn,
        before_send=make_before_send(static_secrets),
    )
    return True


class JsonFormatter(logging.Formatter):
    """A small, real feature — not a rewrite of every log call site.
    Only used when `HYDRA_API_LOG_FORMAT=json`; the human-readable
    default (`api/main.py`'s existing format string) is unchanged."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(log_format: str) -> None:
    """Replaces `api/main.py`'s old unconditional `logging.basicConfig`
    call — same "no-op if the root logger already has a handler" safety
    (a real deployment's own explicit logging config, set up before this
    module imports, always wins), but able to select `JsonFormatter`
    when `log_format == "json"`, which `logging.basicConfig`'s own
    `format=` parameter (a plain string, not a `Formatter` object)
    cannot do."""
    root = logging.getLogger()
    if root.handlers:
        return
    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.INFO)
