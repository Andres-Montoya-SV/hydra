"""Shared pieces of the ticketing providers: the provider interface, the
request shape, errors, and small formatting helpers."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse


class TicketingConfigError(ValueError):
    """Invalid provider configuration or credential shape."""


class RateLimitedError(ValueError):
    """The provider asked us to slow down (HTTP 429)."""

    def __init__(self, retry_after: int | None) -> None:
        super().__init__("HTTP 429 (rate limited)")
        self.retry_after = retry_after


@dataclass(frozen=True)
class TicketRequest:
    url: str
    headers: dict[str, str]
    body: bytes


class Provider(Protocol):
    """What each provider module (jira, linear, servicenow) implements."""

    REQUIRED_CONFIG: tuple[str, ...]
    REQUIRED_CREDENTIAL: tuple[str, ...]

    def normalize(self, config: dict[str, str]) -> dict[str, str]: ...

    def build(
        self,
        config: dict[str, str],
        credential: dict[str, str],
        event_type: str,
        data: dict[str, object],
    ) -> TicketRequest: ...

    def parse(self, config: dict[str, str], payload: dict[str, object]) -> tuple[str, str]: ...


def https_base(url: str, field: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise TicketingConfigError(f"{field} must be an https:// base URL")
    return f"https://{parsed.netloc}{parsed.path.rstrip('/')}"


def title(data: dict[str, object]) -> str:
    return f"[Hydra] {data.get('title') or 'Exposure'} ({data.get('severity', 'unknown')})"


def text(event_type: str, data: dict[str, object]) -> str:
    return "\n".join(
        [
            f"Hydra {event_type.replace('exposure.', 'exposure ')}.",
            f"Severity: {data.get('severity', 'unknown')}",
            f"Exposure: {data.get('exposure_id', '')}",
            f"Asset: {data.get('asset_id', '')}",
        ]
    )


def basic_auth(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def require(value: object, what: str) -> str:
    if not value:
        raise ValueError(f"response has no {what}")
    return str(value)
