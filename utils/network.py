"""Fail-closed helpers for proxied standard-library HTTP requests."""

from __future__ import annotations

import urllib.request
from typing import BinaryIO


def open_url(
    request: urllib.request.Request,
    *,
    timeout: int,
    proxy_url: str | None = None,
) -> BinaryIO:
    """Open a URL through an explicit proxy when one is configured."""
    if proxy_url:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        return opener.open(request, timeout=timeout)
    return urllib.request.urlopen(
        request, timeout=timeout
    )  # nosec B310  # HTTP(S) Request built by the caller
