"""Fail-closed helpers for proxied standard-library HTTP requests."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import BinaryIO

import certifi

CERTIFI_SSL_FAILURE_HINT = (
    "SSL verification failed even with certifi's CA bundle — this may indicate "
    "a genuine MITM/interception on your network, not a local Python configuration issue"
)


def default_ssl_context() -> ssl.SSLContext:
    """TLS context that always trusts certifi's CA bundle, not the OS store.

    Fresh macOS virtualenvs often have an empty/unusable default trust store,
    which surfaces as CERTIFICATE_VERIFY_FAILED against otherwise-valid public
    CAs (Google Trust Services, etc.). curl on the same machine can succeed
    because it uses a different bundle.
    """
    return ssl.create_default_context(cafile=certifi.where())


def _wrap_ssl_error(exc: BaseException) -> BaseException:
    text = str(exc)
    reason = getattr(exc, "reason", None)
    combined = f"{text} {reason or ''}"
    if (
        "CERTIFICATE_VERIFY_FAILED" not in combined
        and "certificate verify failed" not in combined.lower()
    ):
        return exc
    message = f"{exc}; {CERTIFI_SSL_FAILURE_HINT}"
    if isinstance(exc, urllib.error.URLError):
        return urllib.error.URLError(message)
    return ssl.SSLError(message)


def open_url(
    request: urllib.request.Request,
    *,
    timeout: int,
    proxy_url: str | None = None,
) -> BinaryIO:
    """Open a URL through an explicit proxy when one is configured.

    Always verifies TLS with certifi's CA bundle (see ``default_ssl_context``).
    """
    context = default_ssl_context()
    try:
        if proxy_url:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
                urllib.request.HTTPSHandler(context=context),
            )
            return opener.open(request, timeout=timeout)
        return urllib.request.urlopen(  # nosec B310  # HTTP(S) Request built by the caller
            request, timeout=timeout, context=context
        )
    except (ssl.SSLError, urllib.error.URLError) as exc:
        wrapped = _wrap_ssl_error(exc)
        if wrapped is not exc:
            raise wrapped from exc
        raise
