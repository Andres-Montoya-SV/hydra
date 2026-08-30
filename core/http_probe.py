"""Shared urllib HTTP GET helper for active recon plugins.

Mirrors httpx's recon posture: TLS certificate verification is effectively
disabled so soft-404 / param-fuzz / bucket probes observe the same hosts that
were already marked alive. Supports an optional CONNECT proxy.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from core.response_diff import ResponseSnapshot

_DEFAULT_UA = "Mozilla/5.0 (compatible; HydraProbe/1.0)"
_MAX_BODY = 512_000


def insecure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_get(
    url: str,
    *,
    timeout: int,
    proxy_url: str | None = None,
    user_agent: str = _DEFAULT_UA,
    max_body: int = _MAX_BODY,
    extra_headers: dict[str, str] | None = None,
) -> ResponseSnapshot:
    """GET ``url`` and return status/body/error without raising.

    ``extra_headers`` (e.g. a program-mandated researcher attribution header —
    see ``Settings.merged_headers()``) is merged on top of the default
    ``User-Agent`` header. Never pass this for a fixed third-party endpoint
    (OSV.dev, crt.sh, WHOIS, URLhaus) — it identifies the caller to the
    *target*, which is meaningless (and unwanted noise) anywhere else.
    """
    headers = {"User-Agent": user_agent}
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(
        url,
        headers=headers,
        method="GET",
    )
    try:
        if proxy_url:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
                urllib.request.HTTPSHandler(context=insecure_ssl_context()),
            )
            response = opener.open(request, timeout=timeout)
        else:
            response = urllib.request.urlopen(  # nosec B310  # HTTP(S) recon GET; URL comes from httpx-alive hosts
                request, timeout=timeout, context=insecure_ssl_context()
            )
        with response:
            body = response.read(max_body)
            return ResponseSnapshot(
                status_code=int(getattr(response, "status", 200) or 200),
                body=body,
                error=None,
            )
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(max_body)
        except Exception:
            body = b""
        return ResponseSnapshot(status_code=int(exc.code), body=body, error=None)
    except Exception as exc:
        return ResponseSnapshot(status_code=None, body=b"", error=str(exc)[:240])
