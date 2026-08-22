"""Tests for certifi-backed stdlib HTTPS helpers."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from unittest.mock import MagicMock

import certifi
import pytest

from utils.network import CERTIFI_SSL_FAILURE_HINT, default_ssl_context, open_url


def test_default_ssl_context_uses_certifi_cafile(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    real_create = ssl.create_default_context

    def spy_create(*args: object, **kwargs: object) -> ssl.SSLContext:
        seen["args"] = args
        seen["kwargs"] = kwargs
        return real_create(*args, **kwargs)

    monkeypatch.setattr("utils.network.ssl.create_default_context", spy_create)
    ctx = default_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert seen["kwargs"] == {"cafile": certifi.where()}
    assert seen["args"] == ()


def test_open_url_passes_certifi_context_to_urlopen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: never fall back to ssl.create_default_context() with no cafile."""
    seen: dict[str, object] = {}
    real_create = ssl.create_default_context

    def spy_create(*args: object, **kwargs: object) -> ssl.SSLContext:
        seen["create_kwargs"] = kwargs
        return real_create(*args, **kwargs)

    def fake_urlopen(
        request: urllib.request.Request, timeout: object = None, context: object = None
    ):
        seen["context"] = context
        seen["timeout"] = timeout
        response = MagicMock()
        response.read.return_value = b"ok"
        return response

    monkeypatch.setattr("utils.network.ssl.create_default_context", spy_create)
    monkeypatch.setattr("utils.network.urllib.request.urlopen", fake_urlopen)

    request = urllib.request.Request("https://api.osv.dev/v1/query")
    open_url(request, timeout=10, proxy_url=None)

    assert seen["create_kwargs"] == {"cafile": certifi.where()}
    assert isinstance(seen["context"], ssl.SSLContext)
    assert seen["timeout"] == 10


def test_open_url_proxy_installs_certifi_https_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    real_create = ssl.create_default_context

    def spy_create(*args: object, **kwargs: object) -> ssl.SSLContext:
        seen["create_kwargs"] = kwargs
        return real_create(*args, **kwargs)

    def fake_build_opener(*handlers: object) -> object:
        seen["handlers"] = handlers

        class _Opener:
            def open(self, request: object, timeout: object = None) -> MagicMock:
                response = MagicMock()
                response.read.return_value = b"ok"
                return response

        return _Opener()

    monkeypatch.setattr("utils.network.ssl.create_default_context", spy_create)
    monkeypatch.setattr("utils.network.urllib.request.build_opener", fake_build_opener)

    request = urllib.request.Request("https://crt.sh/")
    open_url(request, timeout=10, proxy_url="http://127.0.0.1:8080")

    assert seen["create_kwargs"] == {"cafile": certifi.where()}
    https_handlers = [
        h for h in seen["handlers"] if isinstance(h, urllib.request.HTTPSHandler)  # type: ignore[index]
    ]
    assert https_handlers
    assert https_handlers[0]._context.get_ca_certs()  # type: ignore[attr-defined]


def test_open_url_ssl_failure_explains_certifi_vs_mitm(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.URLError(
            ssl.SSLCertVerificationError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                "unable to get local issuer certificate"
            )
        )

    monkeypatch.setattr("utils.network.urllib.request.urlopen", boom)
    request = urllib.request.Request("https://api.osv.dev/v1/query")
    with pytest.raises(urllib.error.URLError) as caught:
        open_url(request, timeout=5, proxy_url=None)
    text = str(caught.value)
    assert "CERTIFICATE_VERIFY_FAILED" in text
    assert CERTIFI_SSL_FAILURE_HINT in text
