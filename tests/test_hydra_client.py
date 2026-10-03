"""Productization Phase 13c: the thin API-client CLI (`hydra_client`)."""

from __future__ import annotations

import io
import json
import os
import socket
import stat
import threading
import urllib.error
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from _client_transport import BASE_URL, in_process_transport
from _org_helpers import api_client, verified_owner

from hydra_client.cli import main
from hydra_client.client import (
    ApiError,
    HydraClient,
    Response,
    _http_only_opener,
    urllib_transport,
)


class _Scripted:
    """A transport that replays canned responses and records requests."""

    def __init__(self, *responses: Response) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        self.requests.append((method, url, dict(headers), body))
        return self.responses.pop(0)


def _error(status: int, code: str, *, retryable: bool, retry_after: str | None = None) -> Response:
    body = {
        "detail": "x",
        "error": {"code": code, "message": "m", "request_id": "rid", "retryable": retryable},
    }
    headers = {"retry-after": retry_after} if retry_after else {}
    return Response(status, headers, json.dumps(body).encode())


_OK = Response(200, {}, b'{"ok": true}')


def _run(
    argv: list[str], transport: Any, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        argv,
        transport=transport,
        stdout=out,
        stderr=err,
        env={"HYDRA_API_URL": BASE_URL, **(env or {})},
        sleep=lambda s: None,
    )
    return code, out.getvalue(), err.getvalue()


class TestRetries:
    def test_a_retryable_get_is_retried_after_retry_after(self) -> None:
        waits: list[float] = []
        transport = _Scripted(_error(429, "rate_limited", retryable=True, retry_after="7"), _OK)
        client = HydraClient(BASE_URL, "k", transport=transport, sleep=waits.append)
        assert client.request("GET", "/organizations") == {"ok": True}
        assert waits == [7.0] and len(transport.requests) == 2

    def test_a_post_is_never_retried(self) -> None:
        transport = _Scripted(_error(503, "unavailable", retryable=True, retry_after="1"))
        client = HydraClient(BASE_URL, "k", transport=transport, sleep=lambda s: None)
        with pytest.raises(ApiError) as caught:
            client.request("POST", "/scans", body={"domain": "example.com"})
        assert caught.value.code == "unavailable" and len(transport.requests) == 1

    def test_a_non_retryable_error_is_not_retried(self) -> None:
        transport = _Scripted(_error(404, "not_found", retryable=False))
        client = HydraClient(BASE_URL, "k", transport=transport, sleep=lambda s: None)
        with pytest.raises(ApiError):
            client.request("GET", "/scans/x")
        assert len(transport.requests) == 1

    def test_gives_up_after_three_attempts_and_caps_the_wait(self) -> None:
        waits: list[float] = []
        busy = _error(429, "rate_limited", retryable=True, retry_after="9999")
        transport = _Scripted(busy, busy, busy)
        client = HydraClient(BASE_URL, "k", transport=transport, sleep=waits.append)
        with pytest.raises(ApiError):
            client.request("GET", "/organizations")
        assert waits == [60.0, 60.0] and len(transport.requests) == 3

    def test_a_non_hydra_error_body_still_becomes_an_api_error(self) -> None:
        transport = _Scripted(Response(502, {}, b"<html>Bad gateway</html>"))
        client = HydraClient(BASE_URL, "k", transport=transport, sleep=lambda s: None)
        with pytest.raises(ApiError) as caught:
            client.request("POST", "/feedback", body={})
        assert caught.value.code == "http_502" and "Bad gateway" in caught.value.message


class TestRequests:
    def test_the_key_goes_only_in_the_header(self) -> None:
        transport = _Scripted(_OK)
        HydraClient(BASE_URL, "secret-key", transport=transport).request("GET", "/version")
        method, url, headers, _ = transport.requests[0]
        assert headers["X-API-Key"] == "secret-key" and "secret-key" not in url

    def test_a_user_value_stays_one_path_segment(self) -> None:
        transport = _Scripted(_OK)
        assert _run(["scan-status", "../admin/x?y=1"], transport)[0] == 0
        assert transport.requests[0][1] == f"{BASE_URL}/scans/..%2Fadmin%2Fx%3Fy%3D1"

    def test_only_http_urls(self) -> None:
        with pytest.raises(ValueError):
            HydraClient("file:///etc/passwd")
        code, _, err = _run(["version"], _Scripted(), env={"HYDRA_API_URL": "ftp://x"})
        assert code == 2 and "http(s)" in err

    def test_the_process_environment_is_read_at_call_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        err = io.StringIO()
        monkeypatch.setenv("HYDRA_API_URL", "ftp://from-the-environment")
        assert main(["version"], transport=_Scripted(), stderr=err) == 2
        assert "ftp://from-the-environment" in err.getvalue()

    def test_cleartext_to_a_remote_host_warns(self) -> None:
        _, _, err = _run(
            ["version"], _Scripted(_OK), env={"HYDRA_API_URL": "http://api.example.com"}
        )
        assert "unencrypted" in err
        _, _, err = _run(["version"], _Scripted(_OK))  # loopback: no warning
        assert err == ""

    @pytest.mark.parametrize(
        "argv", [["call", "GET", "/x", "--param", "novalue"], ["call", "POST", "/x", "--data", "{"]]
    )
    def test_bad_call_arguments_are_usage_errors(self, argv: list[str]) -> None:
        with pytest.raises(SystemExit) as caught:
            _run(argv, _Scripted())
        assert caught.value.code == 2

    def test_a_value_starting_with_a_dash_goes_after_double_dash(self) -> None:
        transport = _Scripted(_OK)
        assert _run(["feedback", "idea", "--", "-dash first"], transport)[0] == 0
        assert json.loads(transport.requests[0][3] or b"{}")["message"] == "-dash first"

    def test_unreachable_api(self) -> None:
        with socket.socket() as sock:  # a port nothing listens on
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        code, _, err = _run(
            ["version"],
            urllib_transport(timeout=2),
            env={"HYDRA_API_URL": f"http://127.0.0.1:{port}"},
        )
        assert code == 3 and "Could not reach" in err


class TestAgainstTheRealApp:
    def test_signup_saves_the_key_privately(self, tmp_path: Path) -> None:
        key_file = tmp_path / "key"
        with api_client(tmp_path) as client:
            transport = in_process_transport(client)
            code, out, _ = _run(
                ["signup", "cli@example.com", "--save-key", str(key_file)], transport
            )
            assert code == 0
            assert json.loads(out)["api_key"] == f"(saved to {key_file})"
            assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
            code, out, _ = _run(["--key-file", str(key_file), "diagnostics"], transport)
        assert code == 0 and json.loads(out)["email_verified"] is False

    def test_an_api_error_prints_its_code_and_request_id(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, _ = verified_owner(client)
            code, out, err = _run(
                ["scan", "not-verified.example"],
                in_process_transport(client),
                env={"HYDRA_API_KEY": headers["X-API-Key"]},
            )
        assert (code, out) == (1, "")
        assert err.startswith("error: domain_not_verified (HTTP 403):")
        assert "request id: " in err


class _Responder(BaseHTTPRequestHandler):
    """First request: 429 with Retry-After; then 200. A redirect target
    records whether the key followed it."""

    calls: list[dict[str, str]] = []

    def _get(self) -> None:
        _Responder.calls.append({"path": self.path, "key": self.headers.get("X-API-Key", "")})
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/stolen")
            self.end_headers()
            return
        first = len(_Responder.calls) == 1
        body = (
            b'{"detail": "slow down", "error": {"code": "rate_limited", "message": "m",'
            b' "request_id": "r", "retryable": true}}'
            if first
            else b'{"version": "1.0.0"}'
        )
        self.send_response(429 if first else 200)
        if first:
            self.send_header("Retry-After", "1")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


# http.server calls `do_GET`, a name the linter rightly dislikes elsewhere.
_Handler = type("_Handler", (_Responder,), {"do_GET": _Responder._get})


class TestTheRealTransport:
    @pytest.fixture
    def server(self) -> Any:
        _Responder.calls = []
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
        httpd.shutdown()

    def test_a_real_429_then_200_over_http(self, server: str) -> None:
        waits: list[float] = []
        client = HydraClient(server, "k", transport=urllib_transport(timeout=5), sleep=waits.append)
        assert client.request("GET", "/version") == {"version": "1.0.0"}
        assert waits == [1.0] and len(_Responder.calls) == 2

    def test_a_redirect_is_never_followed(self, server: str) -> None:
        client = HydraClient(server, "k", transport=urllib_transport(timeout=5))
        with pytest.raises(ApiError) as caught:
            client.request("GET", "/redirect")
        assert caught.value.status == 302
        assert [c["path"] for c in _Responder.calls] == ["/redirect"]  # the key went nowhere else

    def test_only_http_and_https_can_be_opened(self) -> None:
        with pytest.raises(urllib.error.URLError, match="unknown url type"):
            _http_only_opener().open("file:///etc/passwd")
