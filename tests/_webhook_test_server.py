"""Shared test-support helper — deliberately NOT `conftest.py` (see
tests/_httpx_verification.py's docstring for why). A REAL local HTTPS
server standing in for a customer's own webhook receiver (their Slack/
Teams incoming webhook, their own automation endpoint) — the same "real
server as arbiter" pattern `tests/_fake_postmark_server.py`/
`tests/_fake_wompi_server.py` already established, extended to TLS
since `api/webhooks.py` only ever accepts `https://` destinations.

The certificate is generated fresh, once per test process, via a real
`openssl` subprocess call (not a new Python dependency — `cryptography`
is only an OPTIONAL transitive dependency of `sslyze`, never guaranteed
present in the plain `requirements-dev.txt` + `requirements-api.txt`
install CI's own `check` job actually runs) — self-signed, so
`api/webhooks.py::deliver_event`'s own `verify=False` test-only override
is what a test uses to talk to it, exactly the same "explicit override,
never used on a real code path" shape that parameter's own docstring
documents.
"""

from __future__ import annotations

import http.server
import json
import ssl
import subprocess  # noqa: S404 - a fixed, local `openssl` invocation, never untrusted input
import tempfile
import threading
from pathlib import Path
from typing import Any


class WebhookTestHandler(http.server.BaseHTTPRequestHandler):
    requests: list[dict[str, Any]] = []
    response_status = 200
    # Set to a positive number to make the handler sleep before
    # responding — used to exercise the client's own timeout.
    delay_seconds = 0.0

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        import time

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        WebhookTestHandler.requests.append(
            {
                "headers": dict(self.headers.items()),
                "raw_body": raw,
                "body": json.loads(raw.decode("utf-8")) if raw else None,
            }
        )
        self.send_response(self.response_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")


def reset_webhook_test_state(*, status: int = 200, delay_seconds: float = 0.0) -> None:
    WebhookTestHandler.requests = []
    WebhookTestHandler.response_status = status
    WebhookTestHandler.delay_seconds = delay_seconds


def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed argv, no shell, local openssl only
        [  # noqa: S607 - "openssl" resolved via PATH, a fixed local tool, not untrusted input
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )


def start_webhook_test_server() -> tuple[http.server.HTTPServer, int, threading.Thread, Path]:
    """Returns `(httpd, port, thread, tmp_dir)` — caller passes `tmp_dir`
    to `stop_webhook_test_server` for cleanup."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="hydra-webhook-test-"))
    cert_path = tmp_dir / "cert.pem"
    key_path = tmp_dir / "key.pem"
    _generate_self_signed_cert(cert_path, key_path)

    http.server.HTTPServer.allow_reuse_address = True
    httpd = http.server.HTTPServer(("127.0.0.1", 0), WebhookTestHandler)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread, tmp_dir


def stop_webhook_test_server(
    httpd: http.server.HTTPServer, thread: threading.Thread, tmp_dir: Path
) -> None:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
    import shutil

    shutil.rmtree(tmp_dir, ignore_errors=True)
