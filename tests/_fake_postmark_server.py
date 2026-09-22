"""Shared test-support helper — deliberately NOT `conftest.py` (see
tests/_httpx_verification.py's docstring for why). A real local HTTP
server standing in for `api.postmarkapp.com`
(`postmarkapp.com/developer/api/email-api`), the same "real server as
arbiter" pattern `tests/_fake_wompi_server.py` already established for
Wompi — used by tests/test_postmark_email_sender.py.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
from typing import Any


class FakePostmarkHandler(http.server.BaseHTTPRequestHandler):
    requests: list[dict[str, Any]] = []
    response_status = 200
    response_body: dict[str, Any] = {
        "To": "recipient@example.com",
        "SubmittedAt": "2026-01-01T00:00:00.000000-00:00",
        "MessageID": "fake-message-id",
        "ErrorCode": 0,
        "Message": "OK",
    }
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
        if self.path == "/email":
            FakePostmarkHandler.requests.append(
                {
                    "headers": dict(self.headers.items()),
                    "body": json.loads(raw.decode("utf-8")),
                }
            )
            payload = json.dumps(self.response_body).encode("utf-8")
            self.send_response(self.response_status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()


def reset_fake_postmark_state(
    *, status: int = 200, body: dict[str, Any] | None = None, delay_seconds: float = 0.0
) -> None:
    FakePostmarkHandler.requests = []
    FakePostmarkHandler.response_status = status
    FakePostmarkHandler.response_body = body or {
        "To": "recipient@example.com",
        "SubmittedAt": "2026-01-01T00:00:00.000000-00:00",
        "MessageID": "fake-message-id",
        "ErrorCode": 0,
        "Message": "OK",
    }
    FakePostmarkHandler.delay_seconds = delay_seconds


def start_fake_postmark_server() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), FakePostmarkHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


def stop_fake_postmark_server(httpd: socketserver.TCPServer, thread: threading.Thread) -> None:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
