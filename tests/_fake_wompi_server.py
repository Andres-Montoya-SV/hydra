"""Shared test-support helper — deliberately NOT `conftest.py` (see
tests/_httpx_verification.py's docstring for why). A real local HTTP
server standing in for BOTH `id.wompi.sv` (OAuth token exchange) and
`api.wompi.sv` (`EnlacePagoRecurrente`/`TransaccionCompra`) — used by
tests/test_wompi_client.py (direct `WompiClient` unit tests) and
tests/test_api_subscription_endpoints.py (full HTTP end-to-end tests
through the real FastAPI app, pointed at this server via
`dev_wompi_id_base_url`/`dev_wompi_api_base_url`).
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import urllib.parse
from typing import Any


class FakeWompiHandler(http.server.BaseHTTPRequestHandler):
    token_requests: list[dict[str, str]] = []
    access_token = "fake-access-token"
    expires_in = 3600
    transaction_response: dict[str, Any] = {"esAprobada": True}

    def log_message(self, *args: object) -> None:
        pass

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path == "/connect/token":
            form = urllib.parse.parse_qs(raw.decode("utf-8"))
            FakeWompiHandler.token_requests.append({k: v[0] for k, v in form.items()})
            self._send_json(
                200,
                {
                    "access_token": self.access_token,
                    "expires_in": self.expires_in,
                    "token_type": "Bearer",
                    "scope": "wompi_api",
                },
            )
            return
        if self.path == "/EnlacePagoRecurrente":
            self._send_json(200, {"idEnlace": "1", "urlEnlace": "https://pay.example/x"})
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/TransaccionCompra/"):
            self._send_json(200, self.transaction_response)
            return
        self.send_response(404)
        self.end_headers()


def reset_fake_wompi_state(*, transaction_approved: bool = True, expires_in: int = 3600) -> None:
    FakeWompiHandler.token_requests = []
    FakeWompiHandler.expires_in = expires_in
    FakeWompiHandler.transaction_response = {"esAprobada": transaction_approved}


def start_fake_wompi_server() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), FakeWompiHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


def stop_fake_wompi_server(httpd: socketserver.TCPServer, thread: threading.Thread) -> None:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
