"""Shared test-support helper — deliberately NOT `conftest.py` (see
tests/_httpx_verification.py's docstring for why). A real local HTTP
server standing in for an S3-compatible object-storage endpoint, the
same "real server as arbiter" pattern `tests/_fake_postmark_server.py`/
`tests/_fake_wompi_server.py` already established — a real `boto3`
client talks to this over real HTTP, never mocked.

Only implements the one operation `api/backup_worker.py::
_upload_snapshot_to_s3` actually performs (`PutObject`, via
`boto3`'s `upload_file`) — path-style addressing only (this project's
own backup code always sets `addressing_style: "path"` when a custom
`endpoint_url` is configured, exactly so a bare-IP local endpoint like
this one works), so every request path is `/<bucket>/<key...>`.
"""

from __future__ import annotations

import http.server
import socketserver
import threading


class FakeS3Handler(http.server.BaseHTTPRequestHandler):
    # path -> raw uploaded bytes — real evidence of what boto3 actually
    # sent, not a claim that it "worked."
    uploads: dict[str, bytes] = {}
    fail_with_status: int | None = None

    def log_message(self, *args: object) -> None:
        pass

    def do_PUT(self) -> None:  # noqa: N802
        if FakeS3Handler.fail_with_status is not None:
            self.send_response(FakeS3Handler.fail_with_status)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        FakeS3Handler.uploads[self.path] = body
        self.send_response(200)
        # S3's real PutObject response always carries an ETag header —
        # boto3's own response parsing expects one to be present.
        self.send_header("ETag", '"fake-etag"')
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        # botocore issues a HeadBucket/HeadObject probe in some code
        # paths — always answer "exists, empty" so upload_file proceeds
        # straight to a plain PutObject for our small test files.
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def reset_fake_s3_state(*, fail_with_status: int | None = None) -> None:
    FakeS3Handler.uploads = {}
    FakeS3Handler.fail_with_status = fail_with_status


def start_fake_s3_server() -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), FakeS3Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


def stop_fake_s3_server(httpd: socketserver.TCPServer, thread: threading.Thread) -> None:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
