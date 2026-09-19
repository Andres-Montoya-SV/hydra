"""`api/domain_verification.py::verify_dns_txt`/`verify_well_known_file`
against REAL servers — a real UDP DNS server speaking real wire-format
DNS (via `dnspython`'s own message parsing, not a mock of the Python
function) for the TXT check, and a real `http.server` instance for the
well-known-file check — the same "real server as arbiter" pattern this
project already uses for HTTP confinement
(tests/test_httpx_confinement_live.py) and now applied to DNS.
"""

from __future__ import annotations

import http.server
import socketserver
import threading

import pytest

pytest.importorskip("dns")
pytest.importorskip("httpx")

from _dns_test_server import resolver_for, start_dns_test_server, stop_dns_test_server  # noqa: E402

from api.domain_verification import (  # noqa: E402
    dns_record_name,
    verify_dns_txt,
    verify_well_known_file,
    well_known_file_path,
)

DOMAIN = "verify-live-test.example"
TOKEN = "test-token-abc123"


@pytest.fixture
def dns_test_server():
    """Yields a factory: call it with {qname: txt_value} to (re)configure
    what the server answers, and it returns a resolver already pointed at
    it. A fresh server per test avoids state leaking between tests."""
    server, thread = start_dns_test_server()

    def configure(txt_records: dict[str, str]):
        server.txt_records = txt_records
        return resolver_for(server.port)

    try:
        yield configure
    finally:
        stop_dns_test_server(server, thread)


class TestDnsTxtVerificationAgainstARealServer:
    @pytest.mark.asyncio
    async def test_success_when_the_real_server_answers_the_expected_value(
        self, dns_test_server
    ) -> None:
        record_name = dns_record_name(DOMAIN)
        resolver = dns_test_server({record_name: f"hydra-verify={TOKEN}"})

        success, detail = await verify_dns_txt(DOMAIN, TOKEN, resolver=resolver)

        assert success is True
        assert record_name in detail

    @pytest.mark.asyncio
    async def test_failure_when_no_record_exists(self, dns_test_server) -> None:
        # The test server answers with a real, valid NOERROR/no-data
        # response (an empty answer section) when the qname isn't in its
        # configured records — the real-world shape a domain with no
        # verification TXT record at all actually has (not NXDOMAIN,
        # since the domain itself typically still resolves for other
        # record types).
        resolver = dns_test_server({})

        success, detail = await verify_dns_txt(DOMAIN, TOKEN, resolver=resolver)

        assert success is False
        assert "no TXT records" in detail

    @pytest.mark.asyncio
    async def test_failure_when_the_txt_value_does_not_match(self, dns_test_server) -> None:
        record_name = dns_record_name(DOMAIN)
        resolver = dns_test_server({record_name: "hydra-verify=some-other-token"})

        success, detail = await verify_dns_txt(DOMAIN, TOKEN, resolver=resolver)

        assert success is False
        assert "does not" not in detail  # sanity: real message, not a stub
        assert "none match" in detail.lower()

    @pytest.mark.asyncio
    async def test_never_trusts_a_txt_record_on_the_wrong_name(self, dns_test_server) -> None:
        """The server has a perfectly valid answer, just under a
        different name than `_hydra-verification.<domain>` — must not be
        picked up (dnspython only ever returns records for the name
        actually queried, but this test proves it end-to-end rather than
        assuming that library behavior)."""
        resolver = dns_test_server({f"decoy.{DOMAIN}": f"hydra-verify={TOKEN}"})

        success, _ = await verify_dns_txt(DOMAIN, TOKEN, resolver=resolver)

        assert success is False


def _serve_well_known(
    content: str | None, *, status: int = 200
) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            if content is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


class TestWellKnownFileVerificationAgainstARealServer:
    @pytest.mark.asyncio
    async def test_success_when_the_file_exists_with_matching_content(self) -> None:
        httpd, port, thread = _serve_well_known(TOKEN)
        try:
            success, detail = await verify_well_known_file(
                DOMAIN, TOKEN, base_url=f"http://127.0.0.1:{port}"
            )
            assert success is True
            assert well_known_file_path(TOKEN) in detail
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_failure_when_the_file_is_absent(self) -> None:
        httpd, port, thread = _serve_well_known(None)
        try:
            success, detail = await verify_well_known_file(
                DOMAIN, TOKEN, base_url=f"http://127.0.0.1:{port}"
            )
            assert success is False
            assert "404" in detail
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_failure_when_the_content_is_wrong(self) -> None:
        httpd, port, thread = _serve_well_known("not-the-right-token")
        try:
            success, detail = await verify_well_known_file(
                DOMAIN, TOKEN, base_url=f"http://127.0.0.1:{port}"
            )
            assert success is False
            assert "does not match" in detail
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_failure_when_nothing_is_listening(self) -> None:
        success, detail = await verify_well_known_file(DOMAIN, TOKEN, base_url="http://127.0.0.1:1")
        assert success is False
        assert "Could not reach" in detail

    @pytest.mark.asyncio
    async def test_uses_a_real_httpx_client_end_to_end_when_none_is_injected(self) -> None:
        """Sanity check on the default path (no `client=` override): the
        function must still work end-to-end against a real local server
        when it constructs its own httpx.AsyncClient internally."""
        httpd, port, thread = _serve_well_known(TOKEN)
        try:
            success, _ = await verify_well_known_file(
                DOMAIN, TOKEN, base_url=f"http://127.0.0.1:{port}"
            )
            assert success is True
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)
