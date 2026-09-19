"""`POST /domains` / `POST /domains/{domain}/verify` / the `POST /scans`
gate — end-to-end through the real FastAPI app (`TestClient`), with the
real DNS/HTTP checks pointed at real local test servers via the
explicit, off-by-default `HYDRA_API_DEV_DNS_*`/
`HYDRA_API_DEV_WELL_KNOWN_BASE_URL` settings (api/settings.py) — never
mocking `verify_dns_txt`/`verify_well_known_file` themselves, only their
network destination. Task 3's design decisions (expiry, first-verification-
wins conflict, no live re-check per scan) are exercised here as actual
HTTP behavior, not just unit-tested in isolation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("dns")
pytest.importorskip("httpx")

from _dns_test_server import start_dns_test_server, stop_dns_test_server  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.domain_verification import dns_record_name, dns_record_value  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402

DOMAIN = "endpoint-test.example"


@pytest.fixture
def dns_backed_client(tmp_path: Path):
    """A real TestClient whose DNS TXT checks are pointed at a real local
    DNS test server — `HYDRA_API_DEV_DNS_NAMESERVER`/`_PORT` are the only
    thing distinguishing this from a real production deployment; the
    actual verification code path (api/domain_verification.py) runs
    completely unmodified.

    The server runs on its own background OS thread (not asyncio) so it
    keeps answering queries even while `client.post(...)` blocks this
    thread — see tests/_dns_test_server.py's docstring."""
    server, thread = start_dns_test_server()
    settings = APISettings(
        data_dir=tmp_path / "api_data",
        dev_dns_nameserver="127.0.0.1",
        dev_dns_port=server.port,
    )
    try:
        with TestClient(create_app(settings)) as client:
            yield client, server
    finally:
        stop_dns_test_server(server, thread)


def _create_account(client: TestClient) -> str:
    return client.post("/accounts").json()["api_key"]


class TestDnsTxtEndToEndThroughTheRealApi:
    def test_full_flow_register_verify_then_scan_succeeds(
        self, dns_backed_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, dns_server = dns_backed_client
        api_key = _create_account(client)

        register = client.post("/domains", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
        assert register.status_code == 201
        body = register.json()
        assert body["domain"] == DOMAIN
        token = body["token"]
        assert body["dns_instructions"]["name"] == dns_record_name(DOMAIN)
        assert body["dns_instructions"]["value"] == dns_record_value(token)

        # Populate the real DNS test server with the exact record the
        # client was told to add.
        dns_server.txt_records[dns_record_name(DOMAIN)] = dns_record_value(token)

        verify = client.post(
            f"/domains/{DOMAIN}/verify", json={"method": "dns_txt"}, headers={"X-API-Key": api_key}
        )
        assert verify.status_code == 200
        verify_body = verify.json()
        assert verify_body["status"] == "verified"
        assert verify_body["method"] == "dns_txt"

        # Now the non-negotiable gate must let a scan through — stub the
        # pipeline itself (irrelevant to this test) so it completes fast.
        _stub_pipeline(monkeypatch)
        scan_resp = client.post("/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
        assert scan_resp.status_code == 202

    def test_verify_fails_clearly_when_the_record_is_missing(self, dns_backed_client) -> None:
        client, _dns_server = dns_backed_client
        api_key = _create_account(client)
        client.post("/domains", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})

        verify = client.post(
            f"/domains/{DOMAIN}/verify", json={"method": "dns_txt"}, headers={"X-API-Key": api_key}
        )
        assert verify.status_code == 422
        assert "Verification check failed" in verify.json()["detail"]

    def test_scan_against_never_verified_domain_is_403_and_creates_no_scan(
        self, dns_backed_client
    ) -> None:
        client, _dns_server = dns_backed_client
        api_key = _create_account(client)

        resp = client.post(
            "/scans", json={"domain": "never-verified.example"}, headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 403
        assert "not verified" in resp.json()["detail"]
        assert "POST /domains" in resp.json()["detail"]

    def test_a_subdomain_of_a_verified_domain_is_covered(
        self, dns_backed_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, dns_server = dns_backed_client
        api_key = _create_account(client)

        register = client.post("/domains", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
        token = register.json()["token"]
        dns_server.txt_records[dns_record_name(DOMAIN)] = dns_record_value(token)
        client.post(
            f"/domains/{DOMAIN}/verify", json={"method": "dns_txt"}, headers={"X-API-Key": api_key}
        )

        _stub_pipeline(monkeypatch)
        resp = client.post(
            "/scans", json={"domain": f"sub.{DOMAIN}"}, headers={"X-API-Key": api_key}
        )
        assert resp.status_code == 202

    def test_second_account_verifying_the_same_domain_gets_a_clear_conflict(
        self, dns_backed_client
    ) -> None:
        client, dns_server = dns_backed_client
        key_a = _create_account(client)
        key_b = _create_account(client)

        register_a = client.post("/domains", json={"domain": DOMAIN}, headers={"X-API-Key": key_a})
        token_a = register_a.json()["token"]
        dns_server.txt_records[dns_record_name(DOMAIN)] = dns_record_value(token_a)
        verify_a = client.post(
            f"/domains/{DOMAIN}/verify", json={"method": "dns_txt"}, headers={"X-API-Key": key_a}
        )
        assert verify_a.status_code == 200

        # Account B requests its OWN token and, hypothetically, also
        # manages to satisfy it (e.g. briefly had DNS control, or is
        # simply trying its luck) — the real check succeeds, but account
        # A already holds this domain.
        register_b = client.post("/domains", json={"domain": DOMAIN}, headers={"X-API-Key": key_b})
        token_b = register_b.json()["token"]
        dns_server.txt_records[dns_record_name(DOMAIN)] = dns_record_value(token_b)
        verify_b = client.post(
            f"/domains/{DOMAIN}/verify", json={"method": "dns_txt"}, headers={"X-API-Key": key_b}
        )
        assert verify_b.status_code == 409
        assert "already verified by another account" in verify_b.json()["detail"]

        # Account B still cannot scan the domain.
        scan_b = client.post("/scans", json={"domain": DOMAIN}, headers={"X-API-Key": key_b})
        assert scan_b.status_code == 403

    def test_expired_verification_is_rejected_with_a_distinct_message(
        self, dns_backed_client
    ) -> None:
        client, dns_server = dns_backed_client
        api_key = _create_account(client)

        register = client.post("/domains", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
        token = register.json()["token"]
        dns_server.txt_records[dns_record_name(DOMAIN)] = dns_record_value(token)
        verify = client.post(
            f"/domains/{DOMAIN}/verify", json={"method": "dns_txt"}, headers={"X-API-Key": api_key}
        )
        assert verify.status_code == 200

        # Simulate 90 days having passed — the real, honest way to test
        # expiry without sleeping 90 days or mocking datetime.now()
        # globally (same pattern as Round 1's key-rotation test).
        control_db = client.app.state.control_db
        with control_db._connect() as conn:  # noqa: SLF001 - test-only direct DB access
            conn.execute(
                "UPDATE domain_verifications SET expires_at = '2000-01-01T00:00:00+00:00' "
                "WHERE domain = ?",
                (DOMAIN,),
            )

        resp = client.post("/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
        assert resp.status_code == 403
        assert "expired" in resp.json()["detail"].lower()
        assert "not verified" not in resp.json()["detail"]


def _stub_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The domain-verification gate is the subject of this test file —
    stub the actual scan execution the same way
    tests/test_api_scans.py does, so a 202 here means "the gate let it
    through," not "we waited for a real recon pipeline."""
    from unittest.mock import AsyncMock

    from core.models import ToolStatus
    from core.plugin_base import PluginResult
    from modules.dnsx import DnsxPlugin
    from modules.httpx import HttpxPlugin
    from modules.subfinder import SubfinderPlugin
    from utils.files import write_jsonl, write_lines

    async def stub_subfinder(self, context, input_path):
        write_lines(context.output_dir / "subdomains.txt", [DOMAIN], base_dir=context.output_dir)
        context.subdomains = [DOMAIN]
        return PluginResult(
            success=True, output_path=context.output_dir / "subdomains.txt", lines_produced=1
        )

    async def stub_dnsx(self, context, input_path):
        write_jsonl(
            context.output_dir / "dnsx_records.jsonl",
            [{"host": DOMAIN, "a": ["203.0.113.5"], "status_code": "NOERROR"}],
            base_dir=context.output_dir,
        )
        write_lines(context.output_dir / "resolved.txt", [DOMAIN], base_dir=context.output_dir)
        context.resolved = [DOMAIN]
        return PluginResult(
            success=True, output_path=context.output_dir / "resolved.txt", lines_produced=1
        )

    async def stub_httpx(self, context, input_path):
        url = f"https://{DOMAIN}/"
        write_jsonl(
            context.output_dir / "httpx.json",
            [{"input": DOMAIN, "url": url, "status_code": 200}],
            base_dir=context.output_dir,
        )
        write_lines(context.output_dir / "alive.txt", [url], base_dir=context.output_dir)
        context.alive_urls = [url]
        context.httpx_results = [{"input": DOMAIN, "url": url, "status_code": 200}]
        return PluginResult(
            success=True, output_path=context.output_dir / "httpx.json", lines_produced=1
        )

    monkeypatch.setattr(SubfinderPlugin, "run", stub_subfinder)
    monkeypatch.setattr(DnsxPlugin, "run", stub_dnsx)
    monkeypatch.setattr(HttpxPlugin, "run", stub_httpx)

    from core.dependencies.service import DependencyService
    from core.tool_manager import ToolManager

    async def fake_validate(self, context):
        for plugin in self.get_all_plugins():
            info = plugin.build_tool_info()
            info.status = (
                ToolStatus.READY
                if plugin.name in {"subfinder", "dnsx", "httpx"}
                else ToolStatus.SKIPPED
            )
            context.tool_states[plugin.name] = info
        return True

    async def fake_analyze(self, force_refresh: bool = False):
        return {}

    monkeypatch.setattr(ToolManager, "validate_tools", fake_validate)
    monkeypatch.setattr(ToolManager, "ensure_mandatory_tools", AsyncMock())
    monkeypatch.setattr(
        ToolManager, "is_runnable", lambda self, name: name in {"subfinder", "dnsx", "httpx"}
    )
    monkeypatch.setattr(DependencyService, "analyze_all", fake_analyze)
    monkeypatch.setattr(
        "ui.dependency_report.render_dependency_report", lambda *args, **kwargs: None
    )


class TestWellKnownFileEndToEndThroughTheRealApi:
    def test_full_flow_register_verify_then_scan_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import http.server
        import socketserver
        import threading

        # Register first (without a running file server yet) to learn the
        # token, THEN start a real HTTP server serving exactly that file —
        # mirrors the real operator workflow (get the token, publish it,
        # then ask for verification).
        settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(settings)) as client:
            api_key = _create_account(client)
            register = client.post(
                "/domains", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
            )
            token = register.json()["token"]
            file_path = register.json()["file_instructions"]["path"]

            class _Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args: object) -> None:
                    pass

                def do_GET(self) -> None:  # noqa: N802
                    if self.path == file_path:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(token.encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()

            socketserver.TCPServer.allow_reuse_address = True
            httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
            http_port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                client.app.state.api_settings.dev_well_known_base_url = (
                    f"http://127.0.0.1:{http_port}"
                )
                verify = client.post(
                    f"/domains/{DOMAIN}/verify",
                    json={"method": "well_known_file"},
                    headers={"X-API-Key": api_key},
                )
                assert verify.status_code == 200
                assert verify.json()["method"] == "well_known_file"

                _stub_pipeline(monkeypatch)
                scan_resp = client.post(
                    "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
                )
                assert scan_resp.status_code == 202
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)
