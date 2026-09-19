"""`api/routers/scans.py` — docs/PAID_API_DESIGN.md Part E (async scan
lifecycle) and Part F (multi-tenant isolation), exercised through real
HTTP requests. Network collectors are stubbed at the plugin-class
boundary — the same pattern tests/test_cli_acceptance.py and
tests/test_engagement_cli.py already use — so a full scan completes in
milliseconds instead of ~25 minutes; everything downstream of that
(control-plane bookkeeping, per-account SQLite isolation, status
transitions, report/client-report generation) is the real production
path, unstubbed.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")

from _verified_domain import seed_verified_domain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402
from core.models import ToolStatus  # noqa: E402
from core.plugin_base import PluginResult  # noqa: E402
from modules.dnsx import DnsxPlugin  # noqa: E402
from modules.httpx import HttpxPlugin  # noqa: E402
from modules.subfinder import SubfinderPlugin  # noqa: E402
from utils.files import write_jsonl, write_lines  # noqa: E402

SEED = "api-test-target.example"


def _install_pipeline_stubs(
    monkeypatch: pytest.MonkeyPatch, *, subfinder_delay: float = 0.0
) -> None:
    async def stub_subfinder(self, context, input_path):
        if subfinder_delay:
            await asyncio.sleep(subfinder_delay)
        write_lines(context.output_dir / "subdomains.txt", [SEED], base_dir=context.output_dir)
        context.subdomains = [SEED]
        return PluginResult(
            success=True, output_path=context.output_dir / "subdomains.txt", lines_produced=1
        )

    async def stub_dnsx(self, context, input_path):
        write_jsonl(
            context.output_dir / "dnsx_records.jsonl",
            [{"host": SEED, "a": ["203.0.113.55"], "status_code": "NOERROR"}],
            base_dir=context.output_dir,
        )
        write_lines(context.output_dir / "resolved.txt", [SEED], base_dir=context.output_dir)
        context.resolved = [SEED]
        return PluginResult(
            success=True, output_path=context.output_dir / "resolved.txt", lines_produced=1
        )

    async def stub_httpx(self, context, input_path):
        url = f"https://{SEED}/"
        write_jsonl(
            context.output_dir / "httpx.json",
            [{"input": SEED, "url": url, "status_code": 200, "a": ["203.0.113.55"]}],
            base_dir=context.output_dir,
        )
        write_lines(context.output_dir / "alive.txt", [url], base_dir=context.output_dir)
        context.alive_urls = [url]
        context.httpx_results = [{"input": SEED, "url": url, "status_code": 200}]
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


def _client(tmp_path: Path) -> TestClient:
    settings = APISettings(data_dir=tmp_path / "api_data")
    return TestClient(create_app(settings))


def _create_account(client: TestClient, *, verified_domain: str = SEED) -> str:
    """Creates an account and pre-seeds it as the verified owner of
    `verified_domain` (Round 2's mandatory gate — see
    tests/_verified_domain.py) so this file's Round-1-era tests, whose
    subject is the scan lifecycle/isolation, can call `POST /scans`
    exactly as before rather than performing real domain verification in
    every test."""
    body = client.post("/accounts").json()
    seed_verified_domain(client, body["account_id"], verified_domain)
    return body["api_key"]


def _wait_for_terminal_status(
    client: TestClient, api_key: str, scan_id: str, *, timeout: float = 10.0
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/scans/{scan_id}", headers={"X-API-Key": api_key})
        assert resp.status_code == 200
        body = resp.json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not reach a terminal status within {timeout}s")


class TestScanLifecycle:
    def test_full_cycle_queued_to_completed_to_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_pipeline_stubs(monkeypatch)
        with _client(tmp_path) as client:
            api_key = _create_account(client)

            create_resp = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": api_key}
            )
            assert create_resp.status_code == 202
            body = create_resp.json()
            assert body["status"] == "queued"
            scan_id = body["scan_id"]

            final = _wait_for_terminal_status(client, api_key, scan_id)
            assert final["status"] == "completed"
            assert final["domain"] == SEED
            assert final["error_message"] is None

            report_resp = client.get(f"/scans/{scan_id}/report", headers={"X-API-Key": api_key})
            assert report_resp.status_code == 200
            report = report_resp.json()
            assert report["subdomains_count"] == 1
            assert report["resolved_count"] == 1
            assert report["alive_count"] == 1

    def test_report_is_409_before_the_scan_completes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A deliberate delay in the stub keeps the scan reliably
        # "running" long enough for the immediate check below — this
        # avoids a flaky/skip-on-bad-luck test racing the stubbed
        # pipeline's own (otherwise near-instant) completion.
        _install_pipeline_stubs(monkeypatch, subfinder_delay=0.3)
        with _client(tmp_path) as client:
            api_key = _create_account(client)
            scan_id = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": api_key}
            ).json()["scan_id"]

            immediate = client.get(f"/scans/{scan_id}/report", headers={"X-API-Key": api_key})
            assert immediate.status_code == 409

            final = _wait_for_terminal_status(client, api_key, scan_id)
            assert final["status"] == "completed"
            completed = client.get(f"/scans/{scan_id}/report", headers={"X-API-Key": api_key})
            assert completed.status_code == 200

    def test_nonexistent_scan_is_404(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            api_key = _create_account(client)
            resp = client.get("/scans/does-not-exist", headers={"X-API-Key": api_key})
            assert resp.status_code == 404


class TestMultiTenantIsolation:
    def test_account_b_cannot_read_account_as_scan_by_exact_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_pipeline_stubs(monkeypatch)
        with _client(tmp_path) as client:
            key_a = _create_account(client)
            key_b = _create_account(client)

            scan_id = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": key_a}
            ).json()["scan_id"]
            _wait_for_terminal_status(client, key_a, scan_id)

            # Account A can read its own scan fine.
            assert client.get(f"/scans/{scan_id}", headers={"X-API-Key": key_a}).status_code == 200

            # Account B, using the EXACT same scan_id, gets a plain 404 —
            # not 403 (which would confirm the scan's existence to a
            # non-owner), and not any data about it.
            b_status = client.get(f"/scans/{scan_id}", headers={"X-API-Key": key_b})
            assert b_status.status_code == 404
            b_report = client.get(f"/scans/{scan_id}/report", headers={"X-API-Key": key_b})
            assert b_report.status_code == 404
            b_client_report = client.post(
                f"/scans/{scan_id}/client-report", json={}, headers={"X-API-Key": key_b}
            )
            assert b_client_report.status_code == 404

    def test_each_account_gets_its_own_physically_separate_db_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_pipeline_stubs(monkeypatch)
        with _client(tmp_path) as client:
            key_a = _create_account(client)
            key_b = _create_account(client)

            scan_a = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": key_a}
            ).json()["scan_id"]
            scan_b = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": key_b}
            ).json()["scan_id"]
            _wait_for_terminal_status(client, key_a, scan_a)
            _wait_for_terminal_status(client, key_b, scan_b)

            accounts_root = tmp_path / "api_data" / "accounts"
            account_dirs = [p for p in accounts_root.iterdir() if p.is_dir()]
            assert len(account_dirs) == 2
            db_files = sorted((d / "output" / "recon.db") for d in account_dirs)
            assert all(p.is_file() for p in db_files)
            assert db_files[0] != db_files[1]
