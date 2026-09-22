"""Hallazgo 2's original fix (`ControlDB.fail_orphaned_scans`, a
one-time startup check that unconditionally marked every `queued`/
`running` scan `failed`) has been SUPERSEDED by the durable scan queue
(docs/PAID_API_DESIGN.md's "Durable, multi-worker-safe scan execution"
section) — a stale `running` scan is now automatically REQUEUED and
actually RE-EXECUTED (up to a bounded retry ceiling), not just marked
failed and abandoned. The pure sweep/retry-ceiling/claim-race logic
itself is tested directly against `ControlDB` in
`tests/test_scan_queue_durability.py`; this file keeps the real,
end-to-end value the original Hallazgo 2 test had — a REAL app, with
its REAL worker loop, recovering real leftover state through the actual
HTTP API — updated to assert what's actually true now instead of the
superseded "everything becomes failed" behavior.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")

from _verified_account import unique_email  # noqa: E402
from _verified_domain import seed_verified_domain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.control_db import ControlDB  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402

DOMAIN = "orphaned-scan-test.example"


def _install_pipeline_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
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


def _wait_for_status(
    client: TestClient, api_key: str, scan_id: str, *, timeout: float = 10.0
) -> str:
    deadline = time.monotonic() + timeout
    status = "unknown"
    while time.monotonic() < deadline:
        status = client.get(f"/scans/{scan_id}", headers={"X-API-Key": api_key}).json()["status"]
        if status in ("completed", "failed"):
            return status
        time.sleep(0.05)
    return status


class TestOrphanedScanReconciliationOnStartup:
    def test_a_scan_left_running_by_a_dead_process_is_requeued_and_actually_completes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_pipeline_stubs(monkeypatch)
        settings = APISettings(
            data_dir=tmp_path / "api_data",
            scan_poll_interval_seconds=0.1,
            scan_stale_after_seconds=0,  # immediately stale — no heartbeat was ever set
        )

        # Simulate "a previous process died mid-scan": create the
        # control DB directly (no app, no lifespan, no worker loop) and
        # leave a scan 'running' with no hearteat — exactly the state a
        # killed/crashed process (never having gone through
        # claim_next_queued_scan itself) would leave behind.
        pre_restart_db = ControlDB(settings.control_db_path)
        account_id = pre_restart_db.create_account()
        pre_restart_db.create_default_subscription(account_id, tier="free")
        pre_restart_db.create_scan(
            scan_id="was-queued", account_id=account_id, domain=DOMAIN, db_path="/tmp/x"
        )
        pre_restart_db.create_scan(
            scan_id="was-running", account_id=account_id, domain=DOMAIN, db_path="/tmp/x"
        )
        pre_restart_db.update_scan_status("was-running", "running")
        # A scan already resolved before the "restart" — must be left
        # completely untouched.
        pre_restart_db.create_scan(
            scan_id="already-completed", account_id=account_id, domain=DOMAIN, db_path="/tmp/x"
        )
        pre_restart_db.update_scan_status("already-completed", "completed")

        # Now start a REAL app (with its REAL worker loop) against this
        # SAME control.db — no api_key needed to observe these three by
        # scan_id, since we already have account_id/ControlDB access
        # directly.
        with TestClient(create_app(settings)):
            deadline = time.monotonic() + 10.0
            was_queued = was_running = None
            while time.monotonic() < deadline:
                was_queued = pre_restart_db.get_owned_scan("was-queued", account_id)
                was_running = pre_restart_db.get_owned_scan("was-running", account_id)
                if was_queued.status == "completed" and was_running.status == "completed":
                    break
                time.sleep(0.1)

        assert was_queued.status == "completed"
        assert was_running.status == "completed"
        # Real evidence it went through requeue, not a lucky first claim.
        assert was_running.retry_count >= 1

        already_completed = pre_restart_db.get_owned_scan("already-completed", account_id)
        assert already_completed.status == "completed"
        assert already_completed.error_message is None

    def test_no_orphaned_scans_is_a_silent_no_op(self, tmp_path: Path) -> None:
        """The common, healthy case (clean shutdown, or a fresh
        database) — startup must not error or touch anything when
        there's nothing to fix."""
        settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(settings)) as client:
            resp = client.post("/accounts", json={"email": unique_email()})
            assert resp.status_code == 201  # confirms the app started cleanly


class TestNormalScanLifecycleStillWorksAfterTheFix:
    """No regression for a scan that completes normally, with no
    interruption involved at all."""

    def test_a_scan_started_and_completed_in_the_same_process_is_unaffected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_pipeline_stubs(monkeypatch)

        settings = APISettings(data_dir=tmp_path / "api_data", scan_poll_interval_seconds=0.1)
        with TestClient(create_app(settings)) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            api_key = account["api_key"]
            account_id = account["account_id"]
            client.app.state.control_db.mark_email_verified(account_id)
            seed_verified_domain(client, account_id, DOMAIN)

            scan_id = client.post(
                "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
            ).json()["scan_id"]

            status = _wait_for_status(client, api_key, scan_id)
        assert status == "completed"
