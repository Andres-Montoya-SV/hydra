"""Hallazgo 2 (frontend-team review): a scan left `queued`/`running` by
a server restart must never stay stuck in an unresolvable status. The
fix — `ControlDB.fail_orphaned_scans`, called once at process startup
before the app accepts any request (`api/main.py`'s lifespan) — is
exercised here by seeding `queued`/`running` rows directly (simulating
"what a previous, now-dead process left behind"), then constructing the
app fresh and confirming every one of them resolves to `failed` with the
expected reason. Task 5, tests 4 and 5.
"""

from __future__ import annotations

from pathlib import Path

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


class TestOrphanedScanReconciliationOnStartup:
    def test_queued_and_running_scans_from_a_previous_process_become_failed(
        self, tmp_path: Path
    ) -> None:
        settings = APISettings(data_dir=tmp_path / "api_data")

        # Simulate "a previous process died mid-scan": create the
        # control DB directly (no app, no lifespan) and leave scans in
        # 'queued'/'running' — exactly the state a killed/crashed
        # process would leave behind.
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

        # Now start a REAL app against this SAME control.db — the
        # lifespan's startup reconciliation is what's under test.
        with TestClient(create_app(settings)):
            pass  # entering the `with` block runs the lifespan startup

        post_restart_db = ControlDB(settings.control_db_path)
        was_queued = post_restart_db.get_owned_scan("was-queued", account_id)
        was_running = post_restart_db.get_owned_scan("was-running", account_id)
        already_completed = post_restart_db.get_owned_scan("already-completed", account_id)

        assert was_queued.status == "failed"
        assert was_queued.error_message == "interrupted by server restart"
        assert was_running.status == "failed"
        assert was_running.error_message == "interrupted by server restart"

        # Never touched — it was already resolved before the "restart".
        assert already_completed.status == "completed"
        assert already_completed.error_message is None

    def test_no_orphaned_scans_is_a_silent_no_op(self, tmp_path: Path) -> None:
        """The common, healthy case (clean shutdown, or a fresh
        database) — startup reconciliation must not error or touch
        anything when there's nothing to fix."""
        settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(settings)) as client:
            resp = client.post("/accounts", json={"email": unique_email()})
            assert resp.status_code == 201  # confirms the app started cleanly


class TestNormalScanLifecycleStillWorksAfterTheFix:
    """Task 5, test 5 — no regression for a scan that completes
    normally, with no restart involved at all."""

    def test_a_scan_started_and_completed_in_the_same_process_is_unaffected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import AsyncMock

        from core.models import ToolStatus
        from core.plugin_base import PluginResult
        from modules.dnsx import DnsxPlugin
        from modules.httpx import HttpxPlugin
        from modules.subfinder import SubfinderPlugin
        from utils.files import write_jsonl, write_lines

        async def stub_subfinder(self, context, input_path):
            write_lines(
                context.output_dir / "subdomains.txt", [DOMAIN], base_dir=context.output_dir
            )
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

        import time

        settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(settings)) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            api_key = account["api_key"]
            account_id = account["account_id"]
            client.app.state.control_db.mark_email_verified(account_id)
            seed_verified_domain(client, account_id, DOMAIN)

            scan_id = client.post(
                "/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key}
            ).json()["scan_id"]

            deadline = time.monotonic() + 10.0
            status = None
            while time.monotonic() < deadline:
                status = client.get(f"/scans/{scan_id}", headers={"X-API-Key": api_key}).json()[
                    "status"
                ]
                if status in ("completed", "failed"):
                    break
                time.sleep(0.05)
            assert status == "completed"
