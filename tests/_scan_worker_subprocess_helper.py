"""Standalone launcher for the durable-scan-queue kill+relaunch test
(`tests/test_scan_queue_durability.py`) — deliberately NOT `conftest.py`
(see `tests/_httpx_verification.py`'s docstring for why), and not a
regular test-support module either: this one is run as its OWN Python
process (`python3 -m tests._scan_worker_subprocess_helper`), never
imported.

**Why a subprocess needs its own stub-installer**: every other API test
stubs the pipeline via pytest's `monkeypatch` fixture inside the SAME
process the test itself runs in — a `monkeypatch.setattr(...)` call has
no effect on a genuinely separate OS process's own fresh Python
interpreter and imports. The kill+relaunch test needs a REAL separate
process (that's the entire point — proving the worker loop's startup/
claim behavior survives an actual process boundary, not a simulated
one), so the stub installation has to happen INSIDE that child process,
before it starts serving. This script does exactly what
`tests/test_api_scans.py::_install_pipeline_stubs` does, via plain
`setattr` instead of `monkeypatch` (no teardown needed — the whole
point is this process exits when the test kills it).

The stub itself sleeps for `SCAN_STUB_DELAY_SECONDS` (env var) before
returning — long enough that the test has a reliable window to kill
this process while a claimed scan is genuinely mid-execution
(`status='running'`), not racing a near-instant stub.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock

SEED = os.environ.get("SCAN_STUB_DOMAIN", "kill-relaunch-test.example")
STUB_DELAY_SECONDS = float(os.environ.get("SCAN_STUB_DELAY_SECONDS", "0"))


def _install_pipeline_stubs() -> None:
    from core.models import ToolStatus
    from core.plugin_base import PluginResult
    from modules.dnsx import DnsxPlugin
    from modules.httpx import HttpxPlugin
    from modules.subfinder import SubfinderPlugin
    from utils.files import write_jsonl, write_lines

    async def stub_subfinder(self, context, input_path):
        if STUB_DELAY_SECONDS:
            await asyncio.sleep(STUB_DELAY_SECONDS)
        write_lines(context.output_dir / "subdomains.txt", [SEED], base_dir=context.output_dir)
        context.subdomains = [SEED]
        return PluginResult(
            success=True, output_path=context.output_dir / "subdomains.txt", lines_produced=1
        )

    async def stub_dnsx(self, context, input_path):
        write_jsonl(
            context.output_dir / "dnsx_records.jsonl",
            [{"host": SEED, "a": ["203.0.113.9"], "status_code": "NOERROR"}],
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
            [{"input": SEED, "url": url, "status_code": 200, "a": ["203.0.113.9"]}],
            base_dir=context.output_dir,
        )
        write_lines(context.output_dir / "alive.txt", [url], base_dir=context.output_dir)
        context.alive_urls = [url]
        context.httpx_results = [{"input": SEED, "url": url, "status_code": 200}]
        return PluginResult(
            success=True, output_path=context.output_dir / "httpx.json", lines_produced=1
        )

    SubfinderPlugin.run = stub_subfinder
    DnsxPlugin.run = stub_dnsx
    HttpxPlugin.run = stub_httpx

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

    ToolManager.validate_tools = fake_validate
    ToolManager.ensure_mandatory_tools = AsyncMock()
    ToolManager.is_runnable = lambda self, name: name in {"subfinder", "dnsx", "httpx"}
    DependencyService.analyze_all = fake_analyze

    import ui.dependency_report

    ui.dependency_report.render_dependency_report = lambda *args, **kwargs: None


if __name__ == "__main__":
    _install_pipeline_stubs()

    import uvicorn

    from api.main import create_app
    from api.settings import APISettings

    settings = APISettings(
        data_dir=Path(os.environ["HYDRA_API_DATA_DIR"]),
        scan_poll_interval_seconds=float(
            os.environ.get("HYDRA_API_SCAN_POLL_INTERVAL_SECONDS", "0.2")
        ),
        scan_heartbeat_interval_seconds=float(
            os.environ.get("HYDRA_API_SCAN_HEARTBEAT_INTERVAL_SECONDS", "0.2")
        ),
        scan_stale_after_seconds=int(os.environ.get("HYDRA_API_SCAN_STALE_AFTER_SECONDS", "1")),
        scan_max_retries=int(os.environ.get("HYDRA_API_SCAN_MAX_RETRIES", "3")),
    )
    uvicorn.run(create_app(settings), host="127.0.0.1", port=int(os.environ["PORT"]))
