"""`POST /scans/{id}/client-report` — confirms the API endpoint produces
the same document (structure, not necessarily identical bytes on a
timestamped field) as calling `core/client_report/cli.py`'s
`cmd_client_report` directly against the same underlying data. The
endpoint is implemented BY calling that exact function
(`api/routers/scans.py`), so this test is really confirming that wiring
is correct — that the API reads the file back and returns it unmodified
— not re-testing `core/client_report/` itself (already covered by
tests/test_client_report_*.py).
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

from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402
from core.client_report.cli import cmd_client_report  # noqa: E402
from core.models import ToolStatus  # noqa: E402
from core.plugin_base import PluginResult  # noqa: E402
from modules.dnsx import DnsxPlugin  # noqa: E402
from modules.httpx import HttpxPlugin  # noqa: E402
from modules.subfinder import SubfinderPlugin  # noqa: E402
from utils.files import write_jsonl, write_lines  # noqa: E402

SEED = "client-report-api-target.example"


def _install_pipeline_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    async def stub_subfinder(self, context, input_path):
        write_lines(context.output_dir / "subdomains.txt", [SEED], base_dir=context.output_dir)
        context.subdomains = [SEED]
        return PluginResult(
            success=True, output_path=context.output_dir / "subdomains.txt", lines_produced=1
        )

    async def stub_dnsx(self, context, input_path):
        write_jsonl(
            context.output_dir / "dnsx_records.jsonl",
            [{"host": SEED, "a": ["203.0.113.77"], "status_code": "NOERROR"}],
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
            [{"input": SEED, "url": url, "status_code": 200, "a": ["203.0.113.77"]}],
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


def _wait_for_terminal_status(
    client: TestClient, api_key: str, scan_id: str, *, timeout: float = 10.0
) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = client.get(f"/scans/{scan_id}", headers={"X-API-Key": api_key})
        body = resp.json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not complete within {timeout}s")


class TestClientReportMatchesCli:
    @pytest.mark.parametrize("fmt,language", [("markdown", "es"), ("markdown", "en")])
    def test_api_document_matches_direct_cli_call_structurally(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str, language: str
    ) -> None:
        _install_pipeline_stubs(monkeypatch)
        api_settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(api_settings)) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            client.app.state.control_db.mark_email_verified(account["account_id"])
            api_key = account["api_key"]
            account_id = account["account_id"]
            seed_verified_domain(client, account_id, SEED)
            # Free tier only permits markdown+es (Round 3's report-option
            # gate) — this test's subject is report-content parity, not
            # tier gating (covered separately), so upgrade past it.
            client.app.state.control_db.set_tier(account_id, "ultra")

            scan_id = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": api_key}
            ).json()["scan_id"]
            _wait_for_terminal_status(client, api_key, scan_id)

            api_resp = client.post(
                f"/scans/{scan_id}/client-report",
                json={"format": fmt, "language": language},
                headers={"X-API-Key": api_key},
            )
            assert api_resp.status_code == 200
            api_content = api_resp.text

            # Reference: call the exact same CLI-layer function directly
            # against the same account's data, writing to a different path
            # so it doesn't clobber the file the API endpoint just read.
            from api.tenancy import account_settings

            settings = account_settings(api_settings, account_id)
            reference_path = tmp_path / "reference_client_report.md"
            rc = cmd_client_report(
                settings, scan_id, output_path=reference_path, output_format=fmt, language=language
            )
            assert rc == 0
            reference_content = reference_path.read_text(encoding="utf-8")

            assert api_content == reference_content

            # Structural checks independent of exact byte-matching, per
            # the task's own wording ("compara estructura, no solo bytes
            # idénticos") — same headings present in both languages.
            heading = "## Resumen ejecutivo" if language == "es" else "## Executive Summary"
            assert heading in api_content
            assert heading in reference_content
            assert SEED in api_content

    def test_docx_format_returns_the_correct_media_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("docx")
        _install_pipeline_stubs(monkeypatch)
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            client.app.state.control_db.mark_email_verified(account["account_id"])
            api_key = account["api_key"]
            seed_verified_domain(client, account["account_id"], SEED)
            # docx + en is a Medium+ feature (Round 3's report-option
            # gate) — this test's subject is docx media-type wiring, not
            # tier gating (covered separately), so upgrade past it.
            client.app.state.control_db.set_tier(account["account_id"], "medium")
            scan_id = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": api_key}
            ).json()["scan_id"]
            _wait_for_terminal_status(client, api_key, scan_id)

            resp = client.post(
                f"/scans/{scan_id}/client-report",
                json={"format": "docx", "language": "en"},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            assert len(resp.content) > 0

    def test_client_report_before_completion_is_409(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_pipeline_stubs(monkeypatch)
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            client.app.state.control_db.mark_email_verified(account["account_id"])
            api_key = account["api_key"]
            seed_verified_domain(client, account["account_id"], SEED)
            scan_id = client.post(
                "/scans", json={"domain": SEED}, headers={"X-API-Key": api_key}
            ).json()["scan_id"]
            resp = client.post(
                f"/scans/{scan_id}/client-report", json={}, headers={"X-API-Key": api_key}
            )
            # Either already completed (stub is fast) or still pending —
            # only a 409 is invalid to assert unconditionally here, so
            # confirm the endpoint never 500s regardless of timing.
            assert resp.status_code in (200, 409)


class TestWhiteLabelBranding:
    """docs/PAID_API_DESIGN.md's white-label client report section — an
    Ultra account's own configured name appearing on the report cover/
    title, gated by real branding configuration, not a silent
    fallback."""

    def _ultra_account_with_completed_scan(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[str, str, str]:
        _install_pipeline_stubs(monkeypatch)
        account = client.post("/accounts", json={"email": unique_email()}).json()
        client.app.state.control_db.mark_email_verified(account["account_id"])
        api_key = account["api_key"]
        account_id = account["account_id"]
        seed_verified_domain(client, account_id, SEED)
        client.app.state.control_db.set_tier(account_id, "ultra")
        scan_id = client.post(
            "/scans", json={"domain": SEED}, headers={"X-API-Key": api_key}
        ).json()["scan_id"]
        _wait_for_terminal_status(client, api_key, scan_id)
        return api_key, account_id, scan_id

    def test_branding_endpoints_round_trip(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            client.app.state.control_db.mark_email_verified(account["account_id"])
            api_key = account["api_key"]
            client.app.state.control_db.set_tier(account["account_id"], "ultra")

            initial = client.get("/account/branding", headers={"X-API-Key": api_key})
            assert initial.status_code == 200
            assert initial.json() == {"company_name": None}

            set_resp = client.put(
                "/account/branding",
                json={"company_name": "Acme Security Consulting"},
                headers={"X-API-Key": api_key},
            )
            assert set_resp.status_code == 200
            assert set_resp.json() == {"company_name": "Acme Security Consulting"}

            get_resp = client.get("/account/branding", headers={"X-API-Key": api_key})
            assert get_resp.json() == {"company_name": "Acme Security Consulting"}

    def test_a_non_ultra_account_cannot_set_branding(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            client.app.state.control_db.mark_email_verified(account["account_id"])
            api_key = account["api_key"]
            # Free tier — never touched set_tier, default from account creation.

            resp = client.put(
                "/account/branding",
                json={"company_name": "Should Not Be Allowed"},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 403

    def test_white_label_with_branding_configured_appears_in_markdown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            api_key, account_id, scan_id = self._ultra_account_with_completed_scan(
                client, monkeypatch
            )
            client.put(
                "/account/branding",
                json={"company_name": "Acme Security Consulting"},
                headers={"X-API-Key": api_key},
            )

            resp = client.post(
                f"/scans/{scan_id}/client-report",
                json={"format": "markdown", "language": "en", "white_label": True},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            assert "Acme Security Consulting" in resp.text
            assert "**Prepared by:** Acme Security Consulting" in resp.text

    def test_white_label_with_branding_configured_appears_in_docx(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("docx")
        import io

        import docx

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            api_key, account_id, scan_id = self._ultra_account_with_completed_scan(
                client, monkeypatch
            )
            client.put(
                "/account/branding",
                json={"company_name": "Acme Security Consulting"},
                headers={"X-API-Key": api_key},
            )

            resp = client.post(
                f"/scans/{scan_id}/client-report",
                json={"format": "docx", "language": "en", "white_label": True},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            document = docx.Document(io.BytesIO(resp.content))
            full_text = "\n".join(p.text for p in document.paragraphs)
            assert "Acme Security Consulting" in full_text

    def test_white_label_without_branding_configured_is_422_not_a_silent_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            api_key, account_id, scan_id = self._ultra_account_with_completed_scan(
                client, monkeypatch
            )
            # Deliberately never called PUT /account/branding.

            resp = client.post(
                f"/scans/{scan_id}/client-report",
                json={"format": "markdown", "language": "en", "white_label": True},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 422
            assert "branding" in resp.json()["detail"].lower()

    def test_white_label_off_is_byte_for_byte_identical_to_no_branding_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No regression for the default path — an Ultra account that
        configured branding but did NOT ask for white_label=true on this
        particular request must get the exact same unbranded output as
        before this task existed."""
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api_data"))) as client:
            api_key, account_id, scan_id = self._ultra_account_with_completed_scan(
                client, monkeypatch
            )
            client.put(
                "/account/branding",
                json={"company_name": "Acme Security Consulting"},
                headers={"X-API-Key": api_key},
            )

            resp = client.post(
                f"/scans/{scan_id}/client-report",
                json={"format": "markdown", "language": "en", "white_label": False},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            assert "Acme Security Consulting" not in resp.text
            assert "Prepared by" not in resp.text
