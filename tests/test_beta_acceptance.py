"""Productization Phase 13c: the beta acceptance test.

A realistic organization lifecycle, driven ENTIRELY through the CLI
(`hydra_client`), which itself only calls the documented public API:
sign up, verify the email, explore the demo, verify a domain, scan it,
triage what the scan found, turn on monitoring, send feedback, export
and clean up.

What is real:
- the whole FastAPI app: routing, auth, edge, entitlements, error shape;
- the scan worker that claims and runs the scan;
- the EASM backfill and exposure lifecycle;
- domain verification, a real DNS TXT lookup against a local test DNS
  server (the documented, off-by-default `HYDRA_API_DEV_DNS_*` settings).

What stands in:
- the recon pipeline's network collection, replaced by fixture results
  for the verified domain only;
- reading the verification email, done by reading the token the console
  email sender would have printed.

Every name and address is reserved for documentation (`.example`,
RFC 2606; RFC 5737). Nothing touches a real third-party target.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pytest
from _client_transport import BASE_URL, in_process_transport
from _dns_test_server import start_dns_test_server, stop_dns_test_server
from fastapi.testclient import TestClient

from api.domain_verification import dns_record_name, dns_record_value
from api.main import create_app
from api.settings import APISettings
from core.assets import Finding, Host, Port, ScanRun
from core.intel.cli import default_db
from core.models import PipelineContext
from core.store import AssetStore
from hydra_client.cli import main

DOMAIN = "acme-corp.example"


async def _fixture_pipeline(settings: Any, *, domain: str, targets_file: Any, run_id: str):
    """Stands in for network collection: the results a scan of the verified
    domain would have written to the account's own results database."""
    store = AssetStore(default_db(settings.project_root, settings.output_directory))
    store.create_run(ScanRun(run_id=run_id, started_at="2026-10-01T00:00:00+00:00"))
    store.upsert_host(run_id, Host(domain=domain, ips=["192.0.2.50"], dns_resolved=True))
    store.upsert_host(
        run_id,
        Host(
            domain=f"admin.{domain}",
            ips=["192.0.2.51"],
            dns_resolved=True,
            ports=[Port(host=f"admin.{domain}", port=443, service="https")],
            findings=[
                Finding(
                    host=f"admin.{domain}",
                    template_id="exposed-admin-panel",
                    severity="high",
                    name="Admin interface exposed",
                    url=f"https://admin.{domain}/login",
                )
            ],
        ),
    )
    return 0, PipelineContext(errors=[])


class _Cli:
    """Runs the CLI against the in-process app and decodes its output."""

    def __init__(self, client: TestClient) -> None:
        self.transport = in_process_transport(client)
        self.env = {"HYDRA_API_URL": BASE_URL}

    def run(self, *argv: str, expect: int = 0) -> Any:
        out, err = io.StringIO(), io.StringIO()
        code = main(
            list(argv),
            transport=self.transport,
            stdout=out,
            stderr=err,
            env=self.env,
            sleep=lambda s: time.sleep(0.05),
        )
        assert code == expect, (argv, code, err.getvalue())
        return json.loads(out.getvalue()) if out.getvalue() else err.getvalue()


@pytest.fixture
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr("app._run_headless_pipeline", _fixture_pipeline)
    monkeypatch.setattr("app._external_mode_preflight", lambda args, settings: True)
    server, thread = start_dns_test_server()
    settings = APISettings(
        data_dir=tmp_path / "api",
        dev_dns_nameserver="127.0.0.1",
        dev_dns_port=server.port,
        max_concurrent_scans=1,
        scan_poll_interval_seconds=0.05,
    )
    try:
        with TestClient(create_app(settings)) as client:
            yield _Cli(client), client, server
    finally:
        stop_dns_test_server(server, thread)


def _sign_up(cli: _Cli, client: TestClient) -> str:
    assert cli.run("version")["api_version"] == "1"
    account = cli.run("signup", "founder@acme-corp.example")
    cli.env["HYDRA_API_KEY"] = account["api_key"]
    hints = cli.run("diagnostics")["hints"]
    assert any(h.startswith("Email not verified") for h in hints)

    # The user opens the verification email.
    token = client.app.state.control_db.get_account(account["account_id"]).email_verification_token
    assert cli.run("verify-email", token)["status"] == "verified"
    return str(account["account_id"])


def _explore_the_demo(cli: _Cli) -> str:
    demo = cli.run("demo")
    assert demo["is_demo"] is True
    exposures = cli.run("exposures", demo["organization_id"])
    assert {e["severity"] for e in exposures} == {"high", "medium", "low"}
    refused = cli.run(
        "exposure-resolve",
        demo["organization_id"],
        exposures[0]["exposure_id"],
        "--reason",
        "x",
        expect=1,
    )
    assert "demo_organization_read_only" in refused
    return str(demo["organization_id"])


def _verify_and_scan(cli: _Cli, dns_server: Any) -> str:
    instructions = cli.run("domain-add", DOMAIN)
    # The customer publishes the TXT record they were given.
    dns_server.txt_records[dns_record_name(DOMAIN)] = dns_record_value(instructions["token"])
    assert cli.run("domain-verify", DOMAIN)["status"] == "verified"

    scan = cli.run("scan", DOMAIN)
    finished = cli.run("scan-wait", scan["scan_id"], "--interval", "0.05", "--timeout", "30")
    assert finished["status"] == "completed", finished
    # Free has one scan a month: the second is refused with a clear code.
    assert "scan_quota_exceeded" in cli.run("scan", DOMAIN, expect=1)
    return str(scan["scan_id"])


def _triage(cli: _Cli, org: str) -> None:
    domains = {a["identity_key"] for a in cli.run("assets", org) if a["asset_type"] == "domain"}
    assert domains == {f"domain:{DOMAIN}", f"domain:admin.{DOMAIN}"}
    (exposure,) = cli.run("exposures", org)
    assert (exposure["severity"], exposure["status"]) == ("high", "open")
    evidence = cli.run(
        "call", "GET", f"/organizations/{org}/exposures/{exposure['exposure_id']}/evidence"
    )
    assert evidence[0]["finding"]["url"] == f"https://admin.{DOMAIN}/login"
    resolved = cli.run(
        "exposure-resolve", org, exposure["exposure_id"], "--reason", "Moved behind the VPN"
    )
    assert resolved["status"] == "resolved"


def test_a_new_customer_from_signup_to_cleanup_through_the_cli(cli: Any) -> None:
    runner, client, dns_server = cli
    account = _sign_up(runner, client)
    demo_org = _explore_the_demo(runner)

    scan_id = _verify_and_scan(runner, dns_server)
    (own_org,) = [o["organization_id"] for o in runner.run("orgs") if not o["is_demo"]]
    _triage(runner, own_org)

    assert runner.run("monitor", DOMAIN)["domain"] == DOMAIN
    assert runner.run("feedback", "idea", "Loving the evidence view")["category"] == "idea"

    diagnostics = runner.run("diagnostics")
    assert diagnostics["account_id"] == account and diagnostics["hints"] == [
        "This month's scans are used up; the quota resets next month."
    ]
    assert diagnostics["recent_scans"][0]["scan_id"] == scan_id
    export = runner.run("call", "GET", "/account/export")
    assert len(export["feedback"]) == 1

    # Done exploring: the demo is deleted like any organization.
    assert "deletion_due_at" in runner.run("call", "DELETE", f"/organizations/{demo_org}")
