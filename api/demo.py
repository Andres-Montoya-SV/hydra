"""Productization Phase 13b: a demo organization from safe fixtures.

`POST /demo/organization` gives an account a clearly labelled organization
full of realistic data, so a beta customer can explore assets, evidence,
exposures and changes before verifying a real domain (decision 2026-10-02).

- **Only reserved names and addresses.** Every host is under a name
  reserved for documentation (RFC 2606: `example.com`, `example.net`,
  `example.org`; RFC 6761: `.test`), and every IP is in a documentation
  range (RFC 5737). Nothing here refers to anyone's real infrastructure,
  and a test checks every value.
- **Nothing is scanned.** The fixtures are written as one scan
  (`trigger_source = 'demo'`) in the owner's own results database. Its
  row is inserted already completed, never queued, and the scan worker's
  claim skips `demo` scans too, so no worker can ever run it. Then
  the ordinary EASM backfill builds the assets, observations, evidence,
  exposures and events from it. The demo therefore shows exactly what a
  real scan would, through the same deterministic engine.
- **Read-only, never scanned, not counted.** Every write to a demo
  organization is refused except deleting it (`api/auth.py`). Scans
  always target the account's default organization, which a demo
  organization never is. It doesn't count against the organization
  entitlement, and retention never purges its scan.
- **One per account.** Asking again returns the existing one.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from api.easm_backfill import run_easm_backfill_for_organization
from api.tenancy import account_db_path, account_settings
from core.assets import (
    DnsRecord,
    Finding,
    Host,
    HttpService,
    Port,
    ScanRun,
    TechnologyFinding,
    TlsCertificate,
)
from core.store import AssetStore

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings

DEMO_ORGANIZATION_NAME = "Demo: Example Corp (sample data)"
DEMO_ROOT_DOMAIN = "example.com"
DEMO_TRIGGER_SOURCE = "demo"
_STARTED_AT = "2026-09-01T00:00:00+00:00"


def _web(host: str, title: str, *, server: str, tech: str, version: str) -> HttpService:
    return HttpService(
        url=f"https://{host}",
        host=host,
        status_code=200,
        title=title,
        webserver=server,
        technologies=[TechnologyFinding(name=tech, source="httpx", confidence=90, version=version)],
    )


def _cert(host: str, *, sans: list[str], not_after: str, digit: str) -> TlsCertificate:
    return TlsCertificate(
        host=host,
        issuer="Example Documentation CA",
        subject=f"CN={host}",
        sans=sans,
        not_before="2026-06-01",
        not_after=not_after,
        fingerprint_sha256=digit * 64,
    )


def demo_hosts() -> list[Host]:
    """The fixture: a small company's external surface, with exposures of
    three severities and certificates with different expiry dates."""
    return [*_public_hosts(), _staging_host(), *_other_hosts()]


def _public_hosts() -> list[Host]:
    return [
        Host(
            domain="example.com",
            ips=["192.0.2.10"],
            dns_resolved=True,
            dns_records=[
                DnsRecord(host="example.com", record_type="A", value="192.0.2.10"),
                DnsRecord(host="example.com", record_type="MX", value="mail.example.com"),
            ],
            ports=[Port(host="example.com", port=443, service="https")],
            http_services=[
                _web("example.com", "Example Corp", server="nginx", tech="nginx", version="1.24.0")
            ],
            tls=_cert(
                "example.com",
                sans=["example.com", "www.example.com"],
                not_after="2027-03-01",
                digit="1",
            ),
        ),
        Host(
            domain="www.example.com",
            ips=["192.0.2.10"],
            dns_resolved=True,
            dns_records=[DnsRecord(host="www.example.com", record_type="A", value="192.0.2.10")],
            ports=[Port(host="www.example.com", port=443, service="https")],
        ),
        Host(
            domain="api.example.com",
            ips=["192.0.2.20"],
            dns_resolved=True,
            dns_records=[DnsRecord(host="api.example.com", record_type="A", value="192.0.2.20")],
            ports=[Port(host="api.example.com", port=443, service="https")],
            http_services=[
                _web("api.example.com", "Example API", server="envoy", tech="Envoy", version="1.30")
            ],
            tls=_cert(
                "api.example.com", sans=["api.example.com"], not_after="2026-10-20", digit="2"
            ),
        ),
    ]


def _staging_host() -> Host:
    return Host(
        domain="staging.example.com",
        ips=["198.51.100.20"],
        dns_resolved=True,
        dns_records=[DnsRecord(host="staging.example.com", record_type="A", value="198.51.100.20")],
        ports=[
            Port(host="staging.example.com", port=22, service="ssh"),
            Port(host="staging.example.com", port=443, service="https"),
        ],
        http_services=[
            _web(
                "staging.example.com",
                "Admin login",
                server="Apache",
                tech="WordPress",
                version="5.8",
            )
        ],
        findings=[
            Finding(
                host="staging.example.com",
                template_id="demo-exposed-admin-panel",
                severity="high",
                name="Admin interface exposed",
                url="https://staging.example.com/wp-admin",
                description="An administration login page is reachable from the internet.",
            ),
            Finding(
                host="staging.example.com",
                template_id="demo-outdated-cms",
                severity="medium",
                name="Outdated CMS version",
                url="https://staging.example.com",
                description="The CMS version is past its security support window.",
            ),
        ],
    )


def _other_hosts() -> list[Host]:
    return [
        Host(
            domain="mail.example.com",
            ips=["203.0.113.25"],
            dns_resolved=True,
            dns_records=[DnsRecord(host="mail.example.com", record_type="A", value="203.0.113.25")],
            ports=[Port(host="mail.example.com", port=25, service="smtp")],
        ),
        Host(
            domain="legacy.example-corp.test",
            ips=["203.0.113.80"],
            dns_resolved=True,
            ports=[Port(host="legacy.example-corp.test", port=8080, service="http")],
            findings=[
                Finding(
                    host="legacy.example-corp.test",
                    template_id="demo-directory-listing",
                    severity="low",
                    name="Directory listing enabled",
                    url="http://legacy.example-corp.test:8080/files/",
                    description="The web server lists the contents of a directory.",
                )
            ],
        ),
    ]


def create_demo_organization(
    control_db: ControlDB, api_settings: APISettings, account_id: str
) -> tuple[str, bool]:
    """`(organization_id, created)`. Seeds the fixtures only the first time."""
    organization_id, created = control_db.create_demo_organization(
        account_id=account_id, name=DEMO_ORGANIZATION_NAME
    )
    if created:
        _seed(control_db, api_settings, account_id, organization_id)
    return organization_id, created


def _seed(
    control_db: ControlDB, api_settings: APISettings, account_id: str, organization_id: str
) -> None:
    scan_id = secrets.token_hex(16)
    control_db.create_demo_scan(
        scan_id=scan_id,
        account_id=account_id,
        organization_id=organization_id,
        domain=DEMO_ROOT_DOMAIN,
        # What every scan records (api/routers/scans.py); the results
        # themselves are always opened via `account_db_path`.
        db_path=str(account_settings(api_settings, account_id).project_root),
    )
    hosts = demo_hosts()
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at=_STARTED_AT, targets=[DEMO_ROOT_DOMAIN]))
    for host in hosts:
        store.upsert_host(scan_id, host)
    store.finish_run(scan_id, host_count=len(hosts), alive_count=len(hosts), warnings=[], errors=[])
    run_easm_backfill_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
