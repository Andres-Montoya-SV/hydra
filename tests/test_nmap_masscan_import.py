"""Fase 11 (EASM roadmap) — the real, DB-backed half of the Nmap/Masscan
importers: `import_nmap_xml`/`import_masscan_json` running against real
organizations, proving the phase's own required invariants: importing
the same artifact twice never duplicates anything, `Nmap imported IP !=
authorized target`, `Masscan imported port != authorization`, malformed
data is rejected safely, and no organization can import into another's
data.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import ControlDB
from api.nmap_masscan_import import (
    MAX_ARTIFACT_BYTES,
    ImportValidationError,
    import_masscan_json,
    import_nmap_xml,
)
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host
from core.store import AssetStore, ScanRun

_NMAP_XML_ONE_HOST = b"""<nmaprun>
<host><address addr="198.51.100.10" addrtype="ipv4"/>
<hostnames><hostname name="scanned.example.com" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh"/></port></ports>
</host>
</nmaprun>"""

_MASSCAN_JSON_ONE_HOST = (
    b'[{"ip": "198.51.100.20", "ports": ['
    b'{"port": 3389, "proto": "tcp", "status": "open", "service": {"name": "ms-wbt-server"}}'
    b"]}]"
)


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _seed_real_scanned_domain(
    control_db: ControlDB,
    api_settings: APISettings,
    *,
    account_id: str,
    organization_id: str,
    domain: str,
) -> None:
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain=domain,
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
    store.upsert_host(scan_id, Host(domain=domain, discovery_sources=["dnsx"]))
    control_db.update_scan_status(scan_id, "completed")
    backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )


class TestImportedIpIsNeverAuthorized:
    def test_nmap_imported_ip_never_becomes_an_asset_or_scan_target(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]

        summary = import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=_NMAP_XML_ONE_HOST,
        )
        assert summary.ingest is not None
        assert summary.ingest.candidates_created == 2  # the IP + the resolved hostname

        assert control_db.list_assets_for_organization(organization_id) == []
        candidates = control_db.list_candidate_assets_for_organization(organization_id)
        by_type = {(c.candidate_type, c.normalized_value): c for c in candidates}
        ip_candidate = by_type[("IP", "198.51.100.10")]
        assert ip_candidate.authorization_status == "DENY"
        assert ip_candidate.scope_status == "UNKNOWN"
        assert "22/tcp" in ip_candidate.reason or "22/tcp" in (ip_candidate.reason or "")

        assert control_db.get_verified_domains_for_account(account_id) == []
        assert (
            control_db.list_due_active_monitoring_page(
                due_before="2099-01-01T00:00:00+00:00", cursor=None, limit=100
            )
            == []
        )

    def test_masscan_imported_port_never_becomes_authorization(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]

        summary = import_masscan_json(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            json_bytes=_MASSCAN_JSON_ONE_HOST,
        )
        assert summary.ingest is not None
        assert summary.ingest.candidates_created == 1  # masscan reports no hostnames

        assert control_db.list_assets_for_organization(organization_id) == []
        candidates = control_db.list_candidate_assets_for_organization(organization_id)
        assert len(candidates) == 1
        assert candidates[0].candidate_type == "IP"
        assert candidates[0].normalized_value == "198.51.100.20"
        assert candidates[0].authorization_status == "DENY"


class TestHostnameCorroboratesAnAlreadyKnownDomain:
    def test_a_resolved_hostname_that_is_already_a_known_asset_gets_evidence_not_a_candidate(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_real_scanned_domain(
            control_db,
            api_settings,
            account_id=account_id,
            organization_id=organization_id,
            domain="scanned.example.com",
        )

        summary = import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=_NMAP_XML_ONE_HOST,
        )
        assert summary.ingest is not None
        # The IP is still a fresh, unauthorized candidate...
        assert summary.ingest.candidates_created == 1
        # ...but the hostname, already known and owned, gets corroborating evidence instead.
        assert summary.ingest.observations_recorded_on_known_assets == 1

        candidates = control_db.list_candidate_assets_for_organization(organization_id)
        assert [c.candidate_type for c in candidates] == ["IP"]


class TestImportingTheSameArtifactTwiceNeverDuplicates:
    def test_repeat_nmap_import_produces_zero_new_rows(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]

        first = import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=_NMAP_XML_ONE_HOST,
        )
        assert first.already_imported is False
        second = import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=_NMAP_XML_ONE_HOST,
        )
        assert second.already_imported is True
        assert second.ingest is not None
        assert second.ingest.candidates_created == 0
        assert second.ingest.batch_id == first.ingest.batch_id  # type: ignore[union-attr]

        assert len(control_db.list_candidate_assets_for_organization(organization_id)) == 2
        assert len(control_db.list_observation_batches_for_organization(organization_id)) == 1

    def test_a_byte_for_byte_different_artifact_creates_a_separate_batch(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=_NMAP_XML_ONE_HOST,
        )
        different_xml = _NMAP_XML_ONE_HOST.replace(b"198.51.100.10", b"198.51.100.99")
        import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=different_xml,
        )
        assert len(control_db.list_observation_batches_for_organization(organization_id)) == 2


class TestMalformedAndOversizedArtifactsAreRejectedSafely:
    def test_malformed_xml_is_rejected_with_zero_writes(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner6@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        with pytest.raises(ImportValidationError):
            import_nmap_xml(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                xml_bytes=b"<nmaprun><host>not closed",
            )
        assert control_db.list_candidate_assets_for_organization(organization_id) == []
        assert control_db.list_observation_batches_for_organization(organization_id) == []

    def test_malformed_masscan_json_is_rejected_with_zero_writes(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner7@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        with pytest.raises(ImportValidationError):
            import_masscan_json(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                json_bytes=b"{not valid json,,,",
            )
        assert control_db.list_observation_batches_for_organization(organization_id) == []

    def test_unsupported_schema_is_rejected(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner8@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        with pytest.raises(ImportValidationError):
            import_masscan_json(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                json_bytes=b'{"not": "a masscan array"}',
            )

    def test_empty_artifact_is_rejected(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner9@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        with pytest.raises(ImportValidationError):
            import_nmap_xml(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                xml_bytes=b"",
            )

    def test_oversized_artifact_is_rejected_before_parsing(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner10@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        oversized = b"<nmaprun>" + b" " * (MAX_ARTIFACT_BYTES + 1) + b"</nmaprun>"
        with pytest.raises(ImportValidationError):
            import_nmap_xml(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                xml_bytes=oversized,
            )
        assert control_db.list_observation_batches_for_organization(organization_id) == []

    def test_gzip_magic_bytes_are_rejected_without_attempting_decompression(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner11@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        with pytest.raises(ImportValidationError, match="compressed"):
            import_nmap_xml(
                control_db=control_db,
                organization_id=organization_id,
                account_id=account_id,
                xml_bytes=b"\x1f\x8b\x08\x00" + b"\x00" * 20,
            )

    def test_a_host_with_an_impossible_ip_is_skipped_the_rest_of_the_batch_still_processes(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner12@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        xml = b"""<nmaprun>
        <host><address addr="999.999.999.999" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
        <host><address addr="198.51.100.50" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
        </nmaprun>"""
        summary = import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=xml,
        )
        assert summary.hosts_skipped_invalid_ip == 1
        candidates = control_db.list_candidate_assets_for_organization(organization_id)
        assert [c.normalized_value for c in candidates] == ["198.51.100.50"]


class TestDuplicateRecordsWithinOneArtifactDoNotDuplicateCandidates:
    def test_the_same_ip_reported_by_two_host_blocks_in_one_file_is_one_candidate(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner13@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        xml = b"""<nmaprun>
        <host><address addr="198.51.100.60" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
        <host><address addr="198.51.100.60" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>
        </nmaprun>"""
        import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=xml,
        )
        candidates = control_db.list_candidate_assets_for_organization(organization_id)
        assert len(candidates) == 1


class TestDryRunNeverWritesToTheDatabase:
    def test_dry_run_reports_counts_but_creates_nothing(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner14@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        summary = import_nmap_xml(
            control_db=control_db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=_NMAP_XML_ONE_HOST,
            dry_run=True,
        )
        assert summary.dry_run is True
        assert summary.hosts_parsed == 1
        assert summary.ingest is None
        assert control_db.list_candidate_assets_for_organization(organization_id) == []
        assert control_db.list_observation_batches_for_organization(organization_id) == []


class TestCrossOrganizationIsolation:
    def test_importing_into_organization_a_never_appears_in_organization_b(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_a = control_db.create_account(email="orga@example.com")
        account_b = control_db.create_account(email="orgb@example.com")
        org_a, _ = control_db.list_organizations_for_account(account_a)[0]
        org_b, _ = control_db.list_organizations_for_account(account_b)[0]

        import_nmap_xml(
            control_db=control_db,
            organization_id=org_a,
            account_id=account_a,
            xml_bytes=_NMAP_XML_ONE_HOST,
        )

        assert control_db.list_candidate_assets_for_organization(org_a) != []
        assert control_db.list_candidate_assets_for_organization(org_b) == []
        assert control_db.list_observation_batches_for_organization(org_b) == []


@pytest.mark.parametrize(
    ("importer", "payload"),
    [
        ("import_nmap_xml", b"<nmaprun>\x00</nmaprun>"),
        ("import_masscan_json", b'[{"ip": "1.2.3.4\\u0000"}]'),
    ],
)
def test_a_report_with_a_nul_character_is_refused(
    tmp_path: Path, importer: str, payload: bytes
) -> None:
    """Phase 11g: NUL never belongs in a report and PostgreSQL refuses it."""
    import api.nmap_masscan_import as imports

    db = ControlDB(tmp_path / "control.db")
    keyword = "xml_bytes" if importer == "import_nmap_xml" else "json_bytes"
    with pytest.raises(imports.ImportValidationError, match="NUL"):
        getattr(imports, importer)(
            control_db=db, organization_id="o", account_id="a", dry_run=True, **{keyword: payload}
        )
