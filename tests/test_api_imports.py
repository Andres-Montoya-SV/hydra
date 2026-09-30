"""POST /organizations/{org}/imports/{nmap|masscan} and GET .../imports:
the API over Fase 11's scan-report importer. Imported hosts are candidates,
never authorized targets; uploads are owner-only and size-bounded."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest
from _org_helpers import api_client, verified_owner
from _verified_account import create_verified_account
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from api import nmap_masscan_import
from api.routers.imports import read_bounded_body

NMAP_XML = b"""<nmaprun>
<host><address addr="198.51.100.10" addrtype="ipv4"/>
<hostnames><hostname name="scanned.example.com" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh"/></port></ports>
</host>
</nmaprun>"""
MASSCAN_JSON = (
    b'[{"ip": "198.51.100.20", "ports": ['
    b'{"port": 3389, "proto": "tcp", "status": "open", "service": {"name": "ms-wbt-server"}}'
    b"]}]"
)
XXE = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>"""


def _upload(
    client: TestClient, headers: dict[str, str], org: str, source: str, body: bytes, **params
):  # noqa: ANN003, ANN202
    return client.post(
        f"/organizations/{org}/imports/{source}", headers=headers, content=body, params=params
    )


def _candidates(client: TestClient, headers: dict[str, str], org: str) -> set[str]:
    rows = client.get(f"/organizations/{org}/candidate-assets", headers=headers).json()
    return {row["normalized_value"] for row in rows}


class TestImport:
    def test_nmap_hosts_become_candidates_never_assets(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            body = _upload(client, headers, org, "nmap", NMAP_XML).json()

            assert (body["hosts_parsed"], body["candidates_created"]) == (1, 2)
            assert body["batch_id"]
            assert {"198.51.100.10", "scanned.example.com"} <= _candidates(client, headers, org)
            assert client.get(f"/organizations/{org}/assets", headers=headers).json() == []

    def test_masscan_import_and_listing(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)

            body = _upload(client, headers, org, "masscan", MASSCAN_JSON).json()
            batches = client.get(f"/organizations/{org}/imports", headers=headers).json()

            assert body["candidates_created"] == 1
            assert [(b["source"], b["imported_by_account_id"]) for b in batches] == [
                ("MASSCAN", account_id)
            ]
            assert batches[0]["artifact_sha256"]

    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            body = _upload(client, headers, org, "nmap", NMAP_XML, dry_run=True).json()

            assert (body["dry_run"], body["hosts_parsed"], body["batch_id"]) == (True, 1, None)
            assert _candidates(client, headers, org) == set()

    def test_reimporting_the_same_report_creates_nothing_new(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            first = _upload(client, headers, org, "nmap", NMAP_XML).json()

            again = _upload(client, headers, org, "nmap", NMAP_XML).json()

            assert (again["already_imported"], again["candidates_created"]) == (True, 0)
            assert again["batch_id"] == first["batch_id"]


class TestHostileInput:
    def test_oversized_reports_are_refused_before_parsing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(nmap_masscan_import, "MAX_ARTIFACT_BYTES", 64)
        monkeypatch.setattr("api.routers.imports.MAX_ARTIFACT_BYTES", 64)
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            resp = _upload(client, headers, org, "nmap", NMAP_XML)

            assert resp.status_code == 413
            assert _candidates(client, headers, org) == set()

    def test_malformed_xxe_compressed_and_empty_reports_are_422(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            codes = [
                _upload(client, headers, org, "nmap", body).status_code
                for body in (b"<not-closed", XXE, gzip.compress(NMAP_XML), b"")
            ]

            assert codes == [422, 422, 422, 422]
            assert _candidates(client, headers, org) == set()

    def test_unknown_source_is_422(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            assert _upload(client, headers, org, "ivre", NMAP_XML).status_code == 422


class TestRolesAndTenancy:
    def test_viewer_can_list_but_not_import(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            _, _, org = verified_owner(client)
            viewer_key, viewer_id = create_verified_account(client)
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            viewer = {"X-API-Key": viewer_key}

            assert _upload(client, viewer, org, "nmap", NMAP_XML).status_code == 403
            assert client.get(f"/organizations/{org}/imports", headers=viewer).status_code == 200

    def test_foreign_account_gets_404_and_writes_nothing(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            owner, _, org = verified_owner(client)
            foreign, _, _ = verified_owner(client)

            upload = _upload(client, foreign, org, "nmap", NMAP_XML)
            listing = client.get(f"/organizations/{org}/imports", headers=foreign)

            assert (upload.status_code, listing.status_code) == (404, 404)
            assert client.get(f"/organizations/{org}/imports", headers=owner).json() == []


def _chunked_request(chunks: list[bytes]):  # noqa: ANN202
    """A request with no Content-Length whose body arrives in chunks."""
    messages = [
        {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
        for i, chunk in enumerate(chunks)
    ]

    async def receive() -> dict:
        return messages.pop(0)

    return Request({"type": "http", "method": "POST", "headers": []}, receive)


class TestBoundedBody:
    async def test_a_chunked_body_is_cut_off_past_the_limit(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await read_bounded_body(_chunked_request([b"a" * 40, b"b" * 40, b"c" * 40]), 64)

        assert exc.value.status_code == 413

    async def test_a_chunked_body_within_the_limit_is_returned_whole(self) -> None:
        body = await read_bounded_body(_chunked_request([b"a" * 30, b"b" * 30]), 64)

        assert body == b"a" * 30 + b"b" * 30
