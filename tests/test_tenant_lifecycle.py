"""Productization Phase 11c: tenant export and deletion."""

from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from _verified_account import create_verified_account
from fastapi.testclient import TestClient
from test_api_easm import _seed_account_with_domain_asset
from test_api_exposure_operations import _seed_exposure

import api.control_db as control_db_module
import api.routers.webhooks as webhooks_router
from api import tenants
from api.control_db import ControlDB
from api.db import SqliteBackend
from api.main import create_app
from api.pg_transfer import CONTROL_TABLES
from api.settings import APISettings
from api.tenant_export import ORGANIZATION_DATASETS, write_organization_export
from api.tenant_lifecycle import (
    purge_account_now,
    purge_organization_now,
    run_tenant_deletion_job,
)
from core.store import RUN_PURGE_STATEMENTS, AssetStore


def _settings(tmp_path: Path, **overrides: Any) -> APISettings:
    return APISettings(
        data_dir=tmp_path / "api",
        max_concurrent_scans=0,
        account_creation_rate_limit_per_ip_per_day=50,
        **overrides,
    )


@pytest.fixture
def client(tmp_path: Path) -> Any:
    with TestClient(create_app(_settings(tmp_path))) as test_client:
        yield test_client


def _counts(db: ControlDB, organization_id: str) -> dict[str, int]:
    manifest = write_organization_export(db, organization_id, io.BytesIO())
    return {d["name"]: d["rows"] for d in manifest["datasets"]}


def _schema(path: Path) -> dict[str, tuple[set[str], set[str]]]:
    """table -> (columns, referenced tables)."""
    with closing(sqlite3.connect(path)) as conn:
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
        ]
        return {
            name: (
                {r[1] for r in conn.execute("SELECT * FROM pragma_table_info(?)", (name,))},
                {r[2] for r in conn.execute("SELECT * FROM pragma_foreign_key_list(?)", (name,))},
            )
            for name in names
        }


def _children_first(order: list[str], schema: dict[str, tuple[set[str], set[str]]]) -> None:
    for table in order:
        for parent in schema[table][1] & set(order):
            if parent != table:
                assert order.index(table) < order.index(parent), (table, parent)


class TestCatalogs:
    def test_the_run_purge_covers_every_run_table_children_first(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        store.intel_connection().close()
        schema = _schema(tmp_path / "recon.db")
        order = [table for table, _ in RUN_PURGE_STATEMENTS]
        assert set(order) == {t for t, (cols, _) in schema.items() if "run_id" in cols}
        _children_first(order, schema)
        for table, statement in RUN_PURGE_STATEMENTS:
            assert statement.split() == ["DELETE", "FROM", table, "WHERE", "run_id", "=", "?"]

    def test_the_organization_purge_and_export_cover_every_organization_table(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "control.db"
        ControlDB(path, backend=SqliteBackend(path))
        schema = _schema(path)
        org_tables = {t for t, (cols, _) in schema.items() if "organization_id" in cols}
        purge = [t for t, _ in control_db_module._ORGANIZATION_PURGE_STATEMENTS]
        # The audit log is kept (pseudonymized); deliveries are reached via their event.
        assert set(purge) == (org_tables - {"security_audit_log"}) | {"integration_deliveries"}
        _children_first(purge, schema)
        assert set(ORGANIZATION_DATASETS) == org_tables | {"integration_deliveries"}

    def test_every_control_table_has_a_fate(self) -> None:
        purged = {t for t, _ in control_db_module._ORGANIZATION_PURGE_STATEMENTS}
        purged |= {t for t, _ in control_db_module._ACCOUNT_PURGE_STATEMENTS}
        # Kept on purpose: tombstone, billing and audit records (pseudonymized),
        # IP-keyed abuse counters that belong to no tenant.
        kept = {
            "accounts",
            "subscriptions",
            "wompi_unmatched_payments",
            "wompi_webhook_events",
            "security_audit_log",
            "account_creation_attempts",
            "rate_limit_buckets",
        }
        assert set(CONTROL_TABLES) <= purged | kept


def _two_tenants(client: TestClient) -> dict[str, Any]:
    key_a, account_a, org_a, _ = _seed_account_with_domain_asset(
        client, email="a@example.com", domain="a.example"
    )
    key_b, account_b, org_b, _ = _seed_account_with_domain_asset(
        client, email="b@example.com", domain="b.example"
    )
    _seed_exposure(client, account_a, org_a, run_id="run-a-exposure")
    return {"a": (key_a, account_a, org_a), "b": (key_b, account_b, org_b)}


class TestOrganizationPurge:
    def test_removes_everything_of_one_organization_and_nothing_else(
        self, client: TestClient
    ) -> None:
        db: ControlDB = client.app.state.control_db
        settings: APISettings = client.app.state.api_settings
        tenants_ = _two_tenants(client)
        _, account_a, org_a = tenants_["a"]
        _, _, org_b = tenants_["b"]
        before_a, before_b = _counts(db, org_a), _counts(db, org_b)
        scans_a = db.organization_scans(org_a)
        assert before_a["assets"] and before_a["observations"] and before_a["exposures"]

        purge_organization_now(db, settings, org_a)

        after_a = _counts(db, org_a)
        assert {k: v for k, v in after_a.items() if v} == {
            "security_audit_log": after_a["security_audit_log"]
        }
        assert _counts(db, org_b) == {
            **before_b,
            "security_audit_log": _counts(db, org_b)["security_audit_log"],
        }
        store = AssetStore(settings.account_root(account_a) / "output" / "recon.db")
        assert all(store.get_run(scan_id) is None for _, scan_id in scans_a)
        assert db.get_organization(org_a) is None

    def test_the_kept_audit_events_lose_their_client_address(self, client: TestClient) -> None:
        db: ControlDB = client.app.state.control_db
        key, _, org = _two_tenants(client)["a"]
        client.get(f"/organizations/{org}/export", headers={"X-API-Key": key})
        purge_organization_now(db, client.app.state.api_settings, org)
        events = db.list_security_events_for_organization(org, limit=50, offset=0)
        assert {e.action for e in events} >= {"organization.exported", "organization.purged"}
        assert all(e.client_ip is None for e in events)


class TestScheduling:
    def test_owner_schedules_cancels_and_the_job_waits_for_the_due_date(
        self, client: TestClient
    ) -> None:
        db: ControlDB = client.app.state.control_db
        settings: APISettings = client.app.state.api_settings
        key, _, org = _two_tenants(client)["a"]
        headers = {"X-API-Key": key}

        first = client.delete(f"/organizations/{org}", headers=headers)
        again = client.delete(f"/organizations/{org}", headers=headers)
        assert first.status_code == again.status_code == 202
        due = datetime.fromisoformat(first.json()["deletion_due_at"])
        assert again.json() == first.json()  # idempotent: the original date stands
        assert timedelta(days=29) < due - datetime.now(timezone.utc) <= timedelta(days=30)

        assert run_tenant_deletion_job(api_settings=settings, control_db=db).organizations == 0
        assert (
            client.post(f"/organizations/{org}/deletion/cancel", headers=headers).status_code == 204
        )
        assert (
            client.post(f"/organizations/{org}/deletion/cancel", headers=headers).status_code == 404
        )

        client.delete(f"/organizations/{org}", headers=headers)
        later = due + timedelta(days=1)
        assert (
            run_tenant_deletion_job(api_settings=settings, control_db=db, now=later).organizations
            == 1
        )
        assert db.get_organization(org) is None

    def test_a_dry_run_deployment_purges_nothing(self, client: TestClient, tmp_path: Path) -> None:
        db: ControlDB = client.app.state.control_db
        key, _, org = _two_tenants(client)["a"]
        client.delete(f"/organizations/{org}", headers={"X-API-Key": key})
        later = datetime.now(timezone.utc) + timedelta(days=31)
        dry = _settings(tmp_path, retention_purge_dry_run=True)
        assert (
            run_tenant_deletion_job(api_settings=dry, control_db=db, now=later).organizations == 0
        )
        assert db.get_organization(org) is not None

    def test_only_owners_and_never_outsiders(self, client: TestClient) -> None:
        owner, _, org = _two_tenants(client)["a"]
        viewer_key, viewer_id = create_verified_account(client)
        outsider_key, _ = create_verified_account(client)
        client.post(
            f"/organizations/{org}/members",
            headers={"X-API-Key": owner},
            json={"account_id": viewer_id, "role": "viewer"},
        )
        for path, method in (
            (f"/organizations/{org}", "delete"),
            (f"/organizations/{org}/deletion/cancel", "post"),
            (f"/organizations/{org}/export", "get"),
        ):
            call = getattr(client, method)
            assert call(path, headers={"X-API-Key": viewer_key}).status_code == 403
            assert call(path, headers={"X-API-Key": outsider_key}).status_code == 404


class TestAccountPurge:
    def test_sole_owned_organizations_go_shared_ones_stay_and_a_tombstone_remains(
        self, client: TestClient
    ) -> None:
        db: ControlDB = client.app.state.control_db
        settings: APISettings = client.app.state.api_settings
        tenants_ = _two_tenants(client)
        key_a, account_a, org_a = tenants_["a"]
        key_b, account_b, org_b = tenants_["b"]
        # A co-owns B's organization; B stays its owner.
        client.post(
            f"/organizations/{org_b}/members",
            headers={"X-API-Key": key_b},
            json={"account_id": account_a, "role": "owner"},
        )
        payment = db.create_unmatched_payment(
            transaction_id="txn-1",
            payer_email="a@example.com",
            product_name="Hydra Pro",
            amount=10.0,
            raw_body='{"email": "a@example.com"}',
        )
        db.resolve_unmatched_payment(payment, account_id=account_a)

        assert client.delete("/account", headers={"X-API-Key": key_a}).status_code == 202
        purge_account_now(db, settings, account_a)

        assert db.get_organization(org_a) is None
        assert db.get_organization(org_b) is not None
        assert [m[0] for m in db.list_members_for_organization(org_b)] == [account_b]
        assert not db.account_exists(account_a) and db.get_account(account_a) is None
        assert client.get("/organizations", headers={"X-API-Key": key_a}).status_code == 401
        assert not settings.account_root(account_a).exists()
        with db._connect() as conn:
            tombstone = conn.execute(
                "SELECT email, deleted_at FROM accounts WHERE account_id = ?", (account_a,)
            ).fetchone()
            billing = conn.execute(
                "SELECT payer_email, raw_body FROM wompi_unmatched_payments WHERE unmatched_id = ?",
                (payment,),
            ).fetchone()
            ips = conn.execute(
                "SELECT client_ip FROM security_audit_log WHERE subject_account_id = ?",
                (account_a,),
            ).fetchall()
        assert tombstone[0] is None and tombstone[1]
        assert tuple(billing) == (None, "{}")
        assert ips and all(row[0] is None for row in ips)

    def test_self_service_cancel(self, client: TestClient) -> None:
        key, _ = create_verified_account(client)
        headers = {"X-API-Key": key}
        assert client.delete("/account", headers=headers).status_code == 202
        assert client.post("/account/deletion/cancel", headers=headers).status_code == 204
        assert client.post("/account/deletion/cancel", headers=headers).status_code == 404


class TestExport:
    def test_the_archive_is_complete_verifiable_and_secret_free(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def allow(url: str) -> tuple[bool, str, str]:
            return True, "", "93.184.216.34"

        monkeypatch.setattr(webhooks_router, "validate_webhook_destination", allow)
        key, _, org = _two_tenants(client)["a"]
        headers = {"X-API-Key": key}
        hook = client.post(
            "/webhooks",
            headers=headers,
            json={"url": "https://hooks.example.com/h", "event_types": ["monitoring.changed"]},
        ).json()

        response = client.get(f"/organizations/{org}/export", headers=headers)

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        manifest = json.loads(archive.read("manifest.json"))
        assert [d["name"] for d in manifest["datasets"]] == list(ORGANIZATION_DATASETS)
        for dataset in manifest["datasets"]:
            data = archive.read(f"{dataset['name']}.json")
            assert len(json.loads(data)) == dataset["rows"]
        assert json.loads(archive.read("webhooks.json"))  # exported, minus its secret
        everything = b"".join(archive.read(name) for name in archive.namelist())
        assert hook["secret"].encode() not in everything and b"enc:v1:" not in everything

    def test_too_large_for_http_is_a_413(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, export_max_bytes=200)
        with TestClient(create_app(settings)) as small:
            key, _, org = _two_tenants(small)["a"]
            response = small.get(f"/organizations/{org}/export", headers={"X-API-Key": key})
        assert response.status_code == 413 and "operator" in response.json()["detail"]

    def test_the_account_export(self, client: TestClient) -> None:
        key, account_id, org = _two_tenants(client)["a"]
        body = client.get("/account/export", headers={"X-API-Key": key}).json()
        assert body["account"]["email"] == "a@example.com"
        assert {"organization_id": org, "role": "owner"} in body["memberships"]
        assert body["api_keys"] and "verify_hash" not in body["api_keys"][0]
        assert all("details" in event for event in body["security_events"])


class TestHostCli:
    def test_schedule_cancel_export_and_purge(
        self,
        client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        db: ControlDB = client.app.state.control_db
        settings: APISettings = client.app.state.api_settings
        monkeypatch.setattr(tenants, "_open", lambda: (settings, db))
        _, account_a, org_a = _two_tenants(client)["a"]
        archive = tmp_path / "org.zip"

        assert tenants.main(["delete-organization", org_a]) == 0
        assert tenants.main(["pending"]) == 0
        assert tenants.main(["cancel-organization", org_a]) == 0
        assert tenants.main(["export-organization", org_a, str(archive)]) == 0
        assert tenants.main(["export-organization", org_a, str(archive)]) == 1  # exists
        assert zipfile.ZipFile(archive).read("manifest.json")
        assert tenants.main(["delete-account", "A@Example.com", "--now"]) == 0
        assert db.get_organization(org_a) is None and not db.account_exists(account_a)
        assert tenants.main(["delete-organization", "nope"]) == 1

        out = capsys.readouterr().out
        assert f"organization {org_a}" in out and "Purged" in out
