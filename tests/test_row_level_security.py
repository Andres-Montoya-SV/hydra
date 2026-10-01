"""Productization Phase 10c: row-level security and the connection pool.

The application's organization checks (api/routers/org_access.py) remain
the first line; these tests prove the second one: on Postgres, once a
request is scoped to an organization, the database itself refuses to show
or accept another organization's rows — even if a query forgets its
`WHERE organization_id = ?`.
"""

from __future__ import annotations

import contextvars
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypeVar

import pytest
from _pg_mode import POSTGRES_URL
from fastapi.testclient import TestClient
from test_api_easm import _seed_account_with_domain_asset

import api.control_db as control_db_module
from api.control_db import ControlDB
from api.db import PoolConfig, PostgresDialect, request_organization, set_request_organization
from api.main import create_app
from api.settings import APISettings, load_api_settings

on_postgres = pytest.mark.skipif(not POSTGRES_URL, reason="needs HYDRA_TEST_DATABASE_URL")

T = TypeVar("T")


def _as_organization(organization_id: str, fn: Callable[[], T]) -> T:
    """Runs `fn` the way a request runs after its membership check."""

    def scoped() -> T:
        set_request_organization(organization_id)
        return fn()

    return contextvars.copy_context().run(scoped)


def _two_organizations(db: ControlDB) -> tuple[str, str]:
    orgs = []
    for email in ("a@example.com", "b@example.com"):
        account = db.create_account(email=email)
        org, _ = db.list_organizations_for_account(account)[0]
        db.add_scope_exclusion(
            organization_id=org, account_id=account, pattern=f"x.{email}", reason="r"
        )
        orgs.append(org)
    return orgs[0], orgs[1]


def _visible_orgs(db: ControlDB) -> set[str]:
    with db._connect() as conn:
        rows = conn.execute("SELECT organization_id FROM organization_scope_exclusions")
        return {row[0] for row in rows}


class TestRequestScope:
    def test_the_scope_belongs_to_the_context_that_set_it(self) -> None:
        assert request_organization() is None
        assert _as_organization("org-a", request_organization) == "org-a"
        assert request_organization() is None


class TestPoolSettings:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("MIN", "MAX", "TIMEOUT"):
            monkeypatch.delenv(f"HYDRA_API_DATABASE_POOL_{name}", raising=False)
        assert load_api_settings().database_pool == PoolConfig()

    def test_values_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HYDRA_API_DATABASE_POOL_MIN", "2")
        monkeypatch.setenv("HYDRA_API_DATABASE_POOL_MAX", "20")
        monkeypatch.setenv("HYDRA_API_DATABASE_POOL_TIMEOUT", "5")
        assert load_api_settings().database_pool == PoolConfig(2, 20, 5.0)

    @pytest.mark.parametrize(
        ("low", "high", "timeout"), [("5", "2", "1"), ("0", "2", "1"), ("1", "2", "0")]
    )
    def test_inconsistent_values_are_refused(
        self, monkeypatch: pytest.MonkeyPatch, low: str, high: str, timeout: str
    ) -> None:
        monkeypatch.setenv("HYDRA_API_DATABASE_POOL_MIN", low)
        monkeypatch.setenv("HYDRA_API_DATABASE_POOL_MAX", high)
        monkeypatch.setenv("HYDRA_API_DATABASE_POOL_TIMEOUT", timeout)
        with pytest.raises(ValueError, match="POOL"):
            load_api_settings()


@on_postgres
class TestPolicies:
    def test_every_organization_table_is_forced_under_the_policy(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "c.db")
        with db._connect() as conn:
            rows = conn.execute(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                "EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = current_schema() "
                "AND p.tablename = c.relname AND p.policyname = 'hydra_organization_isolation') "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' "
                "WHERE n.nspname = current_schema() AND c.relkind = 'r'"
            ).fetchall()
        assert len(rows) >= 25  # organizations, assets, exposures, scans, ...
        assert {row[0] for row in rows} >= {"organizations", "assets", "exposures", "scans"}
        assert all(row[1] and row[2] and row[3] for row in rows), rows

    def test_reinitializing_is_idempotent(self, tmp_path: Path) -> None:
        ControlDB(tmp_path / "c.db")
        db = ControlDB(tmp_path / "c.db")
        with db._connect() as conn:
            count = conn.execute(
                "SELECT count(*) FROM pg_policies WHERE schemaname = current_schema()"
            ).fetchone()[0]
        assert count >= 25

    def test_the_suite_role_is_subject_to_row_security(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "c.db")
        with db._connect() as conn:
            assert PostgresDialect().row_security_enforced(conn)


@on_postgres
class TestIsolation:
    def test_reads_are_limited_to_the_request_organization(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "c.db")
        org_a, org_b = _two_organizations(db)

        assert _visible_orgs(db) == {org_a, org_b}  # no request scope: workers etc.
        assert _as_organization(org_a, lambda: _visible_orgs(db)) == {org_a}
        assert _as_organization(org_b, lambda: _visible_orgs(db)) == {org_b}

    def test_writes_into_another_organization_are_refused(self, tmp_path: Path) -> None:
        import psycopg

        db = ControlDB(tmp_path / "c.db")
        org_a, org_b = _two_organizations(db)

        def write_into_b() -> None:
            with db._connect() as conn:
                conn.execute(
                    "UPDATE organization_scope_exclusions SET reason = 'moved' "
                    "WHERE organization_id = ?",
                    (org_b,),
                )
                conn.execute(
                    "INSERT INTO organization_scope_exclusions (exclusion_id, organization_id, "
                    "pattern, reason, created_by_account_id, created_at) "
                    "VALUES ('x', ?, 'p', 'r', 'acct', '2026-01-01T00:00:00+00:00')",
                    (org_b,),
                )

        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            _as_organization(org_a, write_into_b)
        with db._connect() as conn:
            reasons = {
                row[0]
                for row in conn.execute(
                    "SELECT reason FROM organization_scope_exclusions WHERE organization_id = ?",
                    (org_b,),
                )
            }
        assert reasons == {"r"}  # the UPDATE matched nothing; the INSERT was refused

    def test_the_scope_never_outlives_its_transaction_on_a_pooled_connection(
        self, tmp_path: Path
    ) -> None:
        db = ControlDB(tmp_path / "c.db", pool=PoolConfig(min_size=1, max_size=1))
        org_a, org_b = _two_organizations(db)

        assert _as_organization(org_a, lambda: _visible_orgs(db)) == {org_a}
        # The single pooled connection, reused without a scope:
        assert _visible_orgs(db) == {org_a, org_b}
        with db._connect() as conn:
            setting = conn.execute("SELECT current_setting('hydra.organization_id', true)")
            assert setting.fetchone()[0] in ("", None)

    def test_a_query_that_forgets_its_organization_filter_still_cannot_leak(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Defense in depth, end to end through the API: simulate an
        application bug (the assets listing drops its organization
        filter) and the database still returns only the caller's rows."""

        def buggy_listing(self: ControlDB, organization_id: str, **_: Any) -> list[Any]:
            del organization_id
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM assets").fetchall()
            return [control_db_module._asset_record_from_row(row) for row in rows]

        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            key_a, _, org_a, asset_a = _seed_account_with_domain_asset(
                client, email="a@example.com", domain="a.example"
            )
            _, _, _, asset_b = _seed_account_with_domain_asset(
                client, email="b@example.com", domain="b.example"
            )
            monkeypatch.setattr(ControlDB, "list_assets_for_organization", buggy_listing)

            response = client.get(f"/organizations/{org_a}/assets", headers={"X-API-Key": key_a})

        assert response.status_code == 200
        returned = [asset["asset_id"] for asset in response.json()]
        assert returned == [asset_a] and asset_b not in returned


@on_postgres
class TestPoolUnderConcurrentWriters:
    def test_more_writers_than_connections_all_complete(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "c.db", pool=PoolConfig(min_size=1, max_size=2, timeout=30))
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(lambda i: db.create_account(email=f"w{i}@example.com"), range(16)))
        assert len(set(ids)) == 16
        assert all(db.get_account(account_id) is not None for account_id in ids)

    def test_an_exhausted_pool_fails_after_its_timeout_not_forever(self, tmp_path: Path) -> None:
        from psycopg_pool import PoolTimeout

        db = ControlDB(tmp_path / "c.db", pool=PoolConfig(min_size=1, max_size=1, timeout=0.5))
        errors: list[BaseException] = []
        held = threading.Event()
        release = threading.Event()

        def hold() -> None:
            with db._connect():
                held.set()
                release.wait(10)

        holder = threading.Thread(target=hold)
        holder.start()
        held.wait(10)
        try:
            db.get_account("nobody")
        except PoolTimeout as exc:
            errors.append(exc)
        finally:
            release.set()
            holder.join()
        assert len(errors) == 1
