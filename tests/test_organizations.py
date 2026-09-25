"""Fase 02 (EASM roadmap, docs/easm/00_consolidation_plan.md) — the new
`organizations`/`account_organization_roles` tables, the automatic 1:1
migration for accounts that predate them, and the query-level isolation
guarantee: two organizations sharing the same billing `account_id` (the
consultant-with-two-clients case this phase exists for) must never leak
data into each other.

`TestMigrationAgainstRealPreExistingData` deliberately does NOT construct
a `ControlDB` to seed its "before" state — that would already run this
phase's own migration code, defeating the point. It instead opens a raw
`sqlite3` connection and executes the EXACT schema `main` had for
`accounts`/`scans`/`domain_verifications`/`monitored_domains`/`webhooks`
before this phase (verified against `git show main:api/control_db.py`,
not reconstructed from memory), inserts real rows through raw SQL
matching that old shape, closes it, and only then constructs a real
`ControlDB` against that same file — exercising the actual migration
path a real upgrade takes.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from api.control_db import (
    ControlDB,
    role_can_manage_members,
    role_can_modify_scope,
)

_PRE_FASE_02_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    email TEXT,
    email_verified_at TEXT,
    email_verification_token TEXT,
    email_verification_token_expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)
    WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    db_path TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    worker_id TEXT,
    heartbeat_at TEXT,
    trigger_source TEXT NOT NULL DEFAULT 'manual'
);

CREATE TABLE IF NOT EXISTS domain_verifications (
    verification_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    token TEXT NOT NULL,
    method TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    expires_at TEXT,
    last_checked_at TEXT,
    last_check_error TEXT
);

CREATE TABLE IF NOT EXISTS monitored_domains (
    monitoring_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    speed2_enabled INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    last_passive_scan_id TEXT,
    last_active_scan_id TEXT,
    last_passive_run_at TEXT,
    last_active_run_at TEXT,
    next_passive_due_at TEXT NOT NULL,
    next_active_due_at TEXT,
    pending_passive_scan_id TEXT,
    pending_active_scan_id TEXT,
    last_asset_digest TEXT,
    last_asset_count INTEGER,
    needs_review INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (account_id, domain)
);

CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    event_types_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_delivery_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _seed_pre_fase_02_account_with_real_data(db_path: Path) -> str:
    """Writes one account plus one real row in each of scans/
    monitored_domains/webhooks/domain_verifications, using the OLD
    (pre-organizations) schema and raw SQL only — never `ControlDB`,
    which would already carry this phase's migration code."""
    account_id = "acct-legacy-0001"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_PRE_FASE_02_SCHEMA)
        conn.execute(
            "INSERT INTO accounts (account_id, created_at, email, email_verified_at) "
            "VALUES (?, '2025-01-01T00:00:00+00:00', 'legacy@example.com', "
            "'2025-01-01T00:00:00+00:00')",
            (account_id,),
        )
        conn.execute(
            "INSERT INTO scans (scan_id, account_id, domain, db_path, status, "
            "created_at, updated_at) VALUES "
            "('scan-legacy-1', ?, 'legacy.example.com', '/tmp/legacy.db', "  # noqa: S108
            "'completed', '2025-01-02T00:00:00+00:00', '2025-01-02T00:00:00+00:00')",
            (account_id,),
        )
        conn.execute(
            "INSERT INTO domain_verifications (verification_id, account_id, domain, "
            "token, method, status, created_at, verified_at, expires_at) VALUES "
            "('verif-legacy-1', ?, 'legacy.example.com', 'tok-legacy', 'dns_txt', "
            "'verified', '2025-01-01T00:00:00+00:00', '2025-01-01T00:00:00+00:00', "
            "'2099-01-01T00:00:00+00:00')",
            (account_id,),
        )
        conn.execute(
            "INSERT INTO monitored_domains (monitoring_id, account_id, domain, "
            "speed2_enabled, status, next_passive_due_at, needs_review, created_at, "
            "updated_at) VALUES ('mon-legacy-1', ?, 'legacy.example.com', 0, 'active', "
            "'2099-01-01T00:00:00+00:00', 0, '2025-01-01T00:00:00+00:00', "
            "'2025-01-01T00:00:00+00:00')",
            (account_id,),
        )
        conn.execute(
            "INSERT INTO webhooks (webhook_id, account_id, url, secret, "
            "event_types_json, status, consecutive_failures, created_at, updated_at) "
            "VALUES ('hook-legacy-1', ?, 'https://legacy.example.com/hook', "
            "'legacy-secret', ?, 'active', 0, '2025-01-01T00:00:00+00:00', "  # noqa: S106
            "'2025-01-01T00:00:00+00:00')",
            (account_id, json.dumps(["monitoring.changed"])),
        )
        conn.commit()
    finally:
        conn.close()
    return account_id


class TestMigrationAgainstRealPreExistingData:
    def test_a_legacy_account_gets_a_1to1_organization_automatically(self, tmp_path: Path) -> None:
        db_path = tmp_path / "control.db"
        account_id = _seed_pre_fase_02_account_with_real_data(db_path)

        control_db = ControlDB(db_path)

        organizations = control_db.list_organizations_for_account(account_id)
        assert len(organizations) == 1
        organization_id, role = organizations[0]
        assert role == "owner"
        org = control_db.get_organization(organization_id)
        assert org is not None
        assert org.name == "legacy@example.com"

    def test_existing_scans_monitored_domains_and_webhooks_still_work_unchanged(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "control.db"
        account_id = _seed_pre_fase_02_account_with_real_data(db_path)

        control_db = ControlDB(db_path)

        # Every pre-existing, account-scoped accessor returns exactly the
        # same data as before the migration — a real upgrade must be
        # completely unobservable through these calls.
        scan = control_db.get_owned_scan("scan-legacy-1", account_id)
        assert scan is not None
        assert scan.domain == "legacy.example.com"

        verified = control_db.get_verified_domains_for_account(account_id)
        assert [v.domain for v in verified] == ["legacy.example.com"]

        monitored = control_db.list_monitored_domains_for_account(account_id)
        assert [m.domain for m in monitored] == ["legacy.example.com"]

        webhooks = control_db.list_webhooks_for_account(account_id)
        assert [w.webhook_id for w in webhooks] == ["hook-legacy-1"]

        # And the SAME rows are now also reachable through the new
        # organization-scoped accessors, using the auto-created org.
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]
        assert [s.scan_id for s in control_db.list_scans_for_organization(organization_id)] == [
            "scan-legacy-1"
        ]
        assert [
            v.domain for v in control_db.get_verified_domains_for_organization(organization_id)
        ] == ["legacy.example.com"]
        assert [
            m.domain for m in control_db.list_monitored_domains_for_organization(organization_id)
        ] == ["legacy.example.com"]
        assert [
            w.webhook_id for w in control_db.list_webhooks_for_organization(organization_id)
        ] == ["hook-legacy-1"]

    def test_migration_is_idempotent_across_repeated_controldb_construction(
        self, tmp_path: Path
    ) -> None:
        """A second (or hundredth) process start against an already-
        migrated file must never create a second organization for the
        same legacy account — the whole point of the `NOT IN` guard in
        `_backfill_organizations`."""
        db_path = tmp_path / "control.db"
        account_id = _seed_pre_fase_02_account_with_real_data(db_path)

        ControlDB(db_path)
        ControlDB(db_path)
        third = ControlDB(db_path)

        assert len(third.list_organizations_for_account(account_id)) == 1

    def test_a_brand_new_account_gets_its_organization_immediately_not_on_next_restart(
        self, tmp_path: Path
    ) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id = control_db.create_account(email="new@example.com")

        organizations = control_db.list_organizations_for_account(account_id)
        assert len(organizations) == 1
        assert organizations[0][1] == "owner"


class TestOrganizationIsolationEvenUnderTheSameAccount:
    """The consultant case: one billing `account_id`, two target
    organizations, each with its own scope — the required negative test
    that neither can read the other's data through any organization-
    scoped query, even sharing the same account_id."""

    def _two_orgs_one_account(self, control_db: ControlDB) -> tuple[str, str, str]:
        account_id = control_db.create_account(email="consultant@example.com")
        # `create_account` already made a 1:1 default org for this
        # account — that's org A. A second, explicit org (org B) is what
        # a future "onboard a new client" flow would create.
        org_a, _role = control_db.list_organizations_for_account(account_id)[0]
        org_b = control_db.create_organization(name="Client B Inc")
        control_db.add_account_organization_role(
            account_id=account_id, organization_id=org_b, role="owner"
        )
        return account_id, org_a, org_b

    def test_verified_domains_never_cross_organizations(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id, org_a, org_b = self._two_orgs_one_account(control_db)

        record_a = control_db.create_domain_verification(
            account_id=account_id,
            domain="client-a.example.com",
            token="tok-a",  # noqa: S106 - test fixture data, not a real secret
            organization_id=org_a,
        )
        control_db.mark_verification_succeeded(
            record_a.verification_id,
            method="dns_txt",
            verified_at="2026-01-01T00:00:00+00:00",
            expires_at="2099-01-01T00:00:00+00:00",
        )
        record_b = control_db.create_domain_verification(
            account_id=account_id,
            domain="client-b.example.com",
            token="tok-b",  # noqa: S106 - test fixture data, not a real secret
            organization_id=org_b,
        )
        control_db.mark_verification_succeeded(
            record_b.verification_id,
            method="dns_txt",
            verified_at="2026-01-01T00:00:00+00:00",
            expires_at="2099-01-01T00:00:00+00:00",
        )

        domains_a = {v.domain for v in control_db.get_verified_domains_for_organization(org_a)}
        domains_b = {v.domain for v in control_db.get_verified_domains_for_organization(org_b)}
        assert domains_a == {"client-a.example.com"}
        assert domains_b == {"client-b.example.com"}
        assert domains_a.isdisjoint(domains_b)

    def test_monitored_domains_never_cross_organizations(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id, org_a, org_b = self._two_orgs_one_account(control_db)

        control_db.create_or_update_monitored_domain(
            account_id=account_id,
            domain="client-a.example.com",
            speed2_enabled=False,
            passive_interval_hours=24,
            active_interval_hours=168,
            organization_id=org_a,
        )
        control_db.create_or_update_monitored_domain(
            account_id=account_id,
            domain="client-b.example.com",
            speed2_enabled=False,
            passive_interval_hours=24,
            active_interval_hours=168,
            organization_id=org_b,
        )

        domains_a = {m.domain for m in control_db.list_monitored_domains_for_organization(org_a)}
        domains_b = {m.domain for m in control_db.list_monitored_domains_for_organization(org_b)}
        assert domains_a == {"client-a.example.com"}
        assert domains_b == {"client-b.example.com"}

    def test_webhooks_never_cross_organizations(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id, org_a, org_b = self._two_orgs_one_account(control_db)

        control_db.create_webhook(
            account_id=account_id,
            url="https://a.example.com/hook",
            secret="secret-a",  # noqa: S106 - test fixture data, not a real secret
            event_types=("monitoring.changed",),
            organization_id=org_a,
        )
        control_db.create_webhook(
            account_id=account_id,
            url="https://b.example.com/hook",
            secret="secret-b",  # noqa: S106 - test fixture data, not a real secret
            event_types=("monitoring.changed",),
            organization_id=org_b,
        )

        urls_a = {w.url for w in control_db.list_webhooks_for_organization(org_a)}
        urls_b = {w.url for w in control_db.list_webhooks_for_organization(org_b)}
        assert urls_a == {"https://a.example.com/hook"}
        assert urls_b == {"https://b.example.com/hook"}

    def test_scans_never_cross_organizations(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id, org_a, org_b = self._two_orgs_one_account(control_db)

        control_db.create_scan(
            scan_id="scan-a",
            account_id=account_id,
            domain="client-a.example.com",
            db_path=str(tmp_path / "a.db"),
            organization_id=org_a,
        )
        control_db.create_scan(
            scan_id="scan-b",
            account_id=account_id,
            domain="client-b.example.com",
            db_path=str(tmp_path / "b.db"),
            organization_id=org_b,
        )

        ids_a = {s.scan_id for s in control_db.list_scans_for_organization(org_a)}
        ids_b = {s.scan_id for s in control_db.list_scans_for_organization(org_b)}
        assert ids_a == {"scan-a"}
        assert ids_b == {"scan-b"}


class TestRolePermissions:
    def test_owner_can_modify_scope_and_manage_members(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        role = control_db.get_role_for_account_organization(account_id, organization_id)
        assert role == "owner"
        assert role_can_modify_scope(role) is True
        assert role_can_manage_members(role) is True

    def test_viewer_cannot_modify_scope_or_manage_members(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        owner_account = control_db.create_account(email="owner2@example.com")
        viewer_account = control_db.create_account(email="viewer@example.com")
        organization_id, _role = control_db.list_organizations_for_account(owner_account)[0]

        control_db.add_account_organization_role(
            account_id=viewer_account, organization_id=organization_id, role="viewer"
        )

        role = control_db.get_role_for_account_organization(viewer_account, organization_id)
        assert role == "viewer"
        assert role_can_modify_scope(role) is False
        assert role_can_manage_members(role) is False

    def test_an_account_with_no_role_at_all_is_treated_the_same_as_viewer(
        self, tmp_path: Path
    ) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        owner_account = control_db.create_account(email="owner3@example.com")
        outsider_account = control_db.create_account(email="outsider@example.com")
        organization_id, _role = control_db.list_organizations_for_account(owner_account)[0]

        role = control_db.get_role_for_account_organization(outsider_account, organization_id)
        assert role is None
        assert role_can_modify_scope(role) is False
        assert role_can_manage_members(role) is False

    def test_re_granting_a_role_replaces_it_rather_than_erroring(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        owner_account = control_db.create_account(email="owner4@example.com")
        member_account = control_db.create_account(email="member@example.com")
        organization_id, _role = control_db.list_organizations_for_account(owner_account)[0]

        control_db.add_account_organization_role(
            account_id=member_account, organization_id=organization_id, role="viewer"
        )
        assert (
            control_db.get_role_for_account_organization(member_account, organization_id)
            == "viewer"
        )

        control_db.add_account_organization_role(
            account_id=member_account, organization_id=organization_id, role="owner"
        )
        assert (
            control_db.get_role_for_account_organization(member_account, organization_id) == "owner"
        )

    def test_unknown_role_is_rejected(self, tmp_path: Path) -> None:
        control_db = ControlDB(tmp_path / "control.db")
        account_id = control_db.create_account(email="x@example.com")
        organization_id, _role = control_db.list_organizations_for_account(account_id)[0]

        with pytest.raises(ValueError):
            control_db.add_account_organization_role(
                account_id=account_id, organization_id=organization_id, role="admin"
            )
