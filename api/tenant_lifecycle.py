"""Productization Phase 11c: deleting a tenant.

Decisions (2026-10-01):

- **Self-service with a grace period.** An organization owner (or an
  account holder, for their own account) requests deletion through the
  API. It is due `GRACE_DAYS` later and can be cancelled until then.
  Operators can purge at once from the host (`python -m api.tenants`).
- **Keep and pseudonymize.** The security audit log and billing records
  are kept, with emails, raw payment payloads and client addresses
  removed; ids stay as opaque ids. Everything else of the tenant is
  deleted.

**Purging an organization** removes:
- every row of it in the control database, in one transaction (literal
  statements in `api/control_db.py`);
- every scan run's data in the members' `recon.db` files
  (`AssetStore.purge_run`);
- the runs' artifact directories.

The scan list is taken first and the database purged next, so the
deletion is never left half-recorded; then the files go. A file that
can't be removed is logged with its scan id.

**Purging an account:**
1. Its sole-owned organizations are purged (nobody else could administer
   them).
2. Its own rows go (keys, memberships, webhooks, monitoring, usage).
3. The account row becomes an anonymous tombstone, so history in
   organizations it shared with others keeps resolving.
4. Its data directory, including its `recon.db`, is removed.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from api import security_audit as audit
from api.control_db import ControlDB
from api.settings import APISettings
from core.store import AssetStore

logger = logging.getLogger("hydra.api.tenant_lifecycle")

GRACE_DAYS = 30


def due_date(now: datetime | None = None) -> str:
    return ((now or datetime.now(timezone.utc)) + timedelta(days=GRACE_DAYS)).isoformat()


def _purge_scan_files(api_settings: APISettings, account_id: str, scan_id: str) -> None:
    account_root = api_settings.account_root(account_id)
    recon_db = account_root / "output" / "recon.db"
    try:
        if recon_db.is_file():
            AssetStore(recon_db).purge_run(scan_id)
        shutil.rmtree(account_root / "output" / scan_id, ignore_errors=True)
    except Exception:  # the database purge already happened; keep going
        logger.exception("Could not remove the files of scan %s (account %s)", scan_id, account_id)


def purge_organization_now(db: ControlDB, api_settings: APISettings, organization_id: str) -> int:
    """Purges the organization and its scan files; returns the control rows
    deleted. The purge itself is recorded (by the system)."""
    scans = db.organization_scans(organization_id)
    deleted = db.purge_organization(organization_id)
    for account_id, scan_id in scans:
        _purge_scan_files(api_settings, account_id, scan_id)
    audit.record(
        db,
        None,
        audit.AuditEvent(
            audit.ORGANIZATION_PURGED,
            actor_type="host",
            organization_id=organization_id,
            target=("organization", organization_id),
            details={"rows": deleted, "scans": len(scans)},
        ),
    )
    return deleted


def purge_account_now(db: ControlDB, api_settings: APISettings, account_id: str) -> int:
    """Purges the account, its sole-owned organizations and its files."""
    deleted = sum(
        purge_organization_now(db, api_settings, organization_id)
        for organization_id in db.sole_owned_organizations(account_id)
    )
    deleted += db.purge_account(account_id)
    shutil.rmtree(api_settings.account_root(account_id), ignore_errors=True)
    audit.record(
        db,
        None,
        audit.AuditEvent(
            audit.ACCOUNT_PURGED,
            actor_type="host",
            subject_account_id=account_id,
            target=("account", account_id),
            details={"rows": deleted},
        ),
    )
    return deleted


@dataclass(frozen=True)
class DeletionRun:
    organizations: int
    accounts: int


def run_tenant_deletion_job(
    *, api_settings: APISettings, control_db: ControlDB, now: datetime | None = None
) -> DeletionRun:
    """Purges every organization and account whose grace period is over
    (the reconciliation loop runs this daily)."""
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    organizations = control_db.due_organization_deletions(stamp)
    accounts = control_db.due_account_deletions(stamp)
    if api_settings.retention_purge_dry_run:
        logger.info(
            "Tenant deletion [DRY RUN, nothing deleted]: due organizations %s, accounts %s.",
            organizations,
            accounts,
        )
        return DeletionRun(organizations=0, accounts=0)
    for organization_id in organizations:
        purge_organization_now(control_db, api_settings, organization_id)
    for account_id in accounts:
        purge_account_now(control_db, api_settings, account_id)
    if organizations or accounts:
        logger.info(
            "Tenant deletion: purged %d organization(s) and %d account(s).",
            len(organizations),
            len(accounts),
        )
    return DeletionRun(organizations=len(organizations), accounts=len(accounts))
