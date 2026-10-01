"""Productization Phase 11c: tenant export and deletion from the host.

    python -m api.tenants pending
    python -m api.tenants export-organization <organization_id> <file.zip>
    python -m api.tenants delete-organization <organization_id> [--now]
    python -m api.tenants delete-account <account_id | email> [--now]
    python -m api.tenants cancel-organization <organization_id>
    python -m api.tenants cancel-account <account_id | email>

Without `--now`, a deletion is scheduled with the same 30-day grace as the
API. `--now` purges at once: for a legal request, or after the tenant has
confirmed. The host export has no size limit. Every action is recorded in
the security audit log with the host user who ran it.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from api import security_audit as audit
from api.control_db import ControlDB
from api.operators import resolve_account
from api.settings import APISettings, load_api_settings
from api.tenant_export import write_organization_export
from api.tenant_lifecycle import due_date, purge_account_now, purge_organization_now

_FAR_FUTURE = "9999-12-31T23:59:59+00:00"


def _open() -> tuple[APISettings, ControlDB]:
    settings = load_api_settings()
    return settings, ControlDB(
        settings.control_db_path, database_url=settings.database_url, pool=settings.database_pool
    )


def _host_event(
    db: ControlDB, action: str, *, organization_id: str | None = None, account_id: str | None = None
) -> None:
    audit.record(
        db,
        None,
        audit.AuditEvent(
            action,
            actor_type="host",
            organization_id=organization_id,
            subject_account_id=account_id,
            target=(
                ("organization", organization_id)
                if organization_id
                else ("account", str(account_id))
            ),
            details={"host_user": getpass.getuser()},
        ),
    )


def _organization(settings: APISettings, db: ControlDB, args: argparse.Namespace) -> str:
    organization_id = args.target
    if db.get_organization(organization_id) is None:
        raise LookupError(f"no organization {organization_id!r}")
    if args.command == "export-organization":
        with Path(args.file).open("xb") as out:
            manifest = write_organization_export(db, organization_id, out)
        rows = sum(d["rows"] for d in manifest["datasets"])
        _host_event(db, audit.ORGANIZATION_EXPORTED, organization_id=organization_id)
        return f"Exported {rows} rows to {args.file}"
    if args.command == "cancel-organization":
        if not db.cancel_organization_deletion(organization_id):
            raise LookupError("no deletion is pending")
        _host_event(db, audit.ORGANIZATION_DELETION_CANCELLED, organization_id=organization_id)
        return "Cancelled"
    if args.now:
        return f"Purged ({purge_organization_now(db, settings, organization_id)} rows)"
    due = db.request_organization_deletion(
        organization_id, actor_account_id="host", due_at=due_date()
    )
    _host_event(db, audit.ORGANIZATION_DELETION_REQUESTED, organization_id=organization_id)
    return f"Scheduled for {due}"


def _account(settings: APISettings, db: ControlDB, args: argparse.Namespace) -> str:
    account_id = resolve_account(db, args.target)
    if account_id is None:
        raise LookupError(f"no account {args.target!r}")
    if args.command == "cancel-account":
        if not db.cancel_account_deletion(account_id):
            raise LookupError("no deletion is pending")
        _host_event(db, audit.ACCOUNT_DELETION_CANCELLED, account_id=account_id)
        return "Cancelled"
    if args.now:
        return f"Purged ({purge_account_now(db, settings, account_id)} rows)"
    due = db.request_account_deletion(account_id, due_at=due_date())
    _host_event(db, audit.ACCOUNT_DELETION_REQUESTED, account_id=account_id)
    return f"Scheduled for {due}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "command",
        choices=(
            "pending",
            "export-organization",
            "delete-organization",
            "delete-account",
            "cancel-organization",
            "cancel-account",
        ),
    )
    parser.add_argument("target", nargs="?")
    parser.add_argument("file", nargs="?", help="export-organization: the new .zip")
    parser.add_argument("--now", action="store_true", help="purge at once, no grace period")
    args = parser.parse_args(argv)

    settings, db = _open()
    if args.command == "pending":
        for organization_id in db.due_organization_deletions(_FAR_FUTURE):
            print(
                f"organization {organization_id}  due {db.organization_deletion_due_at(organization_id)}"
            )
        for account_id in db.due_account_deletions(_FAR_FUTURE):
            print(f"account {account_id}  due {db.account_deletion_due_at(account_id)}")
        return 0
    if not args.target or (args.command == "export-organization" and not args.file):
        parser.error(f"{args.command}: missing argument")
    handler = _account if args.command.endswith("-account") else _organization
    try:
        print(handler(settings, db, args))
    except (LookupError, FileExistsError) as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
