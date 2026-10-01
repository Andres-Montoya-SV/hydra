"""Productization Phase 11b: who may call the admin endpoints.

Operators are ordinary accounts with the operator flag. They authenticate
with their own API keys, so every admin action is audited to a person, and
rotation and revocation use the normal key endpoints. The flag can only be
changed here, on the host. No API endpoint grants it, so a compromised
account can't make itself an operator.

    python -m api.operators list
    python -m api.operators grant <account_id | email>
    python -m api.operators revoke <account_id | email>

Each grant or revoke is recorded in the security audit log, with the host
user who ran it. The database is the one the API uses (HYDRA_API_DATA_DIR
or HYDRA_API_DATABASE_URL).
"""

from __future__ import annotations

import argparse
import getpass
import sys

from api import security_audit as audit
from api.control_db import ControlDB
from api.settings import load_api_settings


def _control_db() -> ControlDB:
    settings = load_api_settings()
    return ControlDB(
        settings.control_db_path, database_url=settings.database_url, pool=settings.database_pool
    )


def _resolve(db: ControlDB, who: str) -> str | None:
    if "@" in who:
        return db.account_id_for_email(who)
    return who if db.account_exists(who) else None


def set_operator(db: ControlDB, who: str, operator: bool) -> str:
    """Grants or revokes; returns the account id. Raises LookupError for an
    unknown account."""
    account_id = _resolve(db, who)
    if account_id is None or not db.set_operator(account_id, operator):
        raise LookupError(f"no account {who!r}")
    audit.record(
        db,
        None,
        audit.AuditEvent(
            audit.OPERATOR_GRANTED if operator else audit.OPERATOR_REVOKED,
            actor_type="host",
            subject_account_id=account_id,
            target=("account", account_id),
            details={"host_user": getpass.getuser()},
        ),
    )
    return account_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("list", "grant", "revoke"))
    parser.add_argument("account", nargs="?", help="account id or email")
    args = parser.parse_args(argv)

    db = _control_db()
    if args.command == "list":
        for account_id, email in db.list_operator_account_ids():
            print(f"{account_id}  {email or '-'}")
        return 0
    if not args.account:
        parser.error(f"{args.command} needs an account id or email")
    try:
        account_id = set_operator(db, args.account, args.command == "grant")
    except LookupError as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(f"{'Granted' if args.command == 'grant' else 'Revoked'} operator: {account_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
