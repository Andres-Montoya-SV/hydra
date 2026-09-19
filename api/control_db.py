"""The control-plane database — accounts, API keys, and the central
`scans` registry (docs/PAID_API_DESIGN.md Part F.3). This is deliberately
a SEPARATE, small SQLite database from any account's own `recon.db`
(`core.store.AssetStore`'s schema is the recon/findings domain; this is
the account/auth/scan-registry domain — mixing them would blur exactly
the boundary Part F exists to keep sharp). Reuses
`core.store.connect_sqlite`/`configure_sqlite` for the same WAL +
foreign-keys-on connection setup the rest of the project already uses,
rather than re-deriving those PRAGMAs here.

Every function that reads or writes account-scoped data (`api_keys`,
`scans`) takes `account_id` as a mandatory, explicit, non-optional
parameter — never inferred, never defaulted (Part F.1) — and the two
`scans` lookups used by the API layer (`get_scan`, `require_owned_scan`)
only ever return a row when `account_id` matches, never "found, wrong
owner" (that distinction is not the caller's to make; a mismatch reads
identically to "not found").
"""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.store import connect_sqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    lookup_hash TEXT NOT NULL UNIQUE,
    verify_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    expires_at TEXT,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_lookup_hash ON api_keys(lookup_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_account_id ON api_keys(account_id);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    db_path TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_account_id ON scans(account_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ApiKeyRecord:
    key_id: str
    account_id: str
    prefix: str
    created_at: str
    revoked_at: str | None
    expires_at: str | None
    last_used_at: str | None


@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    account_id: str
    domain: str
    db_path: str
    status: str
    error_message: str | None
    created_at: str
    updated_at: str


class ControlDB:
    """One instance per process, backed by one SQLite file
    (`APISettings.control_db_path`) — this is the only database in the
    whole service allowed to have rows belonging to more than one
    account; every other database is per-account (`api/tenancy.py`)."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{self.db_path}{suffix}")
            if path.exists():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.db_path)

    # --- accounts ---------------------------------------------------

    def create_account(self) -> str:
        account_id = secrets.token_hex(16)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO accounts (account_id, created_at) VALUES (?, ?)",
                (account_id, _now_iso()),
            )
        return account_id

    def account_exists(self, account_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
        return row is not None

    # --- api keys -----------------------------------------------------

    def insert_api_key(
        self, *, key_id: str, account_id: str, lookup_hash: str, verify_hash: str, prefix: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO api_keys "
                "(key_id, account_id, lookup_hash, verify_hash, prefix, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, account_id, lookup_hash, verify_hash, prefix, _now_iso()),
            )

    def find_key_by_lookup_hash(self, lookup_hash: str) -> tuple[ApiKeyRecord, str] | None:
        """Returns (record, verify_hash) so the caller can run the slow
        Argon2id check outside any DB transaction — this fast lookup
        column exists precisely so authentication doesn't require an
        Argon2id verify against every active key on every request (see
        `api/security.py` module docstring)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE lookup_hash = ?", (lookup_hash,)
            ).fetchone()
        if row is None:
            return None
        return _key_record_from_row(row), row["verify_hash"]

    def get_key(self, key_id: str, account_id: str) -> ApiKeyRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_id = ? AND account_id = ?",
                (key_id, account_id),
            ).fetchone()
        return None if row is None else _key_record_from_row(row)

    def touch_key_last_used(self, key_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (_now_iso(), key_id)
            )

    def revoke_key(self, key_id: str, account_id: str) -> bool:
        """Immediate revocation — never touches any other key on the
        account. Returns False if no matching, not-already-revoked key
        was found for that account (caller treats this as 404, never
        403, per the tenant-isolation convention above)."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked_at = ? "
                "WHERE key_id = ? AND account_id = ? AND revoked_at IS NULL",
                (_now_iso(), key_id, account_id),
            )
        return cursor.rowcount > 0

    def start_key_rotation_grace_period(
        self, key_id: str, account_id: str, *, grace_hours: int
    ) -> str | None:
        """The OLD key stays valid until `expires_at` rather than being
        revoked immediately — the 24h dual-validity window
        (docs/PAID_API_DESIGN.md Part C). Returns the new `expires_at`
        (ISO timestamp), or None if no matching, currently-valid key was
        found for that account."""
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=grace_hours)).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET expires_at = ? "
                "WHERE key_id = ? AND account_id = ? AND revoked_at IS NULL",
                (expires_at, key_id, account_id),
            )
        return expires_at if cursor.rowcount > 0 else None

    # --- scans ----------------------------------------------------------

    def create_scan(self, *, scan_id: str, account_id: str, domain: str, db_path: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans "
                "(scan_id, account_id, domain, db_path, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'queued', ?, ?)",
                (scan_id, account_id, domain, db_path, now, now),
            )

    def update_scan_status(
        self, scan_id: str, status: str, *, error_message: str | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = ?, error_message = ?, updated_at = ? "
                "WHERE scan_id = ?",
                (status, error_message, _now_iso(), scan_id),
            )

    def get_owned_scan(self, scan_id: str, account_id: str) -> ScanRecord | None:
        """The Part F.3 double-check in one call: a scan_id that exists
        but belongs to a different account returns None, identically to
        a scan_id that doesn't exist at all."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ? AND account_id = ?",
                (scan_id, account_id),
            ).fetchone()
        if row is None:
            return None
        return ScanRecord(
            scan_id=row["scan_id"],
            account_id=row["account_id"],
            domain=row["domain"],
            db_path=row["db_path"],
            status=row["status"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


def _key_record_from_row(row: sqlite3.Row) -> ApiKeyRecord:
    return ApiKeyRecord(
        key_id=row["key_id"],
        account_id=row["account_id"],
        prefix=row["prefix"],
        created_at=row["created_at"],
        revoked_at=row["revoked_at"],
        expires_at=row["expires_at"],
        last_used_at=row["last_used_at"],
    )
