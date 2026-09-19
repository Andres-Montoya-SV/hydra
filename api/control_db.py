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

-- Part A (docs/PAID_API_DESIGN.md) domain-ownership verification. One row
-- per verification ATTEMPT, not per (account, domain) — a new attempt
-- (re-verify, retry after a failed check, renewal after expiry) is a new
-- row, never an in-place mutation of history. `status` is one of
-- 'pending' (token issued, no successful check yet), 'verified' (a real
-- DNS/HTTP check succeeded), 'failed' (a real check was attempted and did
-- not confirm the token), 'superseded' (this account's own older
-- verified/pending row for the same domain, replaced by a newer one).
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
CREATE INDEX IF NOT EXISTS idx_domain_verifications_domain ON domain_verifications(domain);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_account
    ON domain_verifications(account_id, domain);

-- Part B (docs/PAID_API_DESIGN.md, Round 3) tier/subscription state. One
-- row per account, created at account-creation time defaulting to
-- 'free' (api/routers/accounts.py) — every account has exactly one
-- current tier, never zero, never ambiguous between two rows.
-- `retention_days_override` is only ever meaningful for an Ultra account
-- ("configurable por cuenta" — api/tiers.py::retention_days_for); NULL
-- for every other tier.
-- `billing_email` is set once a paid enrollment activates
-- (api/routers/subscription.py's webhook handler) — it is what lets a
-- LATER webhook (a recurring monthly charge, success or failure) be
-- correlated back to this account even after the original
-- `wompi_pending_enrollments` row has done its one job and been marked
-- 'matched'. NULL for an account that has never had a paid tier.
CREATE TABLE IF NOT EXISTS subscriptions (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    tier TEXT NOT NULL,
    status TEXT NOT NULL,
    billing_email TEXT,
    grace_period_started_at TEXT,
    retention_days_override INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_billing_email ON subscriptions(billing_email);

-- Monthly usage counters, one row per (account, calendar month, UTC).
-- "Monthly" = calendar month, not a rolling 30-day or per-account
-- billing-anniversary window — simpler, and matches how the tier table
-- itself talks about limits ("Scans/mes"), not "scans per rolling 30
-- days." `period_key` is 'YYYY-MM'.
CREATE TABLE IF NOT EXISTS monthly_usage (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    period_key TEXT NOT NULL,
    scans_used INTEGER NOT NULL DEFAULT 0,
    reportability_spend_usd REAL NOT NULL DEFAULT 0.0,
    hypotheses_spend_usd REAL NOT NULL DEFAULT 0.0,
    PRIMARY KEY (account_id, period_key)
);

-- Part E.1's estimate-then-confirm pattern, extended to reportability/
-- hypotheses (Round 3). One row per `GET .../estimate` call; `POST
-- .../assessment` (or hypotheses' equivalent) must reference a row here
-- that is unexpired AND not yet consumed — never trusts a cost figure
-- the client merely claims it saw.
CREATE TABLE IF NOT EXISTS cost_estimates (
    estimate_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    scan_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    provider TEXT NOT NULL,
    adversarial_provider TEXT,
    degraded_from_adversarial INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd REAL NOT NULL,
    params_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cost_estimates_account ON cost_estimates(account_id);

-- Wompi billing (Part D, Round 3). `wompi_pending_enrollments`: created
-- at `POST /account/subscription {"tier": ...}` time, one row per
-- upgrade *attempt* — the best-effort subscriber-identification
-- mechanism (docs/PAID_API_DESIGN.md's "Round 3 implemented" section
-- documents this honestly as unconfirmed against a real Wompi sandbox):
-- match an incoming webhook's `cliente.Email` against a still-'pending'
-- row's `billing_email` for the same tier/product.
CREATE TABLE IF NOT EXISTS wompi_pending_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    tier TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    matched_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_wompi_pending_email ON wompi_pending_enrollments(billing_email);

-- Idempotency + audit log for every webhook Wompi (or anyone claiming to
-- be Wompi) ever POSTs to this service — `transaction_id` is Wompi's own
-- `IdTransaccion`, unique, so a redelivered webhook (Wompi's own retry
-- behavior, or a replay attempt) is never double-processed.
CREATE TABLE IF NOT EXISTS wompi_webhook_events (
    transaction_id TEXT PRIMARY KEY,
    outcome TEXT NOT NULL,
    matched_account_id TEXT,
    raw_body TEXT NOT NULL,
    received_at TEXT NOT NULL
);

-- The manual-reconciliation backstop (Task's own explicit requirement):
-- any webhook that passed signature verification (so it IS genuinely
-- from Wompi) but could not be matched to a pending enrollment lands
-- here instead of being discarded or guessed — an operator resolves it
-- via `POST /admin/wompi/reconcile`, never automatically.
CREATE TABLE IF NOT EXISTS wompi_unmatched_payments (
    unmatched_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL,
    payer_email TEXT,
    product_name TEXT,
    amount REAL,
    raw_body TEXT NOT NULL,
    received_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_account_id TEXT
);
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


@dataclass(frozen=True)
class SubscriptionRecord:
    account_id: str
    tier: str
    status: str
    billing_email: str | None
    grace_period_started_at: str | None
    retention_days_override: int | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class MonthlyUsageRecord:
    account_id: str
    period_key: str
    scans_used: int
    reportability_spend_usd: float
    hypotheses_spend_usd: float


@dataclass(frozen=True)
class CostEstimateRecord:
    estimate_id: str
    account_id: str
    scan_id: str
    feature: str
    provider: str
    adversarial_provider: str | None
    degraded_from_adversarial: bool
    estimated_cost_usd: float
    params_json: str
    created_at: str
    expires_at: str
    consumed_at: str | None


@dataclass(frozen=True)
class WompiPendingEnrollmentRecord:
    enrollment_id: str
    account_id: str
    tier: str
    billing_email: str
    status: str
    created_at: str
    matched_at: str | None


@dataclass(frozen=True)
class DomainVerificationRecord:
    verification_id: str
    account_id: str
    domain: str
    token: str
    method: str | None
    status: str
    created_at: str
    verified_at: str | None
    expires_at: str | None
    last_checked_at: str | None
    last_check_error: str | None


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

    # --- domain verification (Part A) --------------------------------

    def create_domain_verification(
        self, *, account_id: str, domain: str, token: str
    ) -> DomainVerificationRecord:
        verification_id = secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO domain_verifications "
                "(verification_id, account_id, domain, token, method, status, created_at) "
                "VALUES (?, ?, ?, ?, NULL, 'pending', ?)",
                (verification_id, account_id, domain, token, now),
            )
        return DomainVerificationRecord(
            verification_id=verification_id,
            account_id=account_id,
            domain=domain,
            token=token,
            method=None,
            status="pending",
            created_at=now,
            verified_at=None,
            expires_at=None,
            last_checked_at=None,
            last_check_error=None,
        )

    def get_latest_pending_verification(
        self, account_id: str, domain: str
    ) -> DomainVerificationRecord | None:
        """The token a client is currently trying to prove — the most
        recent 'pending' row for this exact (account, domain). Never
        returns another account's row (account_id is always part of the
        WHERE clause, same discipline as every other lookup here)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE account_id = ? AND domain = ? AND status = 'pending' "
                "ORDER BY created_at DESC LIMIT 1",
                (account_id, domain),
            ).fetchone()
        return None if row is None else _verification_record_from_row(row)

    def get_active_verification_for_domain(
        self, domain: str, *, now: str | None = None
    ) -> DomainVerificationRecord | None:
        """The current, unexpired 'verified' row for `domain`, across ALL
        accounts — used only for the conflict check at the moment a NEW
        verification is about to succeed (Task 3.2: first successful
        verification wins). Never used to authorize a scan directly —
        that always goes through `get_active_verifications_for_account`,
        scoped to one account, never a bare domain lookup."""
        now = now or _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE domain = ? AND status = 'verified' AND expires_at > ? "
                "ORDER BY verified_at DESC LIMIT 1",
                (domain, now),
            ).fetchone()
        return None if row is None else _verification_record_from_row(row)

    def get_all_verifications_for_account(self, account_id: str) -> list[DomainVerificationRecord]:
        """Every row this account has ever had, any domain, newest
        first — used to distinguish "never verified" from "verified
        once, now expired" (Task 3, test 6) by filtering for domain
        coverage in Python (api/domain_verification.py::domain_is_covered),
        the same subdomain-aware matching the scan gate itself uses,
        rather than a second, narrower SQL-only exact-match notion of
        "the same domain"."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_verifications WHERE account_id = ? "
                "ORDER BY created_at DESC",
                (account_id,),
            ).fetchall()
        return [_verification_record_from_row(row) for row in rows]

    def get_verified_domains_for_account(
        self, account_id: str, *, now: str | None = None
    ) -> list[DomainVerificationRecord]:
        """Every currently-active (verified, unexpired) domain this
        account holds — the scan gate checks scan target coverage
        against this list in Python (subdomain matching), not SQL."""
        now = now or _now_iso()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE account_id = ? AND status = 'verified' AND expires_at > ?",
                (account_id, now),
            ).fetchall()
        return [_verification_record_from_row(row) for row in rows]

    def mark_verification_succeeded(
        self, verification_id: str, *, method: str, verified_at: str, expires_at: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE domain_verifications SET status = 'verified', method = ?, "
                "verified_at = ?, expires_at = ?, last_checked_at = ?, last_check_error = NULL "
                "WHERE verification_id = ?",
                (method, verified_at, expires_at, verified_at, verification_id),
            )

    def mark_verification_failed(self, verification_id: str, *, method: str, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE domain_verifications SET method = ?, last_checked_at = ?, "
                "last_check_error = ? WHERE verification_id = ?",
                (method, _now_iso(), error, verification_id),
            )

    def supersede_other_verifications(
        self, account_id: str, domain: str, *, keep_verification_id: str
    ) -> None:
        """After a new verification succeeds, mark this SAME account's
        other rows for the SAME domain as superseded — exactly one
        canonical row per (account, domain) going forward, so "the
        account's active verification for this domain" is never
        ambiguous between two simultaneously-verified rows."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE domain_verifications SET status = 'superseded' "
                "WHERE account_id = ? AND domain = ? AND verification_id != ? "
                "AND status IN ('pending', 'verified')",
                (account_id, domain, keep_verification_id),
            )

    # --- subscriptions / tiers (Part B, Round 3) ------------------------

    def create_default_subscription(self, account_id: str, *, tier: str = "free") -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO subscriptions "
                "(account_id, tier, status, created_at, updated_at) "
                "VALUES (?, ?, 'active', ?, ?)",
                (account_id, tier, now, now),
            )

    def get_subscription(self, account_id: str) -> SubscriptionRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM subscriptions WHERE account_id = ?", (account_id,)
            ).fetchone()
        return None if row is None else _subscription_record_from_row(row)

    def set_tier(
        self,
        account_id: str,
        tier: str,
        *,
        status: str = "active",
        billing_email: str | None = None,
    ) -> None:
        """`billing_email` is only ever passed (and only ever overwrites
        the stored value) when a NEW paid activation just happened
        (`api/routers/subscription.py`'s webhook handler) — a plain
        upgrade/downgrade call (`POST /account/subscription` for
        tier='free', or the admin reconciliation endpoint) leaves
        whatever billing email is already on file untouched."""
        with self._connect() as conn:
            if billing_email is not None:
                conn.execute(
                    "UPDATE subscriptions SET tier = ?, status = ?, billing_email = ?, "
                    "grace_period_started_at = NULL, updated_at = ? WHERE account_id = ?",
                    (tier, status, billing_email.strip().lower(), _now_iso(), account_id),
                )
            else:
                conn.execute(
                    "UPDATE subscriptions SET tier = ?, status = ?, "
                    "grace_period_started_at = NULL, updated_at = ? WHERE account_id = ?",
                    (tier, status, _now_iso(), account_id),
                )

    def find_account_id_by_billing_email(self, billing_email: str) -> str | None:
        """Correlates a RECURRING charge webhook (success or failure) —
        one that arrives after the original `wompi_pending_enrollments`
        row already did its one job — back to the account it belongs to.
        Same "no guessing" discipline as
        `find_pending_enrollment_by_email`: more than one account
        sharing a billing email is unusual enough to not guess between,
        so only an exact single match resolves."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id FROM subscriptions WHERE billing_email = ?",
                (billing_email.strip().lower(),),
            ).fetchall()
        if len(rows) != 1:
            return None
        return rows[0]["account_id"]

    def set_subscription_status(
        self, account_id: str, status: str, *, grace_period_started_at: str | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE subscriptions SET status = ?, grace_period_started_at = ?, "
                "updated_at = ? WHERE account_id = ?",
                (status, grace_period_started_at, _now_iso(), account_id),
            )

    def set_retention_override(self, account_id: str, retention_days: int | None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE subscriptions SET retention_days_override = ?, updated_at = ? "
                "WHERE account_id = ?",
                (retention_days, _now_iso(), account_id),
            )

    # --- monthly usage (Part B) -----------------------------------------

    def get_monthly_usage(self, account_id: str, period_key: str) -> MonthlyUsageRecord:
        """Always returns a record — a period with no activity yet is
        all-zeros, never `None`, so callers never need a separate
        "no row yet" branch just to compare against a limit."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM monthly_usage WHERE account_id = ? AND period_key = ?",
                (account_id, period_key),
            ).fetchone()
        if row is None:
            return MonthlyUsageRecord(
                account_id=account_id,
                period_key=period_key,
                scans_used=0,
                reportability_spend_usd=0.0,
                hypotheses_spend_usd=0.0,
            )
        return MonthlyUsageRecord(
            account_id=row["account_id"],
            period_key=row["period_key"],
            scans_used=row["scans_used"],
            reportability_spend_usd=row["reportability_spend_usd"],
            hypotheses_spend_usd=row["hypotheses_spend_usd"],
        )

    def increment_scan_usage(self, account_id: str, period_key: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO monthly_usage (account_id, period_key, scans_used) "
                "VALUES (?, ?, 1) "
                "ON CONFLICT(account_id, period_key) "
                "DO UPDATE SET scans_used = scans_used + 1",
                (account_id, period_key),
            )

    def add_llm_spend(
        self, account_id: str, period_key: str, *, feature: str, amount_usd: float
    ) -> None:
        # column is one of exactly two hardcoded literals chosen above,
        # never external input — same "identifier is a literal, values
        # are bound params" shape as core/store.py::get_findings's own
        # dynamic-column query (also suppressed below for the same reason).
        column = "reportability_spend_usd" if feature == "reportability" else "hypotheses_spend_usd"
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO monthly_usage (account_id, period_key, {column}) "  # noqa: S608  # nosec B608
                f"VALUES (?, ?, ?) "
                f"ON CONFLICT(account_id, period_key) "
                f"DO UPDATE SET {column} = {column} + excluded.{column}",
                (account_id, period_key, amount_usd),
            )

    # --- cost estimates (Part E.1, extended to LLM features) -----------

    def create_cost_estimate(
        self,
        *,
        account_id: str,
        scan_id: str,
        feature: str,
        provider: str,
        adversarial_provider: str | None,
        degraded_from_adversarial: bool,
        estimated_cost_usd: float,
        params_json: str,
        ttl_minutes: int = 10,
    ) -> CostEstimateRecord:
        estimate_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(minutes=ttl_minutes)).isoformat()
        created_at = now.isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cost_estimates (estimate_id, account_id, scan_id, feature, "
                "provider, adversarial_provider, degraded_from_adversarial, "
                "estimated_cost_usd, params_json, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    estimate_id,
                    account_id,
                    scan_id,
                    feature,
                    provider,
                    adversarial_provider,
                    int(degraded_from_adversarial),
                    estimated_cost_usd,
                    params_json,
                    created_at,
                    expires_at,
                ),
            )
        return CostEstimateRecord(
            estimate_id=estimate_id,
            account_id=account_id,
            scan_id=scan_id,
            feature=feature,
            provider=provider,
            adversarial_provider=adversarial_provider,
            degraded_from_adversarial=degraded_from_adversarial,
            estimated_cost_usd=estimated_cost_usd,
            params_json=params_json,
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=None,
        )

    def get_valid_cost_estimate(
        self, estimate_id: str, account_id: str, *, scan_id: str, feature: str
    ) -> CostEstimateRecord | None:
        """Only returns a row that is this account's, for this exact
        scan+feature, unexpired, AND not already consumed — the same
        single-use/short-lived/bound-to-what-was-shown discipline Part
        E.1 established for the scan cost-estimate flow."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cost_estimates WHERE estimate_id = ? AND account_id = ? "
                "AND scan_id = ? AND feature = ? AND consumed_at IS NULL "
                "AND expires_at > ?",
                (estimate_id, account_id, scan_id, feature, _now_iso()),
            ).fetchone()
        return None if row is None else _cost_estimate_record_from_row(row)

    def consume_cost_estimate(self, estimate_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE cost_estimates SET consumed_at = ? WHERE estimate_id = ?",
                (_now_iso(), estimate_id),
            )

    # --- Wompi billing (Part D, Round 3) --------------------------------

    def create_pending_enrollment(
        self, *, account_id: str, tier: str, billing_email: str
    ) -> WompiPendingEnrollmentRecord:
        enrollment_id = secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO wompi_pending_enrollments "
                "(enrollment_id, account_id, tier, billing_email, status, created_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (enrollment_id, account_id, tier, billing_email.strip().lower(), now),
            )
        return WompiPendingEnrollmentRecord(
            enrollment_id=enrollment_id,
            account_id=account_id,
            tier=tier,
            billing_email=billing_email.strip().lower(),
            status="pending",
            created_at=now,
            matched_at=None,
        )

    def find_pending_enrollment_by_email(
        self, billing_email: str, *, tier: str | None = None
    ) -> WompiPendingEnrollmentRecord | None:
        """The best-effort webhook->account correlation (documented as
        unconfirmed against a real Wompi sandbox — see
        docs/PAID_API_DESIGN.md's "Round 3 implemented" section). Matches
        the most recent still-'pending' enrollment for this email,
        optionally narrowed by tier/product. Returns None (never a
        guess) when there's no unambiguous match — the caller then routes
        to manual reconciliation instead of activating anything."""
        query = (
            "SELECT * FROM wompi_pending_enrollments "
            "WHERE billing_email = ? AND status = 'pending'"
        )
        params: list[str] = [billing_email.strip().lower()]
        if tier is not None:
            query += " AND tier = ?"
            params.append(tier)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        if len(rows) != 1:
            # Zero matches: nothing pending for this email. More than
            # one: ambiguous (e.g. two different tier upgrades requested
            # with the same email) — neither case is safe to guess from.
            return None
        return _pending_enrollment_record_from_row(rows[0])

    def mark_enrollment_matched(self, enrollment_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE wompi_pending_enrollments SET status = 'matched', matched_at = ? "
                "WHERE enrollment_id = ?",
                (_now_iso(), enrollment_id),
            )

    def webhook_event_already_processed(self, transaction_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM wompi_webhook_events WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
        return row is not None

    def record_webhook_event(
        self,
        *,
        transaction_id: str,
        outcome: str,
        matched_account_id: str | None,
        raw_body: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO wompi_webhook_events "
                "(transaction_id, outcome, matched_account_id, raw_body, received_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (transaction_id, outcome, matched_account_id, raw_body, _now_iso()),
            )

    def create_unmatched_payment(
        self,
        *,
        transaction_id: str,
        payer_email: str | None,
        product_name: str | None,
        amount: float | None,
        raw_body: str,
    ) -> str:
        unmatched_id = secrets.token_hex(16)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO wompi_unmatched_payments "
                "(unmatched_id, transaction_id, payer_email, product_name, amount, "
                "raw_body, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    unmatched_id,
                    transaction_id,
                    payer_email,
                    product_name,
                    amount,
                    raw_body,
                    _now_iso(),
                ),
            )
        return unmatched_id

    def get_unresolved_payments(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM wompi_unmatched_payments WHERE resolved_at IS NULL "
                "ORDER BY received_at ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def resolve_unmatched_payment(self, unmatched_id: str, *, account_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE wompi_unmatched_payments SET resolved_at = ?, resolved_account_id = ? "
                "WHERE unmatched_id = ? AND resolved_at IS NULL",
                (_now_iso(), account_id, unmatched_id),
            )
        return cursor.rowcount > 0


def _subscription_record_from_row(row: sqlite3.Row) -> SubscriptionRecord:
    return SubscriptionRecord(
        account_id=row["account_id"],
        tier=row["tier"],
        status=row["status"],
        billing_email=row["billing_email"],
        grace_period_started_at=row["grace_period_started_at"],
        retention_days_override=row["retention_days_override"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _cost_estimate_record_from_row(row: sqlite3.Row) -> CostEstimateRecord:
    return CostEstimateRecord(
        estimate_id=row["estimate_id"],
        account_id=row["account_id"],
        scan_id=row["scan_id"],
        feature=row["feature"],
        provider=row["provider"],
        adversarial_provider=row["adversarial_provider"],
        degraded_from_adversarial=bool(row["degraded_from_adversarial"]),
        estimated_cost_usd=row["estimated_cost_usd"],
        params_json=row["params_json"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


def _pending_enrollment_record_from_row(row: sqlite3.Row) -> WompiPendingEnrollmentRecord:
    return WompiPendingEnrollmentRecord(
        enrollment_id=row["enrollment_id"],
        account_id=row["account_id"],
        tier=row["tier"],
        billing_email=row["billing_email"],
        status=row["status"],
        created_at=row["created_at"],
        matched_at=row["matched_at"],
    )


def _verification_record_from_row(row: sqlite3.Row) -> DomainVerificationRecord:
    return DomainVerificationRecord(
        verification_id=row["verification_id"],
        account_id=row["account_id"],
        domain=row["domain"],
        token=row["token"],
        method=row["method"],
        status=row["status"],
        created_at=row["created_at"],
        verified_at=row["verified_at"],
        expires_at=row["expires_at"],
        last_checked_at=row["last_checked_at"],
        last_check_error=row["last_check_error"],
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
