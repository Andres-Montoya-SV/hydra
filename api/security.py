"""API key generation and verification (docs/PAID_API_DESIGN.md Part C).

Two different hashes are stored per key, deliberately, for two different
jobs:

- `verify_hash` (Argon2id, via `argon2-cffi`) — the actual authentication
  check. Argon2id is intentionally slow and salted so a stolen database
  dump can't be brute-forced quickly.
- `lookup_hash` (plain SHA256 of the raw key) — an indexed, O(1) way to
  find the *candidate* row before running the slow Argon2id check.
  Without this, authenticating a request would mean running Argon2id
  against every active key in the database on every single request (it's
  a KDF, not a keyed index — same input always hashes the same, but nothing
  about a stored Argon2id hash lets you search FOR it), which does not
  scale past a handful of keys. SHA256 as an index doesn't weaken
  anything: finding the right row is not the secret part of
  authentication, verifying the key still requires the slow Argon2id
  match. This is the same two-hash pattern GitHub/Stripe-style API key
  storage uses.

The raw key itself is never stored anywhere, ever — only these two
one-way derivations.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from api.control_db import ApiKeyRecord

_hasher = PasswordHasher()


def generate_raw_key(*, test_mode: bool = False) -> tuple[str, str]:
    """256 bits of randomness, hex-encoded, with a visible prefix
    distinguishing sandbox from production keys — a key pasted into the
    wrong environment is visually obvious before it's ever used
    (docs/PAID_API_DESIGN.md Part C). Returns (raw_key, prefix)."""
    prefix = "hydra_test" if test_mode else "hydra_live"
    return f"{prefix}_{secrets.token_hex(32)}", prefix


def lookup_hash_for(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def hash_for_storage(raw_key: str) -> str:
    return _hasher.hash(raw_key)


def verify_key(raw_key: str, verify_hash: str) -> bool:
    try:
        return _hasher.verify(verify_hash, raw_key)
    except VerifyMismatchError:
        return False


def is_currently_valid(record: ApiKeyRecord) -> bool:
    """Revoked keys are invalid immediately and permanently. A key mid
    rotation-grace-period is valid until `expires_at`, then invalid with
    no further action needed — the grace period is enforced here, not by
    a scheduled job that has to remember to revoke it later."""
    if record.revoked_at is not None:
        return False
    if record.expires_at is not None:
        expires_at = datetime.fromisoformat(record.expires_at)
        if datetime.now(timezone.utc) >= expires_at:
            return False
    return True
