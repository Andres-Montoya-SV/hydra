"""Per-key rate limiting (docs/PAID_API_DESIGN.md Part C) — independent
of any tier/quota (Round 2/3). This protects against raw request-rate
abuse (a leaked key being hammered, runaway polling of `GET /scans/{id}`)
and must produce a visibly different error than a quota/auth failure so a
client can tell "you're going too fast" apart from "you're not
authorized" or "you're out of scans this month" (Part C: "429 vs 403").

**`PersistentTokenBucketLimiter` is what `api/main.py` actually wires up
today** — a `ControlDB`-backed limiter (durable-queue fix,
docs/PAID_API_DESIGN.md's "Durable, multi-worker-safe scan execution"
section) that enforces the SAME limit whether one `uvicorn` worker
process serves a key's requests or several do, and survives a restart
instead of silently resetting every bucket to full. It exposes the
exact same `.check(key_id)` / `RateLimitExceededError` shape
`TokenBucketLimiter` below always had, so `api/auth.py` needed zero
changes to switch to it — same interface, different (now shared,
durable) state.

`TokenBucketLimiter` (in-memory, single-process, resets on restart) is
kept below, unused by the real app, ONLY because nothing about its own
correctness changed and deleting a working, self-contained class that
costs nothing to keep would be removal for its own sake — it's a
legitimate, simpler choice for a caller that genuinely never needs
cross-process/restart durability. `require_api_key`'s own real request
path uses `PersistentTokenBucketLimiter` exclusively.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from api.control_db import ControlDB


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class RateLimitExceededError(Exception):
    """Raised by `.check()` (either limiter below) when a key is over
    its limit — the API layer turns this into a 429, distinct from
    401/403."""


class TokenBucketLimiter:
    """In-memory, single-process — see this module's own docstring for
    why this is no longer what the real app wires up, and kept only as
    a simpler, self-contained option for a caller that doesn't need
    cross-process durability."""

    def __init__(self, *, requests_per_minute: int) -> None:
        self._capacity = float(requests_per_minute)
        self._refill_rate = requests_per_minute / 60.0  # tokens per second
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key_id: str) -> None:
        """Consumes one token for `key_id`, or raises RateLimitExceededError.
        Synchronous and non-blocking by design — no lock is needed
        because a single asyncio event loop never interleaves this
        function's own execution with itself (no `await` inside it)."""
        now = time.monotonic()
        bucket = self._buckets.get(key_id)
        if bucket is None:
            bucket = _Bucket(tokens=self._capacity, last_refill=now)
            self._buckets[key_id] = bucket

        elapsed = now - bucket.last_refill
        bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._refill_rate)
        bucket.last_refill = now

        if bucket.tokens < 1.0:
            raise RateLimitExceededError(f"Rate limit exceeded for key {key_id!r}")
        bucket.tokens -= 1.0


class PersistentTokenBucketLimiter:
    """`ControlDB.check_and_consume_rate_limit_token` does the actual
    atomic refill-and-consume in one SQL statement — this class is a
    thin adapter exposing the exact interface `TokenBucketLimiter`
    already had (`.check(key_id)` / `RateLimitExceededError`), so
    `api/auth.py::require_api_key` never needed to know which
    implementation is behind `app.state.rate_limiter`."""

    def __init__(self, *, control_db: ControlDB, requests_per_minute: int) -> None:
        self._control_db = control_db
        self._capacity = float(requests_per_minute)
        self._refill_rate_per_second = requests_per_minute / 60.0

    def check(self, key_id: str) -> None:
        allowed = self._control_db.check_and_consume_rate_limit_token(
            key_id, capacity=self._capacity, refill_rate_per_second=self._refill_rate_per_second
        )
        if not allowed:
            raise RateLimitExceededError(f"Rate limit exceeded for key {key_id!r}")
