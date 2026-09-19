"""Per-key rate limiting (docs/PAID_API_DESIGN.md Part C) — independent
of any tier/quota (Round 2/3). This protects against raw request-rate
abuse (a leaked key being hammered, runaway polling of `GET /scans/{id}`)
and must produce a visibly different error than a quota/auth failure so a
client can tell "you're going too fast" apart from "you're not
authorized" or "you're out of scans this month" (Part C: "429 vs 403").

Round 1 scope, stated honestly: this is a single-process, in-memory
token bucket. It resets on restart and does not coordinate across
multiple worker processes — correct for one `uvicorn` worker (this
round's deployment target), not yet correct for a horizontally-scaled
multi-worker deployment, which would need a shared store (Redis) instead.
Flagged here rather than silently assumed away, same as the async scan
orchestration's own single-process scope note in `api/scan_orchestrator.py`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class RateLimitExceededError(Exception):
    """Raised by `TokenBucketLimiter.check` when a key is over its limit
    — the API layer turns this into a 429, distinct from 401/403."""


class TokenBucketLimiter:
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
