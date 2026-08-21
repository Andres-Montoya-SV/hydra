"""Shared HTTP response comparison helpers.

Used by soft-404 canaries and parameter fuzzing: both need to decide whether
two responses are meaningfully different (status, body hash, size) without
treating tiny dynamic noise (timestamps, CSRF tokens) as a real change.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ResponseSnapshot:
    """Minimal view of an HTTP response for diffing."""

    status_code: int | None
    body: bytes
    error: str | None = None

    @property
    def body_hash(self) -> str | None:
        if not self.body:
            return None
        return hashlib.sha256(self.body).hexdigest()

    @property
    def body_length(self) -> int:
        return len(self.body)


def body_sha256(body: bytes) -> str | None:
    """Return hex SHA-256 of ``body``, or None for empty bodies."""
    if not body:
        return None
    return hashlib.sha256(body).hexdigest()


def bodies_near_identical(
    left: bytes,
    right: bytes,
    *,
    max_abs_delta: int = 64,
    max_rel_delta: float = 0.05,
) -> bool:
    """True when bodies match by hash or differ only within a size tolerance.

    Soft-404 catch-alls often inject a tiny dynamic token; treating any byte
    difference as significant would flood false negatives there. Parameter
    fuzzing uses the inverse: a change *outside* this band is significant.
    """
    if not left and not right:
        return True
    if not left or not right:
        return False
    if hashlib.sha256(left).digest() == hashlib.sha256(right).digest():
        return True
    larger = max(len(left), len(right), 1)
    return abs(len(left) - len(right)) <= max(max_abs_delta, int(larger * max_rel_delta))


def significant_response_change(
    baseline: ResponseSnapshot,
    candidate: ResponseSnapshot,
    *,
    max_abs_delta: int = 64,
    max_rel_delta: float = 0.05,
) -> bool:
    """True when ``candidate`` differs from ``baseline`` in a meaningful way.

    A change counts when:
    - HTTP status codes differ (and both were observed), or
    - body hashes differ AND the size delta exceeds the near-identical band
      (hash-only diffs within the band are treated as dynamic noise).
    """
    if baseline.status_code is not None and candidate.status_code is not None:
        if baseline.status_code != candidate.status_code:
            return True
    if not baseline.body and not candidate.body:
        return False
    if bodies_near_identical(
        baseline.body,
        candidate.body,
        max_abs_delta=max_abs_delta,
        max_rel_delta=max_rel_delta,
    ):
        return False
    # Outside the near-identical band (or one side empty): significant.
    return True


def canary_reflected(body: bytes, canary: str, *, encoding: str = "utf-8") -> bool:
    """True when the canary string appears as an exact, case-sensitive substring.

    Uses Python's ``in`` on the decoded text — no regex, no casefolding — so
    ``reconprobe123`` must appear literally. Pair with
    :func:`reflected_context` so positives stay auditable.
    """
    return reflected_context(body, canary, encoding=encoding) is not None


def reflected_context(
    body: bytes,
    canary: str,
    *,
    encoding: str = "utf-8",
    window: int = 80,
) -> str | None:
    """Return ±``window`` chars around the first exact canary match, or None.

    Collapses whitespace in the excerpt for readability in JSONL/raw logs.
    """
    if not body or not canary:
        return None
    try:
        text = body.decode(encoding, errors="replace")
    except Exception:
        return None
    index = text.find(canary)  # exact, case-sensitive
    if index < 0:
        return None
    start = max(0, index - window)
    end = min(len(text), index + len(canary) + window)
    excerpt = text[start:end]
    # Single-line for JSONL / raw artifact readability.
    excerpt = " ".join(excerpt.split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{excerpt}{suffix}"
