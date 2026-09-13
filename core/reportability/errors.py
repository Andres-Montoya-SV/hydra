"""Shared exception type for both LLM providers (design v2: Claude +
OpenAI). Kept in its own module so `client.py` (Anthropic) and
`openai_client.py` never need to import from each other just to share one
exception class.
"""

from __future__ import annotations


class ReportabilityAPIError(Exception):
    """Wraps any provider SDK exception with a clear, actionable message —
    the CLI layer catches this one type instead of importing a specific
    provider's own exception hierarchy.
    """


class BatchValidationError(Exception):
    """Raised when a provider's structured batch response does not exactly
    match the requested finding_id set — missing, duplicate, or unexpected
    IDs (design v2, exact-batch-validation). The whole batch is rejected;
    nothing is persisted. This is deliberately not recoverable by
    discarding just the bad entries and continuing with the rest — a
    provider that can't reliably echo back the exact IDs it was given for
    part of a batch has given no reason to trust the rest of that same
    batch either.
    """
