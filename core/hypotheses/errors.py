"""Shared exception type for both LLM providers in the hypothesis engine
— mirrors `core.reportability.errors`'s exact reasoning (kept in its own
module so the Anthropic/OpenAI client wrappers never need to import from
each other just to share one exception class). Deliberately a distinct
type from `ReportabilityAPIError`, even though both ultimately wrap the
same kind of SDK error via the same shared `core.llm.client` primitives —
each package's CLI layer catches its own error type, and the two
features stay decoupled beyond the shared client (design Part B.3).
"""

from __future__ import annotations


class HypothesisAPIError(Exception):
    """Wraps any provider SDK exception with a clear, actionable message —
    the CLI layer catches this one type instead of importing a specific
    provider's own exception hierarchy."""
