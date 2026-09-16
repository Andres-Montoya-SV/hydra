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


class HypothesisBatchLimitError(Exception):
    """Raised when a provider's structured hypothesis batch exceeds a hard
    structural limit (hardening round: "el proveedor no debe poder causar
    persistencia sin límite") — too many hypotheses, too many citations on
    one hypothesis, or a text field far longer than any legitimate
    analyst-facing note should be. Deliberately a distinct type from
    `HypothesisAPIError` (an SDK/transport failure) and from a reasoning-
    review batch defect (docs/HYPOTHESIS_ENGINE_DESIGN.md hardening round,
    `core.hypotheses.batch`) — this one means the primary batch itself is
    structurally untrustworthy, so the whole call is refused and nothing
    is persisted, mirroring `core.reportability.errors.BatchValidationError`'s
    own all-or-nothing philosophy.
    """
