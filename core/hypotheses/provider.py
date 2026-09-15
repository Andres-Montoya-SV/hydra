"""Provider abstraction for the hypothesis engine (docs/HYPOTHESIS_ENGINE_DESIGN.md
Part B.1): thin, task-specific wrappers over `core.llm.client`'s shared
structured-output-call primitives — the same generalized layer
`core.reportability.client`/`openai_client` now also build on. A
`Protocol`, not a class hierarchy, for the same reason
`core.reportability.provider` uses one: both implementations already
share nothing but a method shape.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from core.hypotheses.errors import HypothesisAPIError

if TYPE_CHECKING:
    from core.hypotheses.schema import HypothesisBatchResult, ReasoningSoundnessBatchResult

SUPPORTED_PROVIDERS = ("anthropic", "openai")


class HypothesisProvider(Protocol):
    """Structural interface both Anthropic/OpenAI hypothesis clients
    satisfy. No provider-specific response shape may leak past this
    boundary."""

    name: str
    model: str

    def count_input_tokens(self, user_message: str) -> int: ...

    def propose_hypotheses(self, user_message: str) -> HypothesisBatchResult: ...

    def review_hypotheses(self, user_message: str) -> ReasoningSoundnessBatchResult: ...


def create_provider(provider: str, *, api_key: str, model: str) -> HypothesisProvider:
    """The one place the Anthropic/OpenAI hypothesis clients are chosen
    between. Both imports are deferred (function-local) so importing
    `core.hypotheses.provider` itself never requires either optional SDK
    to be installed."""
    if provider == "anthropic":
        from core.hypotheses.anthropic_client import AnthropicHypothesisClient

        return AnthropicHypothesisClient(api_key=api_key, model=model)
    if provider == "openai":
        from core.hypotheses.openai_client import OpenAIHypothesisClient

        return OpenAIHypothesisClient(api_key=api_key, model=model)
    raise HypothesisAPIError(
        f"Unknown hypothesis provider {provider!r} — must be one of {SUPPORTED_PROVIDERS}."
    )
