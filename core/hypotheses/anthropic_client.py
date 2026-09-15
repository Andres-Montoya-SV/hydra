"""Claude API client wrapper for the hypothesis engine
(docs/HYPOTHESIS_ENGINE_DESIGN.md Part B). Lazy-imports `anthropic` so
importing this module never fails when the optional dependency isn't
installed. A thin wrapper over `core.llm.client`'s shared primitives —
see that module's own docstring for the re-verification this round did
against the real installed SDK before any of this was written.
"""

from __future__ import annotations

from core.hypotheses.errors import HypothesisAPIError
from core.hypotheses.prompt import ADVERSARIAL_SYSTEM_PROMPT, SYSTEM_PROMPT
from core.hypotheses.schema import HypothesisBatchResult, ReasoningSoundnessBatchResult
from core.llm.client import anthropic_count_tokens, anthropic_structured_call

__all__ = ["HypothesisAPIError", "AnthropicHypothesisClient"]


class AnthropicHypothesisClient:
    """Thin wrapper around `anthropic.Anthropic().messages.{parse,count_tokens}`.
    Construction itself never makes a network call. Implements the
    `core.hypotheses.provider.HypothesisProvider` protocol.
    """

    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise HypothesisAPIError(
                "The 'anthropic' package is not installed. It is an optional "
                "dependency — install it with: pip install -r requirements-optional.txt"
            ) from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def count_input_tokens(self, user_message: str) -> int:
        """Real input-token count for this exact batch, via the free,
        no-beta-header `count_tokens` endpoint — not a local estimate."""
        return anthropic_count_tokens(
            self._anthropic,
            self._client,
            model=self.model,
            system=SYSTEM_PROMPT,
            user_message=user_message,
            output_format=HypothesisBatchResult,
            error_cls=HypothesisAPIError,
        )

    def propose_hypotheses(self, user_message: str) -> HypothesisBatchResult:
        """The one batched hypothesis-generation call for this run —
        full evidence graph once, adaptive thinking at medium effort,
        structured output."""
        return anthropic_structured_call(
            self._anthropic,
            self._client,
            model=self.model,
            system=SYSTEM_PROMPT,
            user_message=user_message,
            output_format=HypothesisBatchResult,
            error_cls=HypothesisAPIError,
            empty_output_message=(
                "Claude's response did not include a structured output — this should not "
                "happen with output_format set; treat this run as having produced zero "
                "hypotheses, not as a real empty-list answer."
            ),
        )

    def review_hypotheses(self, user_message: str) -> ReasoningSoundnessBatchResult:
        """Reasoning-soundness review call (design Part C, Section 4.2):
        review the already-produced hypotheses' reasoning, never generate
        a fresh independent hypothesis list."""
        return anthropic_structured_call(
            self._anthropic,
            self._client,
            model=self.model,
            system=ADVERSARIAL_SYSTEM_PROMPT,
            user_message=user_message,
            output_format=ReasoningSoundnessBatchResult,
            error_cls=HypothesisAPIError,
            empty_output_message=(
                "Claude's reasoning-review response did not include a structured output — "
                "treat this run's review as failed, not as zero challenges."
            ),
        )
