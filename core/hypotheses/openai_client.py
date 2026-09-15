"""OpenAI API client wrapper for the hypothesis engine
(docs/HYPOTHESIS_ENGINE_DESIGN.md Part B). Mirrors
`core.hypotheses.anthropic_client.AnthropicHypothesisClient`'s shape
exactly — same `HypothesisProvider` protocol, same schema classes — so
nothing downstream of `core.hypotheses.provider.create_provider` needs
to know which provider it is holding.

Lazy-imports `openai` for the same reason `anthropic_client.py`
lazy-imports `anthropic`: importing this module must never fail when
the optional dependency isn't installed.

A thin, task-specific wrapper over `core.llm.client`'s shared
primitives — the same shared layer `core.reportability.openai_client`
builds on, re-verified there against the real installed
`openai==3.13.0` package before this round of work; see that module's
docstring and `core/llm/client.py`'s own docstring for the exact
signatures confirmed.

Unlike Anthropic's `messages.count_tokens`, the OpenAI API has no free,
no-spend endpoint for an exact token count of a prospective request —
`count_input_tokens` below is therefore a clearly-labeled character-based
APPROXIMATION (~4 characters/token), not an exact count. Never presented
to the operator without that caveat (see core/hypotheses/cli.py).
"""

from __future__ import annotations

from core.hypotheses.errors import HypothesisAPIError
from core.hypotheses.prompt import ADVERSARIAL_SYSTEM_PROMPT, SYSTEM_PROMPT
from core.hypotheses.schema import HypothesisBatchResult, ReasoningSoundnessBatchResult
from core.llm.client import openai_approximate_token_count, openai_structured_call

__all__ = ["HypothesisAPIError", "OpenAIHypothesisClient"]


class OpenAIHypothesisClient:
    """Thin wrapper around `openai.OpenAI().responses.parse()`. Construction
    itself never makes a network call. Implements the
    `core.hypotheses.provider.HypothesisProvider` protocol.
    """

    name = "openai"

    def __init__(self, api_key: str, model: str) -> None:
        try:
            import openai
        except ImportError as exc:
            raise HypothesisAPIError(
                "The 'openai' package is not installed. It is an optional "
                "dependency — install it with: pip install -r requirements-optional.txt"
            ) from exc
        self._openai = openai
        self._client = openai.OpenAI(api_key=api_key)
        self.model = model

    def count_input_tokens(self, user_message: str) -> int:
        """APPROXIMATE input token count (~4 chars/token) — see this
        module's docstring for why this is an estimate, not an exact count
        the way `AnthropicHypothesisClient.count_input_tokens` is."""
        return openai_approximate_token_count(SYSTEM_PROMPT + user_message)

    def propose_hypotheses(self, user_message: str) -> HypothesisBatchResult:
        """The one batched hypothesis-generation call for this run, via the
        OpenAI Responses API's structured-output support."""
        return openai_structured_call(
            self._openai,
            self._client,
            model=self.model,
            instructions=SYSTEM_PROMPT,
            input_text=user_message,
            text_format=HypothesisBatchResult,
            error_cls=HypothesisAPIError,
            empty_output_message=(
                "OpenAI's response did not include a structured output — this should not "
                "happen with text_format set; treat this run as having produced zero "
                "hypotheses, not as a real empty-list answer."
            ),
        )

    def review_hypotheses(self, user_message: str) -> ReasoningSoundnessBatchResult:
        """Reasoning-soundness review call (design Part C, Section 4.2):
        review the already-produced hypotheses' reasoning, never generate
        a fresh independent hypothesis list."""
        return openai_structured_call(
            self._openai,
            self._client,
            model=self.model,
            instructions=ADVERSARIAL_SYSTEM_PROMPT,
            input_text=user_message,
            text_format=ReasoningSoundnessBatchResult,
            error_cls=HypothesisAPIError,
            empty_output_message=(
                "OpenAI's reasoning-review response did not include a structured output — "
                "treat this run's review as failed, not as zero challenges."
            ),
        )
