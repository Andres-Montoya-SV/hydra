"""OpenAI API client wrapper for the reportability agent (design v2:
provider-agnostic reportability agent). Mirrors
`core.reportability.client.AnthropicClient`'s shape exactly — same
`ReportabilityProvider` protocol, same Pydantic schema classes, same
prompts — so nothing downstream of `core.reportability.provider.create_provider`
needs to know which provider it is holding.

Lazy-imports `openai` for the same reason `client.py` lazy-imports
`anthropic`: importing this module must never fail when the optional
dependency isn't installed.

A thin, task-specific wrapper over `core.llm.client`'s shared
"call the structured-output API, map every SDK exception" primitives
(docs/HYPOTHESIS_ENGINE_DESIGN.md Part B.1) — re-verified against the
real installed `openai==3.13.0` package before this refactor (previously
this module's own docstring carried the honest caveat that no `openai`
package was installed to verify against at the time it was first
written; that gap is closed): `client.responses.parse(model=...,
instructions=..., input=..., text_format=<PydanticModel>)` is still the
real signature (confirmed via `inspect.signature` against the installed
SDK), and the parsed result is still `response.output_parsed`
(platform.openai.com/docs/guides/structured-outputs,
platform.openai.com/docs/guides/text). Exception classes
(`AuthenticationError`, `PermissionDeniedError`, `NotFoundError`,
`RateLimitError`, `InternalServerError`, `APIConnectionError`) verified
against platform.openai.com/docs/guides/error-codes.

Unlike Anthropic's `messages.count_tokens`, the OpenAI API has no
free, no-spend endpoint for an exact token count of a prospective
request — `count_input_tokens` below is therefore a clearly-labeled
character-based APPROXIMATION (~4 characters/token), not an exact count.
Adding the `tiktoken` package purely to make this one estimate exact was
judged not worth a second optional dependency for an approximation the
CLI already labels as such; see the design doc for this tradeoff.
"""

from __future__ import annotations

from core.llm.client import openai_approximate_token_count, openai_structured_call
from core.reportability.errors import ReportabilityAPIError
from core.reportability.prompt import (
    ADVERSARIAL_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_adversarial_user_message,
    build_user_message,
)
from core.reportability.schema import AdversarialBatchResult, ReportabilityBatchResult

__all__ = ["ReportabilityAPIError", "OpenAIClient"]


class OpenAIClient:
    """Thin wrapper around `openai.OpenAI().responses.parse()`. Construction
    itself never makes a network call. Implements the
    `core.reportability.provider.ReportabilityProvider` protocol.
    """

    name = "openai"

    def __init__(self, api_key: str, model: str) -> None:
        try:
            import openai
        except ImportError as exc:
            raise ReportabilityAPIError(
                "The 'openai' package is not installed. It is an optional "
                "dependency — install it with: pip install -r requirements-optional.txt"
            ) from exc
        self._openai = openai
        self._client = openai.OpenAI(api_key=api_key)
        self.model = model

    def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int:
        """APPROXIMATE input token count (~4 chars/token) — see this
        module's docstring for why this is an estimate, not an exact count
        the way `AnthropicClient.count_input_tokens` is. Never presented to
        the operator without that caveat (see core/reportability/cli.py).
        """
        text = SYSTEM_PROMPT + build_user_message(rules_text, findings)
        return openai_approximate_token_count(text)

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult:
        """The one batched classification call for this run (design Part
        B.2), via the OpenAI Responses API's structured-output support."""
        return openai_structured_call(
            self._openai,
            self._client,
            model=self.model,
            instructions=SYSTEM_PROMPT,
            input_text=build_user_message(rules_text, findings),
            text_format=ReportabilityBatchResult,
            error_cls=ReportabilityAPIError,
            empty_output_message=(
                "OpenAI's response did not include a structured output — this should not "
                "happen with text_format set; treat this run's assessment as failed, not "
                "as zero findings."
            ),
        )

    def review_batch(
        self,
        rules_text: str,
        findings: list[dict[str, object]],
        primary_result: ReportabilityBatchResult,
    ) -> AdversarialBatchResult:
        """Adversarial cross-validation call (design v2): review another
        provider's already-produced structured verdicts, never a fresh
        independent classification from scratch (see
        core.reportability.prompt.ADVERSARIAL_SYSTEM_PROMPT).
        """
        message = build_adversarial_user_message(rules_text, findings, primary_result.assessments)
        return openai_structured_call(
            self._openai,
            self._client,
            model=self.model,
            instructions=ADVERSARIAL_SYSTEM_PROMPT,
            input_text=message,
            text_format=AdversarialBatchResult,
            error_cls=ReportabilityAPIError,
            empty_output_message=(
                "OpenAI's adversarial review response did not include a structured output — "
                "treat this run's review as failed, not as zero challenges."
            ),
        )
