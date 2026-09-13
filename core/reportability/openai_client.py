"""OpenAI API client wrapper for the reportability agent (design v2:
provider-agnostic reportability agent). Mirrors
`core.reportability.client.AnthropicClient`'s shape exactly — same
`ReportabilityProvider` protocol, same Pydantic schema classes, same
prompts — so nothing downstream of `core.reportability.provider.create_provider`
needs to know which provider it is holding.

Lazy-imports `openai` for the same reason `client.py` lazy-imports
`anthropic`: importing this module must never fail when the optional
dependency isn't installed.

Verified against the current OpenAI API documentation before writing this
(no `openai` package was available in this environment to read SDK source
from directly, unlike `anthropic==1.5.0` which was verified against
installed source — see docs/REPORTABILITY_AGENT_DESIGN.md v2 addendum for
the honest caveat this leaves): structured output is
`client.responses.parse(model=..., instructions=..., input=..., text_format=<PydanticModel>)`,
and the parsed result is `response.output_parsed`
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

from core.reportability.errors import ReportabilityAPIError
from core.reportability.prompt import (
    ADVERSARIAL_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_adversarial_user_message,
    build_user_message,
)
from core.reportability.schema import AdversarialBatchResult, ReportabilityBatchResult

__all__ = ["ReportabilityAPIError", "OpenAIClient"]

# Rough characters-per-token ratio for English prose — the same
# approximation OpenAI's own cookbook uses as a quick estimate before
# reaching for tiktoken. Good enough for a pre-spend cost ESTIMATE, not
# used for anything that requires an exact count.
_APPROX_CHARS_PER_TOKEN = 4


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
        return max(1, len(text) // _APPROX_CHARS_PER_TOKEN)

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult:
        """The one batched classification call for this run (design Part
        B.2), via the OpenAI Responses API's structured-output support."""
        try:
            response = self._client.responses.parse(
                model=self.model,
                instructions=SYSTEM_PROMPT,
                input=build_user_message(rules_text, findings),
                text_format=ReportabilityBatchResult,
            )
        except Exception as exc:  # re-raised as one domain type below
            raise ReportabilityAPIError(_describe(self._openai, exc)) from exc
        parsed = response.output_parsed
        if parsed is None:
            raise ReportabilityAPIError(
                "OpenAI's response did not include a structured output — this should not "
                "happen with text_format set; treat this run's assessment as failed, not "
                "as zero findings."
            )
        return parsed

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
        try:
            response = self._client.responses.parse(
                model=self.model,
                instructions=ADVERSARIAL_SYSTEM_PROMPT,
                input=message,
                text_format=AdversarialBatchResult,
            )
        except Exception as exc:  # re-raised as one domain type below
            raise ReportabilityAPIError(_describe(self._openai, exc)) from exc
        parsed = response.output_parsed
        if parsed is None:
            raise ReportabilityAPIError(
                "OpenAI's adversarial review response did not include a structured output — "
                "treat this run's review as failed, not as zero challenges."
            )
        return parsed


def _describe(openai_module, exc: Exception) -> str:  # type: ignore[no-untyped-def]
    """Most-specific-first classification of an OpenAI SDK exception into a
    clear, actionable message — never a bare re-raise of the SDK's own
    message alone. Mirrors `core.reportability.client._describe`."""
    if isinstance(exc, openai_module.AuthenticationError):
        return "OPENAI_API_KEY was rejected by the API — check the key is valid and active."
    if isinstance(exc, openai_module.PermissionDeniedError):
        return "The API key lacks permission for this request."
    if isinstance(exc, openai_module.NotFoundError):
        return "The requested model was not found — check OPENAI_MODEL."
    if isinstance(exc, openai_module.RateLimitError):
        return "Rate limited by the OpenAI API — wait and retry."
    if isinstance(exc, openai_module.InternalServerError):
        return f"OpenAI API server error — retry later ({exc})."
    if isinstance(exc, openai_module.APIStatusError):
        return f"OpenAI API rejected the request: {exc}"
    if isinstance(exc, openai_module.APIConnectionError):
        return "Could not reach the OpenAI API — check network connectivity."
    return f"Unexpected error calling the OpenAI API: {exc}"
