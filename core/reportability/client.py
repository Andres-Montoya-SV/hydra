"""Claude API client wrapper for the reportability agent (design Part B,
v2 addendum for the provider abstraction and adversarial cross-validation).

Lazy-imports `anthropic` so importing this module never fails when the
optional dependency isn't installed — the `assess-reportability` command
checks for both the package and `ANTHROPIC_API_KEY` before ever reaching
here, but nothing else in this project should be able to break by this
module merely existing on `sys.path`.
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

__all__ = ["ReportabilityAPIError", "AnthropicClient"]

# One non-streaming request per run's batch (design Part B.2/B.3) — batch
# sizes are capped low (Settings.reportability_max_findings_per_batch) so
# output stays well under streaming-timeout territory even without it.
_MAX_TOKENS = 16000


class AnthropicClient:
    """Thin wrapper around `anthropic.Anthropic().messages.{parse,count_tokens}`.
    Construction itself never makes a network call. Implements the
    `core.reportability.provider.ReportabilityProvider` protocol.
    """

    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ReportabilityAPIError(
                "The 'anthropic' package is not installed. It is an optional "
                "dependency — install it with: pip install -r requirements-optional.txt"
            ) from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int:
        """Real input-token count for this exact batch, via the free,
        no-beta-header `count_tokens` endpoint (design Part D.3) — not an
        estimate computed locally, the real count the Messages API would
        see, schema overhead included.
        """
        try:
            response = self._client.messages.count_tokens(
                model=self.model,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": build_user_message(rules_text, findings)}],
                output_format=ReportabilityBatchResult,
            )
        except Exception as exc:  # re-raised as one domain type below
            raise ReportabilityAPIError(_describe(self._anthropic, exc)) from exc
        return response.input_tokens

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult:
        """The one batched classification call for this run (design Part
        B.2) — full rules text once, every finding in the batch, adaptive
        thinking at medium effort, structured output so the response is
        validated JSON, never freeform text this code has to parse.
        """
        try:
            response = self._client.messages.parse(
                model=self.model,
                max_tokens=_MAX_TOKENS,
                thinking={"type": "adaptive"},
                output_config={"effort": "medium"},
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": build_user_message(rules_text, findings)}],
                output_format=ReportabilityBatchResult,
            )
        except Exception as exc:  # re-raised as one domain type below
            raise ReportabilityAPIError(_describe(self._anthropic, exc)) from exc
        if response.parsed_output is None:
            raise ReportabilityAPIError(
                "Claude's response did not include a structured output — this should not "
                "happen with output_format set; treat this run's assessment as failed, not "
                "as zero findings."
            )
        return response.parsed_output

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
            response = self._client.messages.parse(
                model=self.model,
                max_tokens=_MAX_TOKENS,
                thinking={"type": "adaptive"},
                output_config={"effort": "medium"},
                system=ADVERSARIAL_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": message}],
                output_format=AdversarialBatchResult,
            )
        except Exception as exc:  # re-raised as one domain type below
            raise ReportabilityAPIError(_describe(self._anthropic, exc)) from exc
        if response.parsed_output is None:
            raise ReportabilityAPIError(
                "Claude's adversarial review response did not include a structured output — "
                "treat this run's review as failed, not as zero challenges."
            )
        return response.parsed_output


def _describe(anthropic_module, exc: Exception) -> str:  # type: ignore[no-untyped-def]
    """Most-specific-first classification of an Anthropic SDK exception
    into a clear, actionable message — never a bare re-raise of the SDK's
    own message alone."""
    if isinstance(exc, anthropic_module.AuthenticationError):
        return "ANTHROPIC_API_KEY was rejected by the API — check the key is valid and active."
    if isinstance(exc, anthropic_module.PermissionDeniedError):
        return "The API key lacks permission for this request."
    if isinstance(exc, anthropic_module.NotFoundError):
        return "The requested model was not found — check ANTHROPIC_MODEL."
    if isinstance(exc, anthropic_module.RateLimitError):
        return "Rate limited by the Anthropic API — wait and retry."
    if isinstance(exc, anthropic_module.APIStatusError):
        if exc.status_code >= 500:
            return f"Anthropic API server error ({exc.status_code}) — retry later."
        return f"Anthropic API rejected the request: {exc.message}"
    if isinstance(exc, anthropic_module.APIConnectionError):
        return "Could not reach the Anthropic API — check network connectivity."
    return f"Unexpected error calling the Anthropic API: {exc}"
