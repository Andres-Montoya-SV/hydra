"""Claude API client wrapper for the reportability agent (design Part B,
v2 addendum for the provider abstraction and adversarial cross-validation).

Lazy-imports `anthropic` so importing this module never fails when the
optional dependency isn't installed — the `assess-reportability` command
checks for both the package and `ANTHROPIC_API_KEY` before ever reaching
here, but nothing else in this project should be able to break by this
module merely existing on `sys.path`.

A thin, task-specific wrapper over `core.llm.client`'s shared
"call the structured-output API, map every SDK exception" primitives
(docs/HYPOTHESIS_ENGINE_DESIGN.md Part B.1) — this module owns only the
reportability-specific prompts/schemas and the exact per-call-site error
wording; the actual `messages.parse`/`count_tokens` plumbing and
exception classification live in `core.llm.client`, shared with
`core.hypotheses.provider`.
"""

from __future__ import annotations

from core.llm.client import anthropic_count_tokens, anthropic_structured_call
from core.reportability.errors import ReportabilityAPIError
from core.reportability.prompt import (
    ADVERSARIAL_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_adversarial_user_message,
    build_user_message,
)
from core.reportability.schema import AdversarialBatchResult, ReportabilityBatchResult

__all__ = ["ReportabilityAPIError", "AnthropicClient"]


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
        return anthropic_count_tokens(
            self._anthropic,
            self._client,
            model=self.model,
            system=SYSTEM_PROMPT,
            user_message=build_user_message(rules_text, findings),
            output_format=ReportabilityBatchResult,
            error_cls=ReportabilityAPIError,
        )

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult:
        """The one batched classification call for this run (design Part
        B.2) — full rules text once, every finding in the batch, adaptive
        thinking at medium effort, structured output so the response is
        validated JSON, never freeform text this code has to parse.
        """
        return anthropic_structured_call(
            self._anthropic,
            self._client,
            model=self.model,
            system=SYSTEM_PROMPT,
            user_message=build_user_message(rules_text, findings),
            output_format=ReportabilityBatchResult,
            error_cls=ReportabilityAPIError,
            empty_output_message=(
                "Claude's response did not include a structured output — this should not "
                "happen with output_format set; treat this run's assessment as failed, not "
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
        return anthropic_structured_call(
            self._anthropic,
            self._client,
            model=self.model,
            system=ADVERSARIAL_SYSTEM_PROMPT,
            user_message=message,
            output_format=AdversarialBatchResult,
            error_cls=ReportabilityAPIError,
            empty_output_message=(
                "Claude's adversarial review response did not include a structured output — "
                "treat this run's review as failed, not as zero challenges."
            ),
        )
