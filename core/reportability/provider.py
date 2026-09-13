"""Provider abstraction for the reportability agent (design v2): a single
`ReportabilityProvider` protocol that `AnthropicClient` and `OpenAIClient`
both satisfy structurally, so `core/reportability/cli.py` never branches
on which provider it is holding — no per-provider `if` in any code past
`create_provider` below.

Deliberately NOT a class hierarchy (no shared base class, no ABC) — a
`Protocol` is enough here since both implementations already share nothing
but a method shape, and a base class would just be ceremony (design v2's
own instruction to avoid overengineering).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from core.reportability.errors import ReportabilityAPIError

if TYPE_CHECKING:
    # Deferred: core.reportability.schema imports pydantic, an optional
    # dependency (requirements-optional.txt). `from __future__ import
    # annotations` above means these names are never evaluated at runtime
    # just to type-hint the Protocol methods below — only a type checker
    # ever needs this import, so importing core.reportability.provider
    # itself never requires pydantic to be installed.
    from core.reportability.schema import AdversarialBatchResult, ReportabilityBatchResult

SUPPORTED_PROVIDERS = ("anthropic", "openai")


class ReportabilityProvider(Protocol):
    """Structural interface both `AnthropicClient` and `OpenAIClient`
    satisfy. No provider-specific response shape (an Anthropic
    `Message`/OpenAI `Response` object, a provider's own exception type)
    may leak past this boundary — every method here returns either a
    plain `int` or one of the shared Pydantic schema types every provider
    is given to fill in identically.
    """

    name: str
    model: str

    def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int: ...

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult: ...

    def review_batch(
        self,
        rules_text: str,
        findings: list[dict[str, object]],
        primary_result: ReportabilityBatchResult,
    ) -> AdversarialBatchResult: ...


def create_provider(provider: str, *, api_key: str, model: str) -> ReportabilityProvider:
    """The one place `AnthropicClient`/`OpenAIClient` are chosen between.
    Both imports are deferred (function-local, not at this module's top
    level) so importing `core.reportability.provider` itself never
    requires either optional SDK to be installed.
    """
    if provider == "anthropic":
        from core.reportability.client import AnthropicClient

        return AnthropicClient(api_key=api_key, model=model)
    if provider == "openai":
        from core.reportability.openai_client import OpenAIClient

        return OpenAIClient(api_key=api_key, model=model)
    raise ReportabilityAPIError(
        f"Unknown reportability provider {provider!r} — must be one of {SUPPORTED_PROVIDERS}."
    )
