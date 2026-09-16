"""core/hypotheses/provider.py — the provider abstraction (docs/
HYPOTHESIS_ENGINE_DESIGN.md Part B.1). Importing this module must never
require pydantic, anthropic, or openai — exercised implicitly just by
this file existing and being collectable without any `importorskip`,
mirroring tests/test_reportability_provider.py's own reasoning.
"""

from __future__ import annotations

import pytest

from core.hypotheses.errors import HypothesisAPIError
from core.hypotheses.provider import SUPPORTED_PROVIDERS, create_provider


def test_supported_providers_is_exactly_anthropic_and_openai() -> None:
    assert set(SUPPORTED_PROVIDERS) == {"anthropic", "openai"}


def test_unknown_provider_raises_hypothesis_api_error() -> None:
    with pytest.raises(HypothesisAPIError, match="Unknown hypothesis provider"):
        create_provider("cohere", api_key="x", model="y")


def test_anthropic_dispatches_to_anthropic_hypothesis_client() -> None:
    pytest.importorskip("anthropic")
    pytest.importorskip("pydantic")
    from core.hypotheses.anthropic_client import AnthropicHypothesisClient

    provider = create_provider("anthropic", api_key="sk-fake", model="claude-sonnet-5")
    assert isinstance(provider, AnthropicHypothesisClient)
    assert provider.name == "anthropic"
    assert provider.model == "claude-sonnet-5"


def test_openai_dispatches_to_openai_hypothesis_client() -> None:
    pytest.importorskip("openai")
    pytest.importorskip("pydantic")
    from core.hypotheses.openai_client import OpenAIHypothesisClient

    provider = create_provider("openai", api_key="sk-fake", model="gpt-5.6-terra")
    assert isinstance(provider, OpenAIHypothesisClient)
    assert provider.name == "openai"
    assert provider.model == "gpt-5.6-terra"
