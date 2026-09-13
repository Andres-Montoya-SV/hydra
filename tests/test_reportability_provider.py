"""core/reportability/provider.py — the provider abstraction (design v2).

Importing this module must never require pydantic, anthropic, or openai —
that's exercised implicitly just by this file existing and being
collectable without any `importorskip`, on the same CI runner that lacks
all three (see tests/test_reportability_cli.py's own importorskip guards,
which exist only because THAT file also imports schema.py directly).
"""

from __future__ import annotations

import pytest

from core.reportability.errors import ReportabilityAPIError
from core.reportability.provider import SUPPORTED_PROVIDERS, create_provider


def test_supported_providers_is_exactly_anthropic_and_openai() -> None:
    assert set(SUPPORTED_PROVIDERS) == {"anthropic", "openai"}


def test_unknown_provider_raises_reportability_api_error() -> None:
    with pytest.raises(ReportabilityAPIError, match="Unknown reportability provider"):
        create_provider("cohere", api_key="x", model="y")


def test_anthropic_dispatches_to_anthropic_client(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("anthropic")
    pytest.importorskip("pydantic")
    from core.reportability.client import AnthropicClient

    provider = create_provider("anthropic", api_key="sk-fake", model="claude-sonnet-5")
    assert isinstance(provider, AnthropicClient)
    assert provider.name == "anthropic"
    assert provider.model == "claude-sonnet-5"


def test_openai_dispatches_to_openai_client(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("openai")
    pytest.importorskip("pydantic")
    from core.reportability.openai_client import OpenAIClient

    provider = create_provider("openai", api_key="sk-fake", model="gpt-5.6-terra")
    assert isinstance(provider, OpenAIClient)
    assert provider.name == "openai"
    assert provider.model == "gpt-5.6-terra"
