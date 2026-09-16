"""core/hypotheses/anthropic_client.py (AnthropicHypothesisClient). The
real Anthropic API call is mocked in every test here — none of these
spend real credits. Mirrors tests/test_reportability_client.py's own
structure and exception-mapping coverage, since both wrappers now share
`core.llm.client`'s primitives (design Part B.1).
"""

from __future__ import annotations

import pytest

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from core.hypotheses.anthropic_client import (  # noqa: E402
    AnthropicHypothesisClient,
    HypothesisAPIError,
)
from core.hypotheses.prompt import ADVERSARIAL_SYSTEM_PROMPT, SYSTEM_PROMPT  # noqa: E402
from core.hypotheses.schema import (  # noqa: E402
    HypothesisBatchResult,
    ReasoningSoundnessBatchResult,
)


def _fake_request() -> httpx2.Request:
    return httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _client() -> AnthropicHypothesisClient:
    return AnthropicHypothesisClient(api_key="sk-fake", model="claude-sonnet-5")


class TestConstruction:
    def test_missing_anthropic_package_raises_hypothesis_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "anthropic":
                raise ImportError("simulated: anthropic not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(HypothesisAPIError, match="not installed"):
            AnthropicHypothesisClient(api_key="sk-fake", model="claude-sonnet-5")

    def test_exposes_name_and_model(self) -> None:
        client = _client()
        assert client.name == "anthropic"
        assert client.model == "claude-sonnet-5"

    def test_construction_never_makes_a_network_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fail(*args: object, **kwargs: object) -> None:
            raise AssertionError("construction must not touch the network")

        monkeypatch.setattr(anthropic.Anthropic, "__init__", lambda self, **kw: None)
        _client()  # must not raise/network


class TestProposeHypotheses:
    def test_returns_the_parsed_structured_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()
        expected = HypothesisBatchResult(hypotheses=[])

        class _FakeResponse:
            parsed_output = expected

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        result = client.propose_hypotheses("EVIDENCE")
        assert result is expected

    def test_none_parsed_output_raises_hypothesis_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client()

        class _FakeResponse:
            parsed_output = None

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        with pytest.raises(HypothesisAPIError, match="did not include a structured output"):
            client.propose_hypotheses("EVIDENCE")

    def test_uses_the_primary_system_prompt_and_schema(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client()
        captured: dict[str, object] = {}

        class _FakeResponse:
            parsed_output = HypothesisBatchResult(hypotheses=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.messages, "parse", _fake_parse)
        client.propose_hypotheses("EVIDENCE")
        assert captured["system"] == SYSTEM_PROMPT
        assert captured["output_format"] is HypothesisBatchResult
        assert captured["thinking"] == {"type": "adaptive"}
        assert captured["output_config"] == {"effort": "medium"}
        assert captured["messages"] == [{"role": "user", "content": "EVIDENCE"}]


class TestReviewHypotheses:
    def test_returns_the_parsed_review_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()
        expected = ReasoningSoundnessBatchResult(reviews=[])

        class _FakeResponse:
            parsed_output = expected

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        result = client.review_hypotheses("REVIEW INPUT")
        assert result is expected

    def test_uses_the_adversarial_system_prompt_and_schema(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client()
        captured: dict[str, object] = {}

        class _FakeResponse:
            parsed_output = ReasoningSoundnessBatchResult(reviews=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.messages, "parse", _fake_parse)
        client.review_hypotheses("REVIEW INPUT")
        assert captured["system"] == ADVERSARIAL_SYSTEM_PROMPT
        assert captured["output_format"] is ReasoningSoundnessBatchResult

    def test_none_parsed_output_raises_hypothesis_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client()

        class _FakeResponse:
            parsed_output = None

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        with pytest.raises(HypothesisAPIError, match="reasoning-review response"):
            client.review_hypotheses("REVIEW INPUT")


class TestCountInputTokens:
    def test_returns_the_real_count_from_the_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()

        class _FakeCount:
            input_tokens = 4321

        monkeypatch.setattr(client._client.messages, "count_tokens", lambda **kwargs: _FakeCount())
        assert client.count_input_tokens("EVIDENCE") == 4321


class TestExceptionMapping:
    """Anthropic SDK exceptions are re-raised as one HypothesisAPIError
    with a clear, actionable message — the CLI layer never needs to
    import anthropic's own exception hierarchy."""

    def test_authentication_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = httpx2.Response(401, request=_fake_request(), json={})
        err = anthropic.AuthenticationError("invalid x-api-key", response=response, body=None)
        client = _client()
        monkeypatch.setattr(
            client._client.messages, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="rejected"):
            client.propose_hypotheses("EVIDENCE")

    def test_rate_limit_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = httpx2.Response(429, request=_fake_request(), json={})
        err = anthropic.RateLimitError("rate limited", response=response, body=None)
        client = _client()
        monkeypatch.setattr(
            client._client.messages, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="Rate limited"):
            client.propose_hypotheses("EVIDENCE")

    def test_server_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = httpx2.Response(503, request=_fake_request(), json={})
        err = anthropic.APIStatusError("server exploded", response=response, body=None)
        client = _client()
        monkeypatch.setattr(
            client._client.messages, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="server error"):
            client.propose_hypotheses("EVIDENCE")

    def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        err = anthropic.APIConnectionError(request=_fake_request())
        client = _client()
        monkeypatch.setattr(
            client._client.messages, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="Could not reach"):
            client.propose_hypotheses("EVIDENCE")
