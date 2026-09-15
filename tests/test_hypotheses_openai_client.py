"""core/hypotheses/openai_client.py (OpenAIHypothesisClient). The real
OpenAI API call is mocked in every test here — none of these spend real
credits. Mirrors tests/test_reportability_openai_client.py's own
structure, since both wrappers now share `core.llm.client`'s primitives
(design Part B.1).
"""

from __future__ import annotations

import pytest

openai = pytest.importorskip("openai")
pytest.importorskip("httpx2")

from core.hypotheses.openai_client import HypothesisAPIError, OpenAIHypothesisClient  # noqa: E402
from core.hypotheses.prompt import ADVERSARIAL_SYSTEM_PROMPT, SYSTEM_PROMPT  # noqa: E402
from core.hypotheses.schema import (  # noqa: E402
    HypothesisBatchResult,
    ReasoningSoundnessBatchResult,
)


def _client() -> OpenAIHypothesisClient:
    return OpenAIHypothesisClient(api_key="sk-fake", model="gpt-5.6-terra")


class TestConstruction:
    def test_missing_openai_package_raises_hypothesis_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "openai":
                raise ImportError("simulated: openai not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(HypothesisAPIError, match="not installed"):
            OpenAIHypothesisClient(api_key="sk-fake", model="gpt-5.6-terra")

    def test_exposes_name_and_model(self) -> None:
        client = _client()
        assert client.name == "openai"
        assert client.model == "gpt-5.6-terra"


class TestCountInputTokens:
    def test_is_a_positive_approximation_that_scales_with_input_size(self) -> None:
        client = _client()
        small = client.count_input_tokens("short evidence")
        large = client.count_input_tokens("much longer evidence text " * 200)
        assert small > 0
        assert large > small


class TestProposeHypotheses:
    def test_returns_the_parsed_structured_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()
        expected = HypothesisBatchResult(hypotheses=[])

        class _FakeResponse:
            output_parsed = expected

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        result = client.propose_hypotheses("EVIDENCE")
        assert result is expected

    def test_none_output_parsed_raises_hypothesis_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client()

        class _FakeResponse:
            output_parsed = None

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        with pytest.raises(HypothesisAPIError, match="did not include a structured output"):
            client.propose_hypotheses("EVIDENCE")

    def test_passes_instructions_and_text_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()
        captured: dict[str, object] = {}

        class _FakeResponse:
            output_parsed = HypothesisBatchResult(hypotheses=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.responses, "parse", _fake_parse)
        client.propose_hypotheses("EVIDENCE")
        assert captured["instructions"] == SYSTEM_PROMPT
        assert captured["text_format"] is HypothesisBatchResult
        assert captured["model"] == "gpt-5.6-terra"
        assert captured["input"] == "EVIDENCE"


class TestReviewHypotheses:
    def test_returns_the_parsed_review_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()
        expected = ReasoningSoundnessBatchResult(reviews=[])

        class _FakeResponse:
            output_parsed = expected

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        result = client.review_hypotheses("REVIEW INPUT")
        assert result is expected

    def test_uses_the_adversarial_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _client()
        captured: dict[str, object] = {}

        class _FakeResponse:
            output_parsed = ReasoningSoundnessBatchResult(reviews=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.responses, "parse", _fake_parse)
        client.review_hypotheses("REVIEW INPUT")
        assert captured["instructions"] == ADVERSARIAL_SYSTEM_PROMPT
        assert captured["text_format"] is ReasoningSoundnessBatchResult

    def test_none_output_parsed_raises_hypothesis_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _client()

        class _FakeResponse:
            output_parsed = None

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        with pytest.raises(HypothesisAPIError, match="reasoning-review response"):
            client.review_hypotheses("REVIEW INPUT")


class TestExceptionMapping:
    """OpenAI SDK exceptions are re-raised as one HypothesisAPIError with
    a clear, actionable message — mirrors
    tests/test_hypotheses_client.py::TestExceptionMapping."""

    def _fake_response(self, status_code: int):
        import httpx2

        request = httpx2.Request("POST", "https://api.openai.com/v1/responses")
        return httpx2.Response(status_code, request=request, json={})

    def test_authentication_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        err = openai.AuthenticationError(
            "invalid api key", response=self._fake_response(401), body=None
        )
        client = _client()
        monkeypatch.setattr(
            client._client.responses, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="rejected"):
            client.propose_hypotheses("EVIDENCE")

    def test_rate_limit_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        err = openai.RateLimitError("rate limited", response=self._fake_response(429), body=None)
        client = _client()
        monkeypatch.setattr(
            client._client.responses, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="Rate limited"):
            client.propose_hypotheses("EVIDENCE")

    def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx2

        err = openai.APIConnectionError(request=httpx2.Request("POST", "https://api.openai.com"))
        client = _client()
        monkeypatch.setattr(
            client._client.responses, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(HypothesisAPIError, match="Could not reach"):
            client.propose_hypotheses("EVIDENCE")
