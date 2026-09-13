"""core/reportability/openai_client.py (OpenAIClient) — design v2. The
real OpenAI API call is mocked in every test here — none of these spend
real credits. There is no OpenAI equivalent of tests/test_reportability_live.py
since no OPENAI_API_KEY is expected to be available in this environment
either (see docs/REPORTABILITY_AGENT_DESIGN.md v2 addendum for this
explicit, honest limitation).
"""

from __future__ import annotations

import pytest

openai = pytest.importorskip("openai")
pytest.importorskip("httpx2")

from core.reportability.openai_client import OpenAIClient, ReportabilityAPIError  # noqa: E402
from core.reportability.prompt import ADVERSARIAL_SYSTEM_PROMPT, SYSTEM_PROMPT  # noqa: E402
from core.reportability.schema import (  # noqa: E402
    AdversarialBatchResult,
    AdversarialFindingChallenge,
    FindingAssessment,
    ReportabilityBatchResult,
)

_FINDINGS = [
    {
        "id": 1,
        "host": "admin.stripchat.com",
        "template_id": "exposed-admin-panel",
        "severity": "high",
        "name": "Exposed admin panel",
        "description": "Login page reachable without VPN",
        "url": "https://admin.stripchat.com/login",
    }
]


def _assessment(**overrides: object) -> FindingAssessment:
    kwargs: dict[str, object] = dict(
        finding_id=1,
        eligibility="NOT_ELIGIBLE",
        confidence="HIGH",
        rule_citation="Vulnerabilities discovered on any other domains...",
        reasoning="Host is not in the program's listed scope.",
    )
    kwargs.update(overrides)
    return FindingAssessment(**kwargs)


class TestOpenAIClientConstruction:
    def test_missing_openai_package_raises_reportability_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "openai":
                raise ImportError("simulated: openai not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(ReportabilityAPIError, match="not installed"):
            OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")

    def test_exposes_name_and_model(self) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")
        assert client.name == "openai"
        assert client.model == "gpt-5.6-terra"


class TestCountInputTokens:
    def test_is_a_positive_approximation_that_scales_with_input_size(self) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")
        small = client.count_input_tokens("short rules", _FINDINGS)
        large = client.count_input_tokens("much longer rules text " * 200, _FINDINGS)
        assert small > 0
        assert large > small


class TestAssessBatch:
    def test_returns_the_parsed_structured_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")
        expected = ReportabilityBatchResult(assessments=[_assessment()])

        class _FakeResponse:
            output_parsed = expected

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        result = client.assess_batch("RULES TEXT", _FINDINGS)
        assert result is expected

    def test_none_output_parsed_raises_reportability_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")

        class _FakeResponse:
            output_parsed = None

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        with pytest.raises(ReportabilityAPIError, match="did not include a structured output"):
            client.assess_batch("RULES TEXT", _FINDINGS)

    def test_passes_instructions_and_text_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")
        captured: dict[str, object] = {}

        class _FakeResponse:
            output_parsed = ReportabilityBatchResult(assessments=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.responses, "parse", _fake_parse)
        client.assess_batch("RULES TEXT", _FINDINGS)
        assert captured["instructions"] == SYSTEM_PROMPT
        assert captured["text_format"] is ReportabilityBatchResult
        assert captured["model"] == "gpt-5.6-terra"
        assert "RULES TEXT" in captured["input"]


class TestReviewBatch:
    def test_returns_the_parsed_adversarial_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")
        expected = AdversarialBatchResult(
            reviews=[
                AdversarialFindingChallenge(
                    finding_id=1, challenge="AGREE", reasoning="Citation checks out."
                )
            ]
        )

        class _FakeResponse:
            output_parsed = expected

        monkeypatch.setattr(client._client.responses, "parse", lambda **kwargs: _FakeResponse())
        primary = ReportabilityBatchResult(assessments=[_assessment()])
        result = client.review_batch("RULES TEXT", _FINDINGS, primary)
        assert result is expected

    def test_uses_the_adversarial_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")
        captured: dict[str, object] = {}

        class _FakeResponse:
            output_parsed = AdversarialBatchResult(reviews=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.responses, "parse", _fake_parse)
        primary = ReportabilityBatchResult(assessments=[_assessment()])
        client.review_batch("RULES TEXT", _FINDINGS, primary)
        assert captured["instructions"] == ADVERSARIAL_SYSTEM_PROMPT
        assert captured["text_format"] is AdversarialBatchResult


class TestExceptionMapping:
    """OpenAI SDK exceptions are re-raised as one ReportabilityAPIError
    with a clear, actionable message — mirrors
    tests/test_reportability_client.py::TestExceptionMapping."""

    def _client(self) -> OpenAIClient:
        return OpenAIClient(api_key="sk-fake", model="gpt-5.6-terra")

    def _fake_response(self, status_code: int):
        import httpx2

        request = httpx2.Request("POST", "https://api.openai.com/v1/responses")
        return httpx2.Response(status_code, request=request, json={})

    def test_authentication_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        err = openai.AuthenticationError(
            "invalid api key", response=self._fake_response(401), body=None
        )
        client = self._client()
        monkeypatch.setattr(
            client._client.responses, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(ReportabilityAPIError, match="rejected"):
            client.assess_batch("RULES", _FINDINGS)

    def test_rate_limit_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        err = openai.RateLimitError("rate limited", response=self._fake_response(429), body=None)
        client = self._client()
        monkeypatch.setattr(
            client._client.responses, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(ReportabilityAPIError, match="Rate limited"):
            client.assess_batch("RULES", _FINDINGS)

    def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx2

        err = openai.APIConnectionError(request=httpx2.Request("POST", "https://api.openai.com"))
        client = self._client()
        monkeypatch.setattr(
            client._client.responses, "parse", lambda **kwargs: (_ for _ in ()).throw(err)
        )
        with pytest.raises(ReportabilityAPIError, match="Could not reach"):
            client.assess_batch("RULES", _FINDINGS)
