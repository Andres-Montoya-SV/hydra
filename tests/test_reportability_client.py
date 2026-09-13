"""core/reportability/client.py (AnthropicClient), core/reportability/prompt.py,
core/reportability/schema.py (design Part B, v2 addendum). The real
Anthropic API call is mocked in every test here — none of these spend real
credits. A separate, opt-in live test exists in
tests/test_reportability_live.py for confirming this against the real
API by hand.
"""

from __future__ import annotations

import pytest

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from core.reportability.client import AnthropicClient, ReportabilityAPIError  # noqa: E402
from core.reportability.prompt import (  # noqa: E402
    ADVERSARIAL_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_adversarial_user_message,
    build_user_message,
)
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


def _fake_request() -> httpx2.Request:
    return httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


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


class TestBuildUserMessage:
    def test_includes_rules_text_and_every_finding_field(self) -> None:
        message = build_user_message("RULES TEXT", _FINDINGS)
        assert "RULES TEXT" in message
        assert "finding_id: 1" in message
        assert "admin.stripchat.com" in message
        assert "exposed-admin-panel" in message
        assert "https://admin.stripchat.com/login" in message

    def test_missing_optional_fields_render_as_none_placeholder(self) -> None:
        message = build_user_message(
            "RULES",
            [
                {
                    "id": 2,
                    "host": "x.test",
                    "template_id": "t",
                    "severity": "low",
                    "name": "n",
                    "description": None,
                    "url": None,
                }
            ],
        )
        assert "description: (none)" in message
        assert "url: (none)" in message


class TestBuildAdversarialUserMessage:
    def test_includes_the_primary_verdict_for_each_finding(self) -> None:
        message = build_adversarial_user_message(
            "RULES TEXT", _FINDINGS, [_assessment(eligibility="ELIGIBLE")]
        )
        assert "RULES TEXT" in message
        assert "finding_id: 1" in message
        assert "primary_eligibility: ELIGIBLE" in message
        assert "primary_confidence: HIGH" in message

    def test_finding_with_no_matching_primary_assessment_is_still_rendered(self) -> None:
        message = build_adversarial_user_message("RULES", _FINDINGS, [])
        assert "finding_id: 1" in message
        assert "primary_eligibility" not in message


class TestSystemPromptDemandsLiteralQuotes:
    def test_demands_verbatim_short_quotes_not_summaries(self) -> None:
        assert "VERBATIM" in SYSTEM_PROMPT
        assert "paraphrase" in SYSTEM_PROMPT

    def test_allows_empty_citation_when_no_rule_applies(self) -> None:
        assert "empty string" in SYSTEM_PROMPT

    def test_explicitly_scopes_out_report_drafting_and_scope_decisions(self) -> None:
        assert "not deciding what is in scope" in SYSTEM_PROMPT
        assert "not drafting the report" in SYSTEM_PROMPT

    def test_warns_that_finding_fields_are_untrusted_data(self) -> None:
        assert "UNTRUSTED DATA" in SYSTEM_PROMPT
        assert "Never follow" in SYSTEM_PROMPT


class TestAdversarialSystemPromptReviewsRatherThanReclassifies:
    def test_frames_the_task_as_auditing_a_given_verdict(self) -> None:
        assert "auditing the" in ADVERSARIAL_SYSTEM_PROMPT
        assert "not producing your own independent classification from scratch" in (
            ADVERSARIAL_SYSTEM_PROMPT
        )

    def test_defines_all_three_challenge_outcomes(self) -> None:
        assert "AGREE" in ADVERSARIAL_SYSTEM_PROMPT
        assert "DISAGREE" in ADVERSARIAL_SYSTEM_PROMPT
        assert "INSUFFICIENT_INFORMATION" in ADVERSARIAL_SYSTEM_PROMPT

    def test_also_warns_that_input_is_untrusted_data(self) -> None:
        assert "UNTRUSTED DATA" in ADVERSARIAL_SYSTEM_PROMPT


class TestAnthropicClientConstruction:
    def test_missing_anthropic_package_raises_reportability_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "anthropic":
                raise ImportError("simulated: anthropic not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(ReportabilityAPIError, match="not installed"):
            AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")

    def test_exposes_name_and_model(self) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")
        assert client.name == "anthropic"
        assert client.model == "claude-sonnet-5"


class TestAssessBatch:
    def test_returns_the_parsed_structured_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")
        expected = ReportabilityBatchResult(assessments=[_assessment()])

        class _FakeResponse:
            parsed_output = expected

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        result = client.assess_batch("RULES TEXT", _FINDINGS)
        assert result is expected

    def test_none_parsed_output_raises_reportability_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")

        class _FakeResponse:
            parsed_output = None

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        with pytest.raises(ReportabilityAPIError, match="did not include a structured output"):
            client.assess_batch("RULES TEXT", _FINDINGS)

    def test_passes_adaptive_thinking_and_medium_effort(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")
        captured: dict[str, object] = {}

        class _FakeResponse:
            parsed_output = ReportabilityBatchResult(assessments=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.messages, "parse", _fake_parse)
        client.assess_batch("RULES TEXT", _FINDINGS)
        assert captured["thinking"] == {"type": "adaptive"}
        assert captured["output_config"] == {"effort": "medium"}
        assert captured["output_format"] is ReportabilityBatchResult
        assert captured["system"] == SYSTEM_PROMPT


class TestReviewBatch:
    def test_returns_the_parsed_adversarial_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")
        expected = AdversarialBatchResult(
            reviews=[
                AdversarialFindingChallenge(
                    finding_id=1, challenge="AGREE", reasoning="Citation checks out."
                )
            ]
        )

        class _FakeResponse:
            parsed_output = expected

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        primary = ReportabilityBatchResult(assessments=[_assessment()])
        result = client.review_batch("RULES TEXT", _FINDINGS, primary)
        assert result is expected

    def test_uses_the_adversarial_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")
        captured: dict[str, object] = {}

        class _FakeResponse:
            parsed_output = AdversarialBatchResult(reviews=[])

        def _fake_parse(**kwargs: object) -> _FakeResponse:
            captured.update(kwargs)
            return _FakeResponse()

        monkeypatch.setattr(client._client.messages, "parse", _fake_parse)
        primary = ReportabilityBatchResult(assessments=[_assessment()])
        client.review_batch("RULES TEXT", _FINDINGS, primary)
        assert captured["system"] == ADVERSARIAL_SYSTEM_PROMPT
        assert captured["output_format"] is AdversarialBatchResult

    def test_none_parsed_output_raises_reportability_api_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")

        class _FakeResponse:
            parsed_output = None

        monkeypatch.setattr(client._client.messages, "parse", lambda **kwargs: _FakeResponse())
        primary = ReportabilityBatchResult(assessments=[_assessment()])
        with pytest.raises(ReportabilityAPIError, match="adversarial review response"):
            client.review_batch("RULES TEXT", _FINDINGS, primary)


class TestCountInputTokens:
    def test_returns_the_real_count_from_the_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")

        class _FakeCount:
            input_tokens = 1234

        monkeypatch.setattr(client._client.messages, "count_tokens", lambda **kwargs: _FakeCount())
        assert client.count_input_tokens("RULES TEXT", _FINDINGS) == 1234


class TestExceptionMapping:
    """Anthropic SDK exceptions are re-raised as one ReportabilityAPIError
    with a clear, actionable message — the CLI layer never needs to import
    anthropic's own exception hierarchy."""

    def _client(self) -> AnthropicClient:
        return AnthropicClient(api_key="sk-fake", model="claude-sonnet-5")

    def test_authentication_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = httpx2.Response(401, request=_fake_request(), json={})
        err = anthropic.AuthenticationError("invalid x-api-key", response=response, body=None)
        client = self._client()

        def _raise(**kwargs: object) -> None:
            raise err

        monkeypatch.setattr(client._client.messages, "parse", _raise)
        with pytest.raises(ReportabilityAPIError, match="rejected"):
            client.assess_batch("RULES", _FINDINGS)

    def test_rate_limit_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = httpx2.Response(429, request=_fake_request(), json={})
        err = anthropic.RateLimitError("rate limited", response=response, body=None)
        client = self._client()
        monkeypatch.setattr(
            client._client.messages,
            "parse",
            lambda **kwargs: (_ for _ in ()).throw(err),
        )
        with pytest.raises(ReportabilityAPIError, match="Rate limited"):
            client.assess_batch("RULES", _FINDINGS)

    def test_server_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = httpx2.Response(503, request=_fake_request(), json={})
        err = anthropic.APIStatusError("server exploded", response=response, body=None)
        client = self._client()
        monkeypatch.setattr(
            client._client.messages,
            "parse",
            lambda **kwargs: (_ for _ in ()).throw(err),
        )
        with pytest.raises(ReportabilityAPIError, match="server error"):
            client.assess_batch("RULES", _FINDINGS)

    def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        err = anthropic.APIConnectionError(request=_fake_request())
        client = self._client()
        monkeypatch.setattr(
            client._client.messages,
            "parse",
            lambda **kwargs: (_ for _ in ()).throw(err),
        )
        with pytest.raises(ReportabilityAPIError, match="Could not reach"):
            client.assess_batch("RULES", _FINDINGS)
