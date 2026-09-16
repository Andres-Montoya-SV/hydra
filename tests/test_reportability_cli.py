"""core/reportability/cli.py::cmd_assess_reportability — the standalone
`python app.py assess-reportability` command (design Part D, v2 addendum
for provider selection, exact-batch-validation, and adversarial cross-
validation). The real Anthropic/OpenAI API calls are always mocked here —
`core.reportability.cli.create_provider` is monkeypatched, so these tests
don't even need the `anthropic`/`openai` packages installed... except
`core.reportability.schema.FindingAssessment` (a pydantic model, used to
build fake provider responses) does — hence the importorskip guards below.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("anthropic")
pytest.importorskip("pydantic")

from config.settings import Settings  # noqa: E402
from core.assets import Finding, Host, RiskLevel, ScanRun  # noqa: E402
from core.reportability.cli import cmd_assess_reportability  # noqa: E402
from core.reportability.errors import ReportabilityAPIError  # noqa: E402
from core.reportability.schema import (  # noqa: E402
    AdversarialBatchResult,
    AdversarialFindingChallenge,
    FindingAssessment,
    ReportabilityBatchResult,
)
from core.store import AssetStore  # noqa: E402

RUN_ID = "run1"


def _settings(project_root: Path, **overrides: object) -> Settings:
    kwargs: dict[str, object] = {
        "project_root": project_root,
        "anthropic_api_key": "sk-fake",
        "anthropic_model": "claude-sonnet-5",
        "openai_api_key": "sk-fake-openai",
        "openai_model": "gpt-5.6-terra",
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def _seed_run(project_root: Path, *, hosts: list[Host] | None = None) -> AssetStore:
    (project_root / "output").mkdir(parents=True, exist_ok=True)
    db_path = project_root / "output" / "recon.db"
    run_dir = project_root / "output" / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=["x.test"]))
    if hosts is None:
        hosts = [
            Host(
                domain="admin.x.test",
                hostname="admin.x.test",
                risk_level=RiskLevel.HIGH,
                risk_score=70,
                findings=[
                    Finding(
                        host="admin.x.test",
                        template_id="exposed-admin-panel",
                        severity="high",
                        name="Exposed admin panel",
                        source="nuclei",
                        description="Login reachable without VPN",
                        url="https://admin.x.test/login",
                    )
                ],
            )
        ]
    store.persist_registry(RUN_ID, {h.domain: h for h in hosts})
    return store


def _rules_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.txt"
    path.write_text(text, encoding="utf-8")
    return path


RULES_TEXT = (
    "Vulnerabilities discovered on any other domains, applications, or "
    "third-party services not owned or operated by Stripchat are "
    "considered out of scope and not eligible for rewards.\n"
)


def _finding_assessment(**overrides: object) -> FindingAssessment:
    kwargs: dict[str, object] = dict(
        finding_id=1,
        eligibility="NOT_ELIGIBLE",
        confidence="HIGH",
        rule_citation="",
        reasoning="default reasoning",
    )
    kwargs.update(overrides)
    return FindingAssessment(**kwargs)


class _FakeProvider:
    """Stand-in for AnthropicClient/OpenAIClient — never touches a real
    SDK. `assessments`/`reviews` may be a list (used verbatim) or a
    zero-arg callable (invoked per call, so a test can compute finding_ids
    dynamically or raise)."""

    name = "fake"
    model = "fake-model"

    def __init__(
        self, assessments=None, reviews=None, review_error: Exception | None = None
    ) -> None:
        self._assessments = assessments if assessments is not None else []
        self._reviews = reviews if reviews is not None else []
        self._review_error = review_error

    def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int:
        return 500

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult:
        items = self._assessments() if callable(self._assessments) else self._assessments
        return ReportabilityBatchResult(assessments=items)

    def review_batch(
        self, rules_text: str, findings: list[dict[str, object]], primary_result
    ) -> AdversarialBatchResult:
        if self._review_error is not None:
            raise self._review_error
        items = self._reviews() if callable(self._reviews) else self._reviews
        return AdversarialBatchResult(reviews=items)


def _patch_provider(
    monkeypatch: pytest.MonkeyPatch,
    *,
    primary: _FakeProvider | None = None,
    adversarial: _FakeProvider | None = None,
) -> None:
    providers = {"anthropic": primary, "openai": adversarial}

    def _fake_create_provider(provider: str, *, api_key: str, model: str):
        chosen = providers.get(provider)
        if chosen is None:
            raise AssertionError(f"unexpected provider requested: {provider}")
        return chosen

    monkeypatch.setattr("core.reportability.cli.create_provider", _fake_create_provider)


class TestMissingApiKey:
    def test_refuses_cleanly_without_crashing(self, tmp_path: Path) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path, anthropic_api_key=None)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1

    def test_missing_openai_key_refuses_when_openai_is_the_provider(self, tmp_path: Path) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path, openai_api_key=None)
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), provider="openai"
        )
        assert rc == 1

    def test_missing_adversarial_key_refuses(self, tmp_path: Path) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path, openai_api_key=None)
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            adversarial_provider="openai",
        )
        assert rc == 1


class TestProviderSelection:
    def test_unsupported_provider_name_refuses(self, tmp_path: Path) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), provider="cohere"
        )
        assert rc == 1

    def test_adversarial_provider_same_as_primary_refuses(self, tmp_path: Path) -> None:
        """design v2: cross-validating a provider against itself shares
        the same failure modes and defeats the entire point."""
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            provider="anthropic",
            adversarial_provider="anthropic",
        )
        assert rc == 1


class TestMissingDatabaseOrRun:
    def test_missing_database_refuses(self, tmp_path: Path) -> None:
        (tmp_path / "output").mkdir()
        settings = _settings(tmp_path)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1

    def test_missing_run_directory_refuses(self, tmp_path: Path) -> None:
        (tmp_path / "output").mkdir()
        AssetStore(tmp_path / "output" / "recon.db")
        settings = _settings(tmp_path)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1


class TestNoMatchingFindings:
    def test_returns_zero_with_a_clear_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), host="nope.x.test"
        )
        assert rc == 0
        assert "Nothing to assess" in capsys.readouterr().out


def _hosts_with_n_findings(n: int) -> list[Host]:
    return [
        Host(
            domain=f"h{i}.x.test",
            hostname=f"h{i}.x.test",
            risk_level=RiskLevel.HIGH,
            risk_score=70,
            findings=[
                Finding(
                    host=f"h{i}.x.test", template_id="t", severity="high", name="n", source="nuclei"
                )
            ],
        )
        for i in range(n)
    ]


class TestBatchCeiling:
    def test_refuses_when_findings_exceed_the_configured_limit(self, tmp_path: Path) -> None:
        _seed_run(tmp_path, hosts=_hosts_with_n_findings(3))
        settings = _settings(tmp_path, reportability_max_findings_per_batch=2)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1

    def test_explicit_limit_override_still_refuses_if_exceeded(self, tmp_path: Path) -> None:
        _seed_run(tmp_path, hosts=_hosts_with_n_findings(3))
        settings = _settings(tmp_path, reportability_max_findings_per_batch=50)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), limit=2)
        assert rc == 1

    def test_never_silently_truncates(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The refusal message must state the real count, not proceed with
        a truncated subset."""
        _seed_run(tmp_path, hosts=_hosts_with_n_findings(3))
        settings = _settings(tmp_path, reportability_max_findings_per_batch=2)
        cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert "3 findings" in capsys.readouterr().err


class TestNonInteractiveConfirmationGate:
    def test_refuses_without_yes_when_stdin_is_not_a_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1

    def test_yes_flag_skips_confirmation_and_proceeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0

    def test_declining_the_interactive_prompt_aborts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt="": "n")
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1


class TestSuccessfulAssessment:
    def test_grounded_citation_is_persisted_and_not_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        real_citation = (
            "Vulnerabilities discovered on any other domains, applications, or "
            "third-party services not owned or operated by Stripchat are "
            "considered out of scope and not eligible for rewards."
        )
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[
                    _finding_assessment(
                        finding_id=finding_id,
                        eligibility="NOT_ELIGIBLE",
                        rule_citation=real_citation,
                        reasoning="Host is not a Stripchat-owned asset.",
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0

        rows = store.get_reportability_assessments(RUN_ID)
        assert len(rows) == 1
        assert rows[0]["eligibility"] == "NOT_ELIGIBLE"
        assert rows[0]["final_eligibility"] == "NOT_ELIGIBLE"
        assert rows[0]["citation_grounded"] == 1
        assert rows[0]["grounding_method"] == "exact"
        assert rows[0]["model_used"] == "claude-sonnet-5"
        assert rows[0]["provider"] == "anthropic"
        assert rows[0]["prompt_version"]
        assert rows[0]["rules_hash"]

    def test_fabricated_citation_is_persisted_as_ungrounded_and_warned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The single most important behavior in this whole system: a
        citation with no real counterpart in the rules file must be
        caught, marked ungrounded, and surfaced with a visible warning —
        never silently accepted at full confidence."""
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        fabricated_citation = (
            "Critical remote code execution vulnerabilities are always eligible "
            "for the maximum bounty regardless of duplicate status."
        )
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[
                    _finding_assessment(
                        finding_id=finding_id,
                        eligibility="ELIGIBLE",
                        rule_citation=fabricated_citation,
                        reasoning="This finding is a critical RCE.",
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0

        rows = store.get_reportability_assessments(RUN_ID)
        assert len(rows) == 1
        assert rows[0]["citation_grounded"] == 0
        assert rows[0]["grounding_method"] == "none"

        out = capsys.readouterr().out
        assert "UNGROUNDED" in out or "did NOT verify" in out
        assert fabricated_citation in out

    def test_empty_citation_is_persisted_with_no_grounded_flag_and_no_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[
                    _finding_assessment(
                        finding_id=finding_id,
                        eligibility="UNCERTAIN",
                        rule_citation="",
                        reasoning="No specific rule addresses this shape.",
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0
        rows = store.get_reportability_assessments(RUN_ID)
        assert rows[0]["citation_grounded"] is None
        assert "Every non-empty citation verified" in capsys.readouterr().out

    def test_program_rules_snapshot_is_written_to_the_run_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
        )
        cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        snapshot = tmp_path / "output" / RUN_ID / "program_rules_snapshot.txt"
        assert snapshot.is_file()
        assert snapshot.read_text(encoding="utf-8") == RULES_TEXT

    def test_severity_filter_is_applied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        hosts = [
            Host(
                domain="high.x.test",
                hostname="high.x.test",
                risk_level=RiskLevel.HIGH,
                risk_score=70,
                findings=[
                    Finding(
                        host="high.x.test",
                        template_id="t1",
                        severity="high",
                        name="n1",
                        source="nuclei",
                    )
                ],
            ),
            Host(
                domain="low.x.test",
                hostname="low.x.test",
                risk_level=RiskLevel.LOW,
                risk_score=10,
                findings=[
                    Finding(
                        host="low.x.test",
                        template_id="t2",
                        severity="low",
                        name="n2",
                        source="nuclei",
                    )
                ],
            ),
        ]
        store = _seed_run(tmp_path, hosts=hosts)
        settings = _settings(tmp_path)
        finding_id = store.get_findings(RUN_ID, severity=["high"])[0]["id"]
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
        )
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), severity="high", yes=True
        )
        assert rc == 0
        assert "1 finding(s) selected" in capsys.readouterr().out


class TestExactBatchValidation:
    """design v2: any mismatch between the requested finding_id set and
    what the provider returned rejects the WHOLE batch — nothing is
    persisted, no snapshot is written. This supersedes the old
    "discard the bad entry and keep the rest" behavior."""

    def test_hallucinated_finding_id_rejects_the_whole_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[_finding_assessment(finding_id=999999, reasoning="hallucinated")]
            ),
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 1
        assert store.get_reportability_assessments(RUN_ID) == []
        assert "unexpected" in capsys.readouterr().err
        assert not (tmp_path / "output" / RUN_ID / "program_rules_snapshot.txt").exists()

    def test_missing_finding_id_rejects_the_whole_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_provider(monkeypatch, primary=_FakeProvider(assessments=[]))
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 1
        assert store.get_reportability_assessments(RUN_ID) == []
        assert "missing" in capsys.readouterr().err

    def test_duplicate_finding_id_rejects_the_whole_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[
                    _finding_assessment(finding_id=finding_id),
                    _finding_assessment(finding_id=finding_id),
                ]
            ),
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 1
        assert store.get_reportability_assessments(RUN_ID) == []
        assert "duplicated" in capsys.readouterr().err


class TestAdversarialCrossValidation:
    def test_agree_preserves_the_primary_eligibility_as_final(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[_finding_assessment(finding_id=finding_id, eligibility="ELIGIBLE")]
            ),
            adversarial=_FakeProvider(
                reviews=[
                    AdversarialFindingChallenge(
                        finding_id=finding_id, challenge="AGREE", reasoning="Checks out."
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 0
        row = store.get_reportability_assessments(RUN_ID)[0]
        assert row["eligibility"] == "ELIGIBLE"
        assert row["final_eligibility"] == "ELIGIBLE"
        reviews = store.get_reportability_adversarial_reviews(RUN_ID)
        assert len(reviews) == 1
        assert reviews[0]["challenge"] == "AGREE"
        assert reviews[0]["assessment_id"] == store.get_reportability_assessments(RUN_ID)[0]["id"]

    def test_disagree_forces_final_eligibility_to_uncertain_never_the_counter_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[_finding_assessment(finding_id=finding_id, eligibility="ELIGIBLE")]
            ),
            adversarial=_FakeProvider(
                reviews=[
                    AdversarialFindingChallenge(
                        finding_id=finding_id,
                        challenge="DISAGREE",
                        counter_eligibility="NOT_ELIGIBLE",
                        reasoning="The citation doesn't actually cover this.",
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 0
        row = store.get_reportability_assessments(RUN_ID)[0]
        assert row["eligibility"] == "ELIGIBLE"
        # Fail-closed to UNCERTAIN — NEVER the adversary's own counter_eligibility
        # (which was NOT_ELIGIBLE here), and never the primary's ELIGIBLE either.
        assert row["final_eligibility"] == "UNCERTAIN"
        assert "did NOT confirm" in capsys.readouterr().out

    def test_insufficient_information_also_forces_uncertain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(
                assessments=[_finding_assessment(finding_id=finding_id, eligibility="NOT_ELIGIBLE")]
            ),
            adversarial=_FakeProvider(
                reviews=[
                    AdversarialFindingChallenge(
                        finding_id=finding_id,
                        challenge="INSUFFICIENT_INFORMATION",
                        reasoning="Can't confirm either way from what I was given.",
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 0
        row = store.get_reportability_assessments(RUN_ID)[0]
        assert row["final_eligibility"] == "UNCERTAIN"

    def test_adversarial_batch_mismatch_rejects_the_whole_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
            adversarial=_FakeProvider(reviews=[]),  # missing the one required review
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 1
        # Primary batch was structurally valid but the run still fails
        # closed as a whole — nothing from a partially-reviewed batch is
        # persisted.
        assert store.get_reportability_assessments(RUN_ID) == []

    def test_adversarial_api_error_is_reported_cleanly_and_nothing_is_persisted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
            adversarial=_FakeProvider(review_error=ReportabilityAPIError("simulated failure")),
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 1
        assert store.get_reportability_assessments(RUN_ID) == []


class TestApiErrorHandling:
    def test_api_error_during_assessment_is_reported_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)

        class _FailingProvider(_FakeProvider):
            def assess_batch(self, rules_text: str, findings: list) -> None:
                raise ReportabilityAPIError("simulated failure")

        _patch_provider(monkeypatch, primary=_FailingProvider())
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 1


class TestSingleProviderVsCrossValidatedLabeling:
    """Bug fix: the final summary line and reminder must never claim
    adversarial cross-validation happened unless a second provider was
    both configured AND its review actually completed successfully for
    this run. Confirmed with real evidence before this fix: running
    `assess-reportability --provider anthropic` alone (no
    `--adversarial-provider`, no `REPORTABILITY_ADVERSARIAL_PROVIDER`)
    still printed "(final, post-adversarial-review verdict)" and
    "agreement between two LLMs" — a false impression of more
    verification than actually ran.
    """

    def test_single_provider_run_labels_the_verdict_as_single_provider(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
        )
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True, provider="anthropic"
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "(single-provider verdict — no adversarial cross-validation)" in out
        assert "post-adversarial-review" not in out
        assert "agreement between two LLMs" not in out
        assert "Reminder: this is a single LLM's assessment, not cross-validated" in out

    def test_cross_validated_run_keeps_the_original_post_adversarial_wording(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
            adversarial=_FakeProvider(
                reviews=[
                    AdversarialFindingChallenge(
                        finding_id=finding_id, challenge="AGREE", reasoning="Checks out."
                    )
                ]
            ),
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "(final, post-adversarial-review verdict)" in out
        assert "Reminder: agreement between two LLMs does not constitute proof" in out
        assert "single-provider verdict" not in out

    def test_adversarial_call_failing_partway_never_produces_a_cross_validated_label(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The real production scenario this bug was found alongside: an
        adversarial provider IS configured but its call fails partway
        (e.g. an OpenAI rate limit). The whole run already fails closed
        (rc=1, nothing persisted) before reaching the summary — this test
        pins down that no misleading cross-validated wording escapes
        either, since a future refactor could otherwise reorder things.
        """
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_provider(
            monkeypatch,
            primary=_FakeProvider(assessments=[_finding_assessment(finding_id=finding_id)]),
            adversarial=_FakeProvider(
                review_error=ReportabilityAPIError("Rate limited by the OpenAI API")
            ),
        )
        rc = cmd_assess_reportability(
            settings,
            RUN_ID,
            _rules_file(tmp_path, RULES_TEXT),
            yes=True,
            adversarial_provider="openai",
        )
        assert rc == 1
        assert store.get_reportability_assessments(RUN_ID) == []
        out = capsys.readouterr().out
        assert "post-adversarial-review" not in out
        assert "agreement between two LLMs" not in out
        assert "final, post-adversarial-review verdict" not in out

    def test_real_world_regression_fixture_22_findings_single_provider(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Explicit fixture for the exact case this bug report was filed
        from: 22 findings, `--provider anthropic` only, no adversarial
        provider configured anywhere (not via flag, not via
        REPORTABILITY_ADVERSARIAL_PROVIDER) — 20 NOT_ELIGIBLE, 2 UNCERTAIN,
        0 ELIGIBLE, exactly as observed in production."""
        hosts = _hosts_with_n_findings(22)
        store = _seed_run(tmp_path, hosts=hosts)
        settings = _settings(tmp_path, reportability_adversarial_provider=None)
        findings = store.get_findings(RUN_ID)
        assert len(findings) == 22

        def _assessments() -> list[FindingAssessment]:
            items = []
            for i, finding in enumerate(findings):
                if i < 2:
                    eligibility = "UNCERTAIN"
                else:
                    eligibility = "NOT_ELIGIBLE"
                items.append(
                    _finding_assessment(
                        finding_id=finding["id"],
                        eligibility=eligibility,
                        rule_citation="",
                        reasoning="Not covered by an in-scope rule.",
                    )
                )
            return items

        _patch_provider(monkeypatch, primary=_FakeProvider(assessments=_assessments))
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True, provider="anthropic"
        )
        assert rc == 0

        out = capsys.readouterr().out
        assert (
            "Assessed 22 finding(s): 0 ELIGIBLE, 20 NOT_ELIGIBLE, 2 UNCERTAIN "
            "(single-provider verdict — no adversarial cross-validation)." in out
        )
        assert "post-adversarial-review" not in out
        assert "agreement between two LLMs" not in out
