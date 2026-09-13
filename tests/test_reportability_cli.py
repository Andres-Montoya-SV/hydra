"""core/reportability/cli.py::cmd_assess_reportability — the standalone
`python app.py assess-reportability` command (design Part D). The real
Anthropic API call is mocked in every test here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("anthropic")
pytest.importorskip("pydantic")

from config.settings import Settings  # noqa: E402
from core.assets import Finding, Host, RiskLevel, ScanRun  # noqa: E402
from core.reportability.cli import cmd_assess_reportability  # noqa: E402
from core.reportability.client import ReportabilityAPIError  # noqa: E402
from core.reportability.schema import FindingAssessment, ReportabilityBatchResult  # noqa: E402
from core.store import AssetStore  # noqa: E402

RUN_ID = "run1"


def _settings(project_root: Path, **overrides: object) -> Settings:
    kwargs: dict[str, object] = {
        "project_root": project_root,
        "anthropic_api_key": "sk-fake",
        "anthropic_model": "claude-sonnet-5",
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


class TestMissingApiKey:
    def test_refuses_cleanly_without_crashing(self, tmp_path: Path) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path, anthropic_api_key=None)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
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


class TestBatchCeiling:
    def test_refuses_when_findings_exceed_the_configured_limit(self, tmp_path: Path) -> None:
        hosts = [
            Host(
                domain=f"h{i}.x.test",
                hostname=f"h{i}.x.test",
                risk_level=RiskLevel.HIGH,
                risk_score=70,
                findings=[
                    Finding(
                        host=f"h{i}.x.test",
                        template_id="t",
                        severity="high",
                        name="n",
                        source="nuclei",
                    )
                ],
            )
            for i in range(3)
        ]
        _seed_run(tmp_path, hosts=hosts)
        settings = _settings(tmp_path, reportability_max_findings_per_batch=2)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT))
        assert rc == 1

    def test_explicit_limit_override_still_refuses_if_exceeded(self, tmp_path: Path) -> None:
        hosts = [
            Host(
                domain=f"h{i}.x.test",
                hostname=f"h{i}.x.test",
                risk_level=RiskLevel.HIGH,
                risk_score=70,
                findings=[
                    Finding(
                        host=f"h{i}.x.test",
                        template_id="t",
                        severity="high",
                        name="n",
                        source="nuclei",
                    )
                ],
            )
            for i in range(3)
        ]
        _seed_run(tmp_path, hosts=hosts)
        settings = _settings(tmp_path, reportability_max_findings_per_batch=50)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), limit=2)
        assert rc == 1

    def test_never_silently_truncates(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The refusal message must state the real count, not proceed with
        a truncated subset."""
        hosts = [
            Host(
                domain=f"h{i}.x.test",
                hostname=f"h{i}.x.test",
                risk_level=RiskLevel.HIGH,
                risk_score=70,
                findings=[
                    Finding(
                        host=f"h{i}.x.test",
                        template_id="t",
                        severity="high",
                        name="n",
                        source="nuclei",
                    )
                ],
            )
            for i in range(3)
        ]
        _seed_run(tmp_path, hosts=hosts)
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
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        _patch_client(monkeypatch, assessments=[])
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


def _patch_client(monkeypatch: pytest.MonkeyPatch, *, assessments: list[FindingAssessment]) -> None:
    class _FakeClient:
        def __init__(self, api_key: str, model: str) -> None:
            pass

        def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int:
            return 500

        def assess_batch(
            self, rules_text: str, findings: list[dict[str, object]]
        ) -> ReportabilityBatchResult:
            return ReportabilityBatchResult(assessments=assessments)

    monkeypatch.setattr("core.reportability.cli.ReportabilityClient", _FakeClient)


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
        _patch_client(
            monkeypatch,
            assessments=[
                FindingAssessment(
                    finding_id=finding_id,
                    eligibility="NOT_ELIGIBLE",
                    rule_citation=real_citation,
                    reasoning="Host is not a Stripchat-owned asset.",
                )
            ],
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0

        rows = store.get_reportability_assessments(RUN_ID)
        assert len(rows) == 1
        assert rows[0]["eligibility"] == "NOT_ELIGIBLE"
        assert rows[0]["citation_grounded"] == 1
        assert rows[0]["model_used"] == "claude-sonnet-5"

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
        _patch_client(
            monkeypatch,
            assessments=[
                FindingAssessment(
                    finding_id=finding_id,
                    eligibility="ELIGIBLE",
                    rule_citation=fabricated_citation,
                    reasoning="This finding is a critical RCE.",
                )
            ],
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0

        rows = store.get_reportability_assessments(RUN_ID)
        assert len(rows) == 1
        assert rows[0]["citation_grounded"] == 0

        out = capsys.readouterr().out
        assert "UNGROUNDED" in out or "did NOT verify" in out
        assert fabricated_citation in out

    def test_empty_citation_is_persisted_with_no_grounded_flag_and_no_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_client(
            monkeypatch,
            assessments=[
                FindingAssessment(
                    finding_id=finding_id,
                    eligibility="UNCERTAIN",
                    rule_citation="",
                    reasoning="No specific rule addresses this shape.",
                )
            ],
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0
        rows = store.get_reportability_assessments(RUN_ID)
        assert rows[0]["citation_grounded"] is None
        assert "Every non-empty citation verified" in capsys.readouterr().out

    def test_assessment_for_unrequested_finding_id_is_discarded_with_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_client(
            monkeypatch,
            assessments=[
                FindingAssessment(
                    finding_id=999999,
                    eligibility="ELIGIBLE",
                    rule_citation="",
                    reasoning="hallucinated finding_id",
                )
            ],
        )
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 0
        assert store.get_reportability_assessments(RUN_ID) == []
        assert "not in the requested batch" in capsys.readouterr().err

    def test_program_rules_snapshot_is_written_to_the_run_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_client(monkeypatch, assessments=[])
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
        _seed_run(tmp_path, hosts=hosts)
        settings = _settings(tmp_path)
        _patch_client(monkeypatch, assessments=[])
        rc = cmd_assess_reportability(
            settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), severity="high", yes=True
        )
        assert rc == 0
        assert "1 finding(s) selected" in capsys.readouterr().out


class TestApiErrorHandling:
    def test_api_error_during_assessment_is_reported_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)

        class _FailingClient:
            def __init__(self, api_key: str, model: str) -> None:
                pass

            def count_input_tokens(self, rules_text: str, findings: list) -> int:
                return 100

            def assess_batch(self, rules_text: str, findings: list) -> None:
                raise ReportabilityAPIError("simulated failure")

        monkeypatch.setattr("core.reportability.cli.ReportabilityClient", _FailingClient)
        rc = cmd_assess_reportability(settings, RUN_ID, _rules_file(tmp_path, RULES_TEXT), yes=True)
        assert rc == 1
