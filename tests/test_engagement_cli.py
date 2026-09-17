"""`python app.py engagement` — app.cmd_engagement, the guided orchestrator
that chains run -> investigate/verification-flags -> assess-reportability
-> client-report. The reconnaissance pipeline itself
(`app._run_headless_pipeline`) is monkeypatched to a canned successful
result in every test here — pipeline execution is already covered by
tests/test_cli_acceptance.py, and `cmd_run` itself calls this exact same
shared helper (see app.py), so it isn't re-tested per command. What these
tests actually exercise is the orchestration this command adds: step
ordering, the confirmation gates before assess-reportability/client-report,
and that a decline or missing config skips cleanly instead of erroring.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("anthropic")
pytest.importorskip("pydantic")
pytest.importorskip("rich")

import app as hydra_app  # noqa: E402
from config.settings import Settings  # noqa: E402
from core.assets import Finding, Host, RiskLevel, ScanRun  # noqa: E402
from core.models import DomainTarget, PipelineContext  # noqa: E402
from core.reportability.schema import FindingAssessment, ReportabilityBatchResult  # noqa: E402
from core.store import AssetStore  # noqa: E402

RUN_ID = "run1"
DOMAIN = "admin.x.test"


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


def _seed_run(project_root: Path) -> tuple[AssetStore, Path]:
    output_dir = project_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "recon.db"
    run_dir = output_dir / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=[DOMAIN]))
    host = Host(
        domain=DOMAIN,
        hostname=DOMAIN,
        risk_level=RiskLevel.HIGH,
        risk_score=70,
        findings=[
            Finding(
                host=DOMAIN,
                template_id="exposed-admin-panel",
                severity="high",
                name="Exposed admin panel",
                source="nuclei",
                description="Login reachable without VPN",
                url=f"https://{DOMAIN}/login",
            )
        ],
    )
    store.persist_registry(RUN_ID, {DOMAIN: host})
    return store, run_dir


def _rules_file(tmp_path: Path) -> Path:
    path = tmp_path / "rules.txt"
    path.write_text("Any confirmed vulnerability is eligible for a reward.\n", encoding="utf-8")
    return path


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, finding_id: int) -> None:
        self._finding_id = finding_id

    def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int:
        return 500

    def assess_batch(self, rules_text: str, findings: list[dict[str, object]]):
        return ReportabilityBatchResult(
            assessments=[
                FindingAssessment(
                    finding_id=self._finding_id,
                    eligibility="ELIGIBLE",
                    confidence="HIGH",
                    rule_citation="Any confirmed vulnerability is eligible for a reward.",
                    reasoning="Matches an in-scope, confirmed finding.",
                )
            ]
        )


def _patch_provider(monkeypatch: pytest.MonkeyPatch, finding_id: int) -> None:
    def _fake_create_provider(provider: str, *, api_key: str, model: str):
        return _FakeProvider(finding_id)

    monkeypatch.setattr("core.reportability.cli.create_provider", _fake_create_provider)


def _patch_headless_pipeline(monkeypatch: pytest.MonkeyPatch, project_root: Path) -> None:
    """Stand in for the real pipeline (already covered by
    test_cli_acceptance.py) with a canned, already-finished run pointing at
    the fixtures `_seed_run` persisted."""

    async def _fake_run_headless_pipeline(settings, *, domain, targets_file, run_id):
        context = PipelineContext(
            targets=[DomainTarget(domain=DOMAIN)],
            run_id=RUN_ID,
            output_dir=project_root / "output" / RUN_ID,
        )
        return 0, context

    monkeypatch.setattr(hydra_app, "_run_headless_pipeline", _fake_run_headless_pipeline)


def _args(tmp_path: Path, **overrides: object):
    parser = hydra_app.build_parser()
    argv = ["engagement", "-d", DOMAIN]
    ns = parser.parse_args(argv)
    ns.program_rules = overrides.pop("program_rules", None)
    ns.provider = overrides.pop("provider", None)
    ns.adversarial_provider = overrides.pop("adversarial_provider", None)
    ns.client_report_format = overrides.pop("client_report_format", "markdown")
    ns.skip_reportability = overrides.pop("skip_reportability", False)
    ns.skip_client_report = overrides.pop("skip_client_report", False)
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


class TestFullFlowAccepted:
    def test_each_step_runs_in_order_against_the_same_run_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, run_dir = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_headless_pipeline(monkeypatch, tmp_path)
        _patch_provider(monkeypatch, finding_id)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        answers = iter(["y", "y"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

        args = _args(tmp_path, program_rules=_rules_file(tmp_path))
        rc = hydra_app.asyncio.run(hydra_app.cmd_engagement(args, settings))

        assert rc == 0
        out = capsys.readouterr().out
        recon_pos = out.index("Reconnaissance run")
        reportability_pos = out.index("Reportability assessment:")
        client_report_pos = out.index("Client report draft")
        assert recon_pos < reportability_pos < client_report_pos

        assessments = store.get_reportability_assessments(RUN_ID)
        assert len(assessments) == 1
        assert (run_dir / "client_report.md").exists()


class TestDeclineReportability:
    def test_stops_cleanly_without_offering_client_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, run_dir = _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_headless_pipeline(monkeypatch, tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt="": "n")

        args = _args(tmp_path, program_rules=_rules_file(tmp_path))
        rc = hydra_app.asyncio.run(hydra_app.cmd_engagement(args, settings))

        assert rc == 0
        out = capsys.readouterr().out
        assert "ENGAGEMENT SUMMARY" in out
        assert "Reconnaissance run" in out
        assert "Reportability assessment:" not in out
        assert "CLIENT REPORT DRAFT" not in out
        assert not (run_dir / "client_report.md").exists()
        assert store.get_reportability_assessments(RUN_ID) == []


class TestDeclineClientReport:
    def test_stops_cleanly_after_accepting_reportability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, run_dir = _seed_run(tmp_path)
        finding_id = store.get_findings(RUN_ID)[0]["id"]
        settings = _settings(tmp_path)
        _patch_headless_pipeline(monkeypatch, tmp_path)
        _patch_provider(monkeypatch, finding_id)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        answers = iter(["y", "n"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

        args = _args(tmp_path, program_rules=_rules_file(tmp_path))
        rc = hydra_app.asyncio.run(hydra_app.cmd_engagement(args, settings))

        assert rc == 0
        out = capsys.readouterr().out
        assert "Reportability assessment:" in out
        assert "Declined — no client report generated." in out
        assert not (run_dir / "client_report.md").exists()
        assert len(store.get_reportability_assessments(RUN_ID)) == 1


class TestMissingApiKeySkipsAutomatically:
    def test_never_prompts_when_no_key_is_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path, anthropic_api_key=None, openai_api_key=None)
        _patch_headless_pipeline(monkeypatch, tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt="": "n")

        args = _args(tmp_path, program_rules=_rules_file(tmp_path))
        rc = hydra_app.asyncio.run(hydra_app.cmd_engagement(args, settings))

        assert rc == 0
        out = capsys.readouterr().out
        assert "Skipping reportability assessment — ANTHROPIC_API_KEY is not configured." in out
        assert "Proceed with this assessment" not in out


class TestNonInteractiveFailsClosed:
    def test_refuses_to_spend_without_a_terminal_or_skip_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_headless_pipeline(monkeypatch, tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        args = _args(tmp_path, program_rules=_rules_file(tmp_path))
        rc = hydra_app.asyncio.run(hydra_app.cmd_engagement(args, settings))

        assert rc == 1
        captured = capsys.readouterr()
        assert "Non-interactive stdin — refusing to spend API credits" in captured.err
        assert "CLIENT REPORT DRAFT" not in captured.out

    def test_skip_reportability_flag_avoids_the_fail_closed_path_entirely(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _seed_run(tmp_path)
        settings = _settings(tmp_path)
        _patch_headless_pipeline(monkeypatch, tmp_path)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        args = _args(
            tmp_path,
            program_rules=_rules_file(tmp_path),
            skip_reportability=True,
            skip_client_report=True,
        )
        rc = hydra_app.asyncio.run(hydra_app.cmd_engagement(args, settings))

        assert rc == 0
        out = capsys.readouterr().out
        assert "Skipping reportability assessment (--skip-reportability)." in out
        assert "Skipping client report draft (--skip-client-report)." in out
