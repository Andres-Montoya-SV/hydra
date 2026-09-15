"""core/hypotheses/cli.py::cmd_suggest_hypotheses — the standalone
`python app.py suggest-hypotheses` command (docs/HYPOTHESIS_ENGINE_DESIGN.md
Part D). The real Anthropic/OpenAI API calls are always mocked here —
`core.hypotheses.cli.create_provider` is monkeypatched, so these tests
don't even need the `anthropic`/`openai` packages installed... except
`core.hypotheses.schema` (pydantic models, used to build fake provider
responses) does — hence the importorskip guards below.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from config.settings import Settings  # noqa: E402
from core.assets import ScanRun  # noqa: E402
from core.hypotheses.cli import cmd_suggest_hypotheses  # noqa: E402
from core.hypotheses.errors import HypothesisAPIError  # noqa: E402
from core.hypotheses.schema import (  # noqa: E402
    CitedRelationshipClaim,
    HypothesisBatchResult,
    HypothesisProposal,
    ReasoningSoundnessBatchResult,
    ReasoningSoundnessReview,
)
from core.intel.engine import IntelEngine, IntelRunConfig  # noqa: E402
from core.intel.model import ConfidenceBand  # noqa: E402
from core.store import AssetStore  # noqa: E402

RUN_ID = "run1"
SEED = "example.test"


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


def _seed_run_with_relationships(project_root: Path) -> tuple[AssetStore, dict[str, object]]:
    (project_root / "output").mkdir(parents=True, exist_ok=True)
    db_path = project_root / "output" / "recon.db"
    (project_root / "output" / RUN_ID).mkdir(parents=True, exist_ok=True)
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=[SEED]))

    config = IntelRunConfig(
        run_id=RUN_ID,
        seed_domains=[SEED],
        scope_patterns=[SEED],
        collected_domains={SEED},
        observed_at="2026-08-21T00:00:00Z",
    )
    engine = IntelEngine(config)
    engine.ingest_passive_resolutions({SEED: "203.0.113.10", "sibling.test": "203.0.113.10"})
    engine.correlate()
    store.persist_registry(RUN_ID, {}, intel=engine.snapshot())

    conn = store.intel_connection()
    rel = dict(
        conn.execute(
            "SELECT * FROM intel_relationships WHERE run_id=? LIMIT 1", (RUN_ID,)
        ).fetchone()
    )
    conn.close()
    return store, rel


def _empty_run(project_root: Path) -> AssetStore:
    (project_root / "output").mkdir(parents=True, exist_ok=True)
    db_path = project_root / "output" / "recon.db"
    (project_root / "output" / RUN_ID).mkdir(parents=True, exist_ok=True)
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=[SEED]))
    return store


class _FakeProvider:
    name = "anthropic"
    model = "claude-sonnet-5"

    def __init__(self, batch: HypothesisBatchResult) -> None:
        self._batch = batch

    def count_input_tokens(self, user_message: str) -> int:
        return 500

    def propose_hypotheses(self, user_message: str) -> HypothesisBatchResult:
        return self._batch

    def review_hypotheses(self, user_message: str) -> ReasoningSoundnessBatchResult:
        raise AssertionError(
            "review_hypotheses should not be called without --adversarial-provider"
        )


class TestValidation:
    def test_unsupported_provider_is_rejected(self, tmp_path: Path) -> None:
        _empty_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, provider="cohere", yes=True)
        assert rc == 1

    def test_same_provider_and_adversarial_provider_is_rejected(self, tmp_path: Path) -> None:
        _empty_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(
            settings, RUN_ID, provider="anthropic", adversarial_provider="anthropic", yes=True
        )
        assert rc == 1

    def test_missing_api_key_is_rejected(self, tmp_path: Path) -> None:
        _empty_run(tmp_path)
        settings = _settings(tmp_path, anthropic_api_key=None)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 1

    def test_missing_run_directory_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "output").mkdir(parents=True, exist_ok=True)
        db_path = tmp_path / "output" / "recon.db"
        AssetStore(db_path)  # creates the db but not the run dir
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, "no-such-run", yes=True)
        assert rc == 1

    def test_missing_database_is_rejected(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 1


class TestBatchLimitRefusal:
    def test_more_relationships_than_the_limit_refuses_without_truncating(
        self, tmp_path: Path
    ) -> None:
        _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, limit=0, yes=True)
        assert rc == 1

    def test_limit_can_be_raised_explicitly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider",
            lambda *a, **kw: _FakeProvider(HypothesisBatchResult(hypotheses=[])),
        )
        rc = cmd_suggest_hypotheses(settings, RUN_ID, limit=1000, yes=True)
        assert rc == 0


class TestFailClosedConfirmation:
    def test_non_interactive_stdin_without_yes_refuses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider",
            lambda *a, **kw: _FakeProvider(HypothesisBatchResult(hypotheses=[])),
        )
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=False)
        assert rc == 1

    def test_yes_bypasses_confirmation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider",
            lambda *a, **kw: _FakeProvider(HypothesisBatchResult(hypotheses=[])),
        )
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0


class TestEmptyEvidence:
    def test_no_relationships_entities_or_findings_is_a_clean_no_op(self, tmp_path: Path) -> None:
        _empty_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0

    def test_empty_hypothesis_list_from_the_model_is_a_valid_honest_outcome(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, _ = _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider",
            lambda *a, **kw: _FakeProvider(HypothesisBatchResult(hypotheses=[])),
        )
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0
        assert store.get_llm_hypotheses(RUN_ID) == []
        out = capsys.readouterr().out
        assert "no hypotheses" in out.lower()


class TestSuccessfulGeneration:
    def test_grounded_hypothesis_is_persisted_and_marked_trustworthy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, rel = _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        batch = HypothesisBatchResult(
            hypotheses=[
                HypothesisProposal(
                    statement="Likely commonly-provisioned infrastructure.",
                    cited_relationships=[
                        CitedRelationshipClaim(
                            relationship_id=rel["relationship_id"],
                            claimed_relationship_type=rel["relationship_type"],
                            treated_as_strength=ConfidenceBand(rel["confidence"]),
                        )
                    ],
                    cited_entity_ids=[],
                    confidence="HIGH",
                    suggested_next_step="",
                )
            ]
        )
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider", lambda *a, **kw: _FakeProvider(batch)
        )
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0

        rows = store.get_llm_hypotheses(RUN_ID)
        assert len(rows) == 1
        assert rows[0]["grounding_status"] == "GROUNDED"
        assert rows[0]["calibration_status"] == "CALIBRATED"
        out = capsys.readouterr().out
        assert "✓" in out
        assert "1 hypothesis(es) generated" in out

    def test_ungrounded_hypothesis_is_persisted_and_flagged_in_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, _ = _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        batch = HypothesisBatchResult(
            hypotheses=[
                HypothesisProposal(
                    statement="Cites a relationship that does not exist.",
                    cited_relationships=[
                        CitedRelationshipClaim(
                            relationship_id="does-not-exist",
                            claimed_relationship_type="SHARES_CERTIFICATE",
                            treated_as_strength=ConfidenceBand.HIGH,
                        )
                    ],
                    cited_entity_ids=[],
                    confidence="HIGH",
                    suggested_next_step="",
                )
            ]
        )
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider", lambda *a, **kw: _FakeProvider(batch)
        )
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0

        rows = store.get_llm_hypotheses(RUN_ID)
        assert rows[0]["grounding_status"] == "UNGROUNDED"
        out = capsys.readouterr().out
        assert "⚠" in out
        assert "did NOT pass every check" in out

    def test_api_error_during_generation_is_reported_and_nothing_is_persisted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store, _ = _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)

        class _FailingProvider(_FakeProvider):
            def propose_hypotheses(self, user_message: str) -> HypothesisBatchResult:
                raise HypothesisAPIError("simulated failure")

        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider",
            lambda *a, **kw: _FailingProvider(HypothesisBatchResult(hypotheses=[])),
        )
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 1
        assert store.get_llm_hypotheses(RUN_ID) == []


class TestAdversarialReasoningReview:
    def test_reasoning_review_challenge_is_persisted_alongside_the_hypothesis(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store, rel = _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        batch = HypothesisBatchResult(
            hypotheses=[
                HypothesisProposal(
                    statement="Likely commonly-provisioned infrastructure.",
                    cited_relationships=[
                        CitedRelationshipClaim(
                            relationship_id=rel["relationship_id"],
                            claimed_relationship_type=rel["relationship_type"],
                            treated_as_strength=ConfidenceBand(rel["confidence"]),
                        )
                    ],
                    cited_entity_ids=[],
                    confidence="HIGH",
                    suggested_next_step="",
                )
            ]
        )

        class _AdversarialProvider(_FakeProvider):
            name = "openai"
            model = "gpt-5.6-terra"

            def review_hypotheses(self, user_message: str) -> ReasoningSoundnessBatchResult:
                return ReasoningSoundnessBatchResult(
                    reviews=[
                        ReasoningSoundnessReview(
                            hypothesis_index=0, challenge="SOUND", reasoning="Checks out."
                        )
                    ]
                )

        primary = _FakeProvider(batch)
        adversarial = _AdversarialProvider(HypothesisBatchResult(hypotheses=[]))

        def _fake_create_provider(provider_name: str, *, api_key: str, model: str):
            return primary if provider_name == "anthropic" else adversarial

        monkeypatch.setattr("core.hypotheses.cli.create_provider", _fake_create_provider)
        rc = cmd_suggest_hypotheses(
            settings, RUN_ID, provider="anthropic", adversarial_provider="openai", yes=True
        )
        assert rc == 0

        rows = store.get_llm_hypotheses(RUN_ID)
        assert rows[0]["reasoning_review_challenge"] == "SOUND"
        assert rows[0]["reasoning_review_provider"] == "openai"

    def test_overreaches_review_makes_the_hypothesis_untrustworthy_even_when_calibrated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, rel = _seed_run_with_relationships(tmp_path)
        settings = _settings(tmp_path)
        batch = HypothesisBatchResult(
            hypotheses=[
                HypothesisProposal(
                    statement="Likely commonly-provisioned infrastructure.",
                    cited_relationships=[
                        CitedRelationshipClaim(
                            relationship_id=rel["relationship_id"],
                            claimed_relationship_type=rel["relationship_type"],
                            treated_as_strength=ConfidenceBand(rel["confidence"]),
                        )
                    ],
                    cited_entity_ids=[],
                    confidence="HIGH",
                    suggested_next_step="",
                )
            ]
        )

        class _AdversarialProvider(_FakeProvider):
            name = "openai"
            model = "gpt-5.6-terra"

            def review_hypotheses(self, user_message: str) -> ReasoningSoundnessBatchResult:
                return ReasoningSoundnessBatchResult(
                    reviews=[
                        ReasoningSoundnessReview(
                            hypothesis_index=0,
                            challenge="OVERREACHES",
                            reasoning="Draws a stronger conclusion than the evidence supports.",
                        )
                    ]
                )

        primary = _FakeProvider(batch)
        adversarial = _AdversarialProvider(HypothesisBatchResult(hypotheses=[]))

        def _fake_create_provider(provider_name: str, *, api_key: str, model: str):
            return primary if provider_name == "anthropic" else adversarial

        monkeypatch.setattr("core.hypotheses.cli.create_provider", _fake_create_provider)
        rc = cmd_suggest_hypotheses(
            settings, RUN_ID, provider="anthropic", adversarial_provider="openai", yes=True
        )
        assert rc == 0
        rows = store.get_llm_hypotheses(RUN_ID)
        assert rows[0]["grounding_status"] == "GROUNDED"
        assert rows[0]["calibration_status"] == "CALIBRATED"
        assert rows[0]["reasoning_review_challenge"] == "OVERREACHES"
        out = capsys.readouterr().out
        assert "⚠" in out
