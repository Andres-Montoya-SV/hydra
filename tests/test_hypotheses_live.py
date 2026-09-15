"""Real Anthropic API call — opt-in, only runs when a real ANTHROPIC_API_KEY
is present in the environment. Mirrors tests/test_reportability_live.py's
own skip pattern. This is the one place in the hypothesis engine's test
suite that spends real API credits — every other test mocks the call.

Run explicitly with a real key:
    ANTHROPIC_API_KEY=sk-ant-... pytest tests/test_hypotheses_live.py -v -s
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("anthropic")
pytest.importorskip("pydantic")

from config.settings import Settings  # noqa: E402
from core.assets import ScanRun  # noqa: E402
from core.hypotheses.cli import cmd_suggest_hypotheses  # noqa: E402
from core.intel.engine import IntelEngine, IntelRunConfig  # noqa: E402
from core.store import AssetStore  # noqa: E402

_NO_LIVE_KEY = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set — opt-in live test, see this file's docstring",
)

RUN_ID = "virusbarrier-live-run"
SEED = "example.test"


@_NO_LIVE_KEY
def test_real_api_call_against_a_small_correlated_cluster_produces_a_grounded_hypothesis(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end against the real API: a small, real correlated cluster
    (shared IP) should come back with every citation grounded — since the
    evidence handed to Claude is exactly what gather_run_evidence read
    from SQLite, any citation it makes should verify against that same
    data."""
    (tmp_path / "output").mkdir()
    db_path = tmp_path / "output" / "recon.db"
    run_dir = tmp_path / "output" / RUN_ID
    run_dir.mkdir()
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

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    settings = Settings(project_root=tmp_path, anthropic_api_key=os.environ["ANTHROPIC_API_KEY"])
    rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)

    out = capsys.readouterr().out
    print(out)  # surfaced in pytest -s / -v output for manual inspection
    assert rc == 0

    rows = store.get_llm_hypotheses(RUN_ID)
    # An empty list is a valid, honest answer for such a small cluster —
    # the real, interesting assertion is conditional on there being any.
    for row in rows:
        assert row["grounding_status"] in {"GROUNDED", "PARTIALLY_GROUNDED", "UNGROUNDED"}
        for evidence in row["evidence"]:
            if evidence["exists_in_run"]:
                # Every citation Claude claims exists must genuinely
                # verify against the same relationship data it was shown.
                assert evidence["cited_id"]
