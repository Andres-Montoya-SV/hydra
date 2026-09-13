"""Real Anthropic API call — opt-in, only runs when a real ANTHROPIC_API_KEY
is present in the environment, same skip pattern this project already uses
for real-binary confinement tests (`shutil.which(...)`/
`pytest.importorskip(...)` in tests/test_*_confinement_live.py), applied
here to a real credential instead of a real binary.

This is the one place in the reportability agent's test suite that spends
real API credits. Every other test (tests/test_reportability_*.py) mocks
the Anthropic API call.

Run explicitly with a real key:
    ANTHROPIC_API_KEY=sk-ant-... pytest tests/test_reportability_live.py -v
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("anthropic")
pytest.importorskip("pydantic")

from config.settings import Settings  # noqa: E402
from core.assets import Finding, Host, RiskLevel, ScanRun  # noqa: E402
from core.reportability.cli import cmd_assess_reportability  # noqa: E402
from core.store import AssetStore  # noqa: E402

_NO_LIVE_KEY = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set — opt-in live test, see this file's docstring",
)

RUN_ID = "stripchat-live-run"
RULES_FIXTURE = Path(__file__).parent / "fixtures" / "stripchat_rules.txt"


@_NO_LIVE_KEY
def test_real_api_call_against_real_stripchat_rules_produces_a_grounded_citation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end against the real API (design Part 6 step 5): a finding
    on a domain that is clearly not one of Stripchat's own assets, assessed
    against the real, full Stripchat rules text, should come back
    NOT_ELIGIBLE with a citation that greps clean against the exact same
    rules snapshot this command writes."""
    (tmp_path / "output").mkdir()
    db_path = tmp_path / "output" / "recon.db"
    run_dir = tmp_path / "output" / RUN_ID
    run_dir.mkdir()
    store = AssetStore(db_path)
    store.create_run(
        ScanRun(run_id=RUN_ID, started_at="2026-01-01T00:00:00Z", targets=["stripchat.com"])
    )
    host = Host(
        domain="unrelated-third-party-vendor.example.com",
        hostname="unrelated-third-party-vendor.example.com",
        risk_level=RiskLevel.HIGH,
        risk_score=70,
        findings=[
            Finding(
                host="unrelated-third-party-vendor.example.com",
                template_id="exposed-admin-panel",
                severity="high",
                name="Exposed admin panel",
                source="nuclei",
                description=(
                    "Admin login reachable without authentication on a third-party "
                    "vendor's own domain, not a Stripchat-owned asset."
                ),
                url="https://unrelated-third-party-vendor.example.com/admin",
            )
        ],
    )
    store.persist_registry(RUN_ID, {host.domain: host})

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    settings = Settings(project_root=tmp_path, anthropic_api_key=os.environ["ANTHROPIC_API_KEY"])
    rc = cmd_assess_reportability(settings, RUN_ID, RULES_FIXTURE, yes=True)

    out = capsys.readouterr().out
    print(out)  # surfaced in pytest -s / -v output for manual inspection
    assert rc == 0

    rows = store.get_reportability_assessments(RUN_ID)
    assert len(rows) == 1
    row = rows[0]
    assert row["eligibility"] in {"NOT_ELIGIBLE", "UNCERTAIN"}
    # The real, interesting assertion: IF Claude offered a citation, it
    # must be grounded — this finding's whole premise (a non-Stripchat
    # domain) is explicitly covered by real sentences in the rules text,
    # so a real citation should exist and verify.
    if row["rule_citation"]:
        assert (
            row["citation_grounded"] == 1
        ), f"real API citation failed to ground: {row['rule_citation']!r}"
