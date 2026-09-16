"""Foundational test case for the hypothesis engine (docs/
HYPOTHESIS_ENGINE_DESIGN.md implementation order, Step 6): the real,
mandatory virusbarrier.xyz fixture (tests/fixtures/virusbarrier/), run
through the actual correlation engine, then through the actual
mechanical grounding/calibration checks — no mocked SQLite data.

Two cases, exactly as specified:
1. The engine, given this already-correlated cluster, treats a shared
   TLS certificate as strong (HIGH) and a shared IPv4 as weak cloud
   tenancy (MEDIUM), never with the same weight — and a hypothesis that
   respects this distinction is GROUNDED + CALIBRATED.
2. The explicit adversarial case from design Section 7.2: a hypothesis
   that cites the REAL shared-IP relationship but over-interprets its
   strength as HIGH is caught as OVERSTATED, not silently accepted just
   because the citation itself is real.

The LLM call itself is mocked (as in every other hypotheses test file) —
what's under test here is the real fixture data flowing through the real
correlation engine and the real, non-LLM-judged mechanical checks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from config.settings import Settings  # noqa: E402
from core.assets import ScanRun  # noqa: E402
from core.hypotheses.cli import cmd_suggest_hypotheses  # noqa: E402
from core.hypotheses.schema import (  # noqa: E402
    CitedRelationshipClaim,
    HypothesisBatchResult,
    HypothesisProposal,
)
from core.intel.engine import IntelEngine, IntelRunConfig  # noqa: E402
from core.intel.model import ConfidenceBand  # noqa: E402
from core.store import AssetStore  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SANS = list(CASE["sans"])
FINGERPRINT = CASE["fingerprint_sha256"]
SEED = CASE["seed"]
IP = CASE["ipv4"]
RUN_ID = "virusbarrier-fixture"


def _write_artifacts(tmp_path: Path) -> Path:
    names = "\n".join(SANS)
    (tmp_path / "ctlogs.jsonl").write_text(
        json.dumps(
            {
                "id": 424242,
                "common_name": CASE["subject"],
                "name_value": names,
                "issuer_name": CASE["issuer"],
                "not_before": CASE["not_before"],
                "not_after": CASE["not_after"],
                "fingerprint_sha256": FINGERPRINT,
                "query_domain": SEED,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "httpx.json").write_text(
        json.dumps(
            {
                "input": SEED,
                "host": SEED,
                "url": f"https://{SEED}/",
                "ip": IP,
                "a": [IP],
                "status_code": 200,
                "title": "VirusBarrier",
                "tls": {
                    "subject_cn": CASE["subject"],
                    "issuer_cn": CASE["issuer"],
                    "subject_an": SANS,
                    "not_before": CASE["not_before"],
                    "not_after": CASE["not_after"],
                    "fingerprint_hash": {"sha256": FINGERPRINT},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return tmp_path


def _seed_store(project_root: Path) -> tuple[AssetStore, list[dict[str, object]]]:
    artifacts_dir = project_root / "_artifacts"
    artifacts_dir.mkdir()
    _write_artifacts(artifacts_dir)

    config = IntelRunConfig(
        run_id=RUN_ID,
        seed_domains=[SEED],
        scope_patterns=[SEED],
        collected_domains={SEED},
        observed_at="2026-08-21T00:00:00Z",
    )
    engine = IntelEngine(config)
    engine.ingest_artifacts(artifacts_dir)
    engine.ingest_passive_resolutions({name: IP for name in SANS}, collector="case_fixture")
    engine.correlate()

    (project_root / "output").mkdir(parents=True, exist_ok=True)
    db_path = project_root / "output" / "recon.db"
    (project_root / "output" / RUN_ID).mkdir(parents=True, exist_ok=True)
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-08-21T00:00:00Z", targets=[SEED]))
    store.persist_registry(RUN_ID, {}, intel=engine.snapshot())

    conn = store.intel_connection()
    relationships = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM intel_relationships WHERE run_id=?", (RUN_ID,)
        ).fetchall()
    ]
    conn.close()
    return store, relationships


def _settings(project_root: Path) -> Settings:
    return Settings(project_root=project_root, anthropic_api_key="sk-fake")


class _FakeProvider:
    name = "anthropic"
    model = "claude-sonnet-5"

    def __init__(self, batch: HypothesisBatchResult) -> None:
        self._batch = batch

    def count_input_tokens(self, user_message: str) -> int:
        return 500

    def propose_hypotheses(self, user_message: str) -> HypothesisBatchResult:
        return self._batch

    def review_hypotheses(self, user_message):  # pragma: no cover - not exercised here
        raise AssertionError("no adversarial provider configured in this test")


class TestVirusbarrierRealFixtureProducesCorrectlyWeightedRelationships:
    """Confirms the underlying data itself carries the distinction the
    hypothesis engine's calibration check depends on, on the real
    fixture — mirrors tests/test_intel_virusbarrier.py's own assertions,
    re-verified here via the exact query gather_run_evidence uses."""

    def test_shares_certificate_relationships_are_high_confidence(self, tmp_path: Path) -> None:
        _, relationships = _seed_store(tmp_path)
        cert_rels = [r for r in relationships if r["relationship_type"] == "SHARES_CERTIFICATE"]
        assert cert_rels
        assert all(r["confidence"] == "HIGH" for r in cert_rels)

    def test_shares_ipv4_relationships_are_medium_confidence_not_high(self, tmp_path: Path) -> None:
        _, relationships = _seed_store(tmp_path)
        ip_rels = [r for r in relationships if r["relationship_type"] == "SHARES_IPV4"]
        assert ip_rels
        assert all(r["confidence"] == "MEDIUM" for r in ip_rels)


class TestVirusbarrierFoundationalCase:
    """A reasonable hypothesis treating the shared certificate as strong
    evidence and the shared IP as weak, non-conclusive corroboration —
    must come back GROUNDED and CALIBRATED."""

    def test_correctly_weighted_hypothesis_is_grounded_and_calibrated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, relationships = _seed_store(tmp_path)
        cert_rel = next(r for r in relationships if r["relationship_type"] == "SHARES_CERTIFICATE")
        ip_rel = next(r for r in relationships if r["relationship_type"] == "SHARES_IPV4")

        batch = HypothesisBatchResult(
            hypotheses=[
                HypothesisProposal(
                    statement=(
                        "These domains likely share commonly-provisioned infrastructure: "
                        "they present the same TLS certificate, which is strong technical "
                        "evidence of common provisioning at issuance time. They also resolve "
                        "to the same IP address, but this is weak, non-conclusive corroboration "
                        "since the address is shared cloud tenancy."
                    ),
                    cited_relationships=[
                        CitedRelationshipClaim(
                            relationship_id=cert_rel["relationship_id"],
                            claimed_relationship_type="SHARES_CERTIFICATE",
                            treated_as_strength=ConfidenceBand.HIGH,
                        ),
                        CitedRelationshipClaim(
                            relationship_id=ip_rel["relationship_id"],
                            claimed_relationship_type="SHARES_IPV4",
                            treated_as_strength=ConfidenceBand.LOW,
                        ),
                    ],
                    cited_entity_ids=[],
                    confidence="HIGH",
                    suggested_next_step=(
                        "Worth checking whether these hosts share other infrastructure beyond "
                        "what is already observed."
                    ),
                )
            ]
        )
        monkeypatch.setattr(
            "core.hypotheses.cli.create_provider", lambda *a, **kw: _FakeProvider(batch)
        )
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0

        rows = store.get_llm_hypotheses(RUN_ID)
        assert len(rows) == 1
        print("\n--- virusbarrier.xyz foundational case result ---")
        print(json.dumps(rows[0], indent=2, default=str))
        assert rows[0]["grounding_status"] == "GROUNDED"
        assert rows[0]["calibration_status"] == "CALIBRATED"

        out = capsys.readouterr().out
        print(out)
        assert "✓" in out


class TestVirusbarrierAdversarialOverInterpretationCase:
    """Design Section 7.2's explicit adversarial case: a hypothesis that
    cites the REAL shared-IP relationship but treats it as HIGH-confidence
    (its real band is MEDIUM) must be caught as OVERSTATED — proving
    grounding alone (the citation is real) is not enough."""

    def test_ip_relationship_overstated_as_high_confidence_is_caught(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store, relationships = _seed_store(tmp_path)
        ip_rel = next(r for r in relationships if r["relationship_type"] == "SHARES_IPV4")

        batch = HypothesisBatchResult(
            hypotheses=[
                HypothesisProposal(
                    statement=(
                        "These domains are strongly linked via shared infrastructure: they "
                        "resolve to the same IP address, which is strong evidence of common "
                        "provisioning."
                    ),
                    cited_relationships=[
                        CitedRelationshipClaim(
                            relationship_id=ip_rel["relationship_id"],
                            claimed_relationship_type="SHARES_IPV4",
                            treated_as_strength=ConfidenceBand.HIGH,  # real band is MEDIUM
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
        settings = _settings(tmp_path)
        rc = cmd_suggest_hypotheses(settings, RUN_ID, yes=True)
        assert rc == 0

        rows = store.get_llm_hypotheses(RUN_ID)
        assert len(rows) == 1
        print("\n--- virusbarrier.xyz adversarial over-interpretation case result ---")
        print(json.dumps(rows[0], indent=2, default=str))
        # The citation is real (grounding must not be fooled into hiding
        # this failure mode as a fabricated citation)...
        assert rows[0]["grounding_status"] == "GROUNDED"
        # ...but the strength claimed is dishonest relative to the real
        # ConfidenceBand — this is what must be caught.
        assert rows[0]["calibration_status"] == "OVERSTATED"
        evidence = rows[0]["evidence"][0]
        assert evidence["real_confidence_band"] == "MEDIUM"
        assert evidence["treated_as_strength"] == "HIGH"
        assert evidence["overstated"] == 1

        out = capsys.readouterr().out
        print(out)
        assert "⚠" in out
        assert "OVERSTATED" in out
