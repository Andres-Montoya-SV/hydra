"""Security audit (hardening round 1, Task 5): SQLite integrity beyond the
reportability tables. The reportability agent already has a composite
`FOREIGN KEY(finding_id, run_id) REFERENCES findings(id, run_id)` pattern
(docs/REPORTABILITY_AGENT_DESIGN.md v2) — this file proves the same
cross-run-contamination protection now exists for `intel_hypotheses`
(`relationship_id`, `evidence_id`), and documents, with a real reproduction,
exactly why the same pattern was tried and reverted for
`intel_indicators.evidence_id` rather than silently applied.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.assets import ScanRun
from core.models import DomainTarget, PipelineContext
from core.registry import HostRegistry
from core.runner import intel_config_for_pipeline
from core.store import AssetStore

FIXTURE = Path(__file__).parent / "fixtures" / "virusbarrier"
import json  # noqa: E402

CASE = json.loads((FIXTURE / "case.json").read_text(encoding="utf-8"))
SEED = CASE["seed"]

_PRODUCTION_ARTIFACTS = (
    "ctlogs.jsonl",
    "ctlogs_domains.txt",
    "httpx.json",
    "dnsx_records.jsonl",
    "resolved.txt",
    "scope.txt",
)


def _persist_real_run(tmp_path: Path, run_id: str) -> AssetStore:
    """Mirrors tests/test_virusbarrier_e2e.py's own helper — a real
    finalize() through the production parser/ingest path (no shortcuts),
    so the relationship_id used below is genuinely engine-produced, not
    hand-crafted to look convenient for this test."""
    import shutil

    output_dir = tmp_path / "output" / run_id
    output_dir.mkdir(parents=True)
    for name in _PRODUCTION_ARTIFACTS:
        shutil.copy2(FIXTURE / name, output_dir / name)
    shutil.copy2(FIXTURE / "resolved.txt", output_dir / "subdomains.txt")

    from config.settings import Settings

    settings = Settings(project_root=tmp_path, scope_file=output_dir / "scope.txt")
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        subdomains=[SEED],
        resolved=[SEED],
        output_dir=output_dir,
        run_id=run_id,
    )
    context.collection_scope = None
    config = intel_config_for_pipeline(context, settings)

    registry = HostRegistry(run_id, output_dir)
    registry.intel_config = config
    for tool in ("ctlogs", "dnsx", "httpx"):
        registry.ingest(tool)
    registry.finalize()

    db_path = tmp_path / "output" / "recon.db"
    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=run_id, started_at="2026-08-21T00:00:00Z", targets=[SEED]))
    store.persist_registry(
        run_id,
        registry.to_dict(),
        clusters=registry.clusters,
        graph=registry.graph,
        intel=registry.intel,
    )
    return store


class TestIntelHypothesesCompositeForeignKeys:
    def test_relationship_id_composite_fk_rejects_a_relationship_from_a_different_run(
        self, tmp_path: Path
    ) -> None:
        store = _persist_real_run(tmp_path, "run_a")
        with store._connect() as conn:  # noqa: SLF001
            row = conn.execute(
                "SELECT relationship_id FROM intel_relationships WHERE run_id=? LIMIT 1",
                ("run_a",),
            ).fetchone()
        assert (
            row is not None
        ), "the real virusbarrier fixture must produce at least one relationship"
        real_relationship_id = row["relationship_id"]

        store.create_run(
            ScanRun(run_id="run_b", started_at="2026-08-21T00:00:00Z", targets=["other.test"])
        )
        with pytest.raises(sqlite3.IntegrityError):
            with store._connect() as conn:  # noqa: SLF001
                conn.execute(
                    """INSERT INTO intel_hypotheses
                       (run_id, hypothesis_id, relationship_id, target_value,
                        confidence_band, status, rationale, depth, kind)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        "run_b",
                        "forged-hyp-1",
                        real_relationship_id,  # real id, but belongs to run_a
                        "evil.test",
                        "HIGH",
                        "OPEN",
                        "forged",
                        1,
                        "RELATED_INFRASTRUCTURE",
                    ),
                )
        # And nothing was left half-written by the rejected attempt.
        with store._connect() as conn:  # noqa: SLF001
            leftover = conn.execute(
                "SELECT COUNT(*) AS n FROM intel_hypotheses WHERE run_id=?", ("run_b",)
            ).fetchone()
        assert leftover["n"] == 0

    def test_evidence_id_composite_fk_rejects_evidence_from_a_different_run(
        self, tmp_path: Path
    ) -> None:
        store = _persist_real_run(tmp_path, "run_a")
        with store._connect() as conn:  # noqa: SLF001
            row = conn.execute(
                "SELECT evidence_id FROM intel_evidence WHERE run_id=? LIMIT 1",
                ("run_a",),
            ).fetchone()
        assert (
            row is not None
        ), "the real virusbarrier fixture must produce at least one evidence row"
        real_evidence_id = row["evidence_id"]

        store.create_run(
            ScanRun(run_id="run_b", started_at="2026-08-21T00:00:00Z", targets=["other.test"])
        )
        with pytest.raises(sqlite3.IntegrityError):
            with store._connect() as conn:  # noqa: SLF001
                conn.execute(
                    """INSERT INTO intel_hypotheses
                       (run_id, hypothesis_id, relationship_id, target_value, evidence_id,
                        confidence_band, status, rationale, depth, kind)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        "run_b",
                        "forged-hyp-2",
                        None,
                        "evil.test",
                        real_evidence_id,  # real id, but belongs to run_a
                        "HIGH",
                        "OPEN",
                        "forged",
                        1,
                        "RELATED_INFRASTRUCTURE",
                    ),
                )

    def test_null_relationship_id_and_evidence_id_are_exempt_from_the_fk(
        self, tmp_path: Path
    ) -> None:
        """A hypothesis is always constructed from a real Relationship in
        practice (core/intel/engine.py), but the schema itself must not
        require one — NULL is a legitimate "no relationship/no evidence
        yet" state, and SQLite exempts NULL FK columns from the check by
        design. Confirms the composite FK doesn't accidentally become a
        NOT NULL requirement in disguise."""
        store = _persist_real_run(tmp_path, "run_a")
        with store._connect() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO intel_hypotheses
                   (run_id, hypothesis_id, relationship_id, target_value, evidence_id,
                    confidence_band, status, rationale, depth, kind)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "run_a",
                    "no-relationship-hyp",
                    None,
                    "evil.test",
                    None,
                    "LOW",
                    "OPEN",
                    "no relationship or evidence yet",
                    1,
                    "RELATED_INFRASTRUCTURE",
                ),
            )
        with store._connect() as conn:  # noqa: SLF001
            row = conn.execute(
                "SELECT * FROM intel_hypotheses WHERE hypothesis_id=?", ("no-relationship-hyp",)
            ).fetchone()
        assert row is not None


class TestIntelIndicatorsEvidenceIdFieldNotCompositeForeignKeyed:
    """Documents, with a real reproduction (not just a code-reading claim),
    exactly why intel_indicators.evidence_id was NOT given the same
    composite-FK treatment as intel_hypotheses above."""

    def test_dns_resolution_indicators_legitimately_store_an_observation_id_in_evidence_id(
        self, tmp_path: Path
    ) -> None:
        """core/intel/engine.py's _ingest_a_or_aaaa sets
        Indicator.evidence_id to an intel_observations.observation_id, not
        a real intel_evidence.evidence_id — confirmed directly against the
        real fixture's own persisted rows, which is why a composite FK to
        intel_evidence on this column would reject legitimate production
        data (verified: it did, during this audit, against
        test_virusbarrier_e2e.py/test_followup_loop.py/
        test_infra_correlation.py — reverted rather than forcing it)."""
        store = _persist_real_run(tmp_path, "run_a")
        with store._connect() as conn:  # noqa: SLF001
            indicator_evidence_ids = {
                row["evidence_id"]
                for row in conn.execute(
                    "SELECT evidence_id FROM intel_indicators WHERE run_id=? AND evidence_id IS NOT NULL",
                    ("run_a",),
                ).fetchall()
            }
            real_evidence_ids = {
                row["evidence_id"]
                for row in conn.execute(
                    "SELECT evidence_id FROM intel_evidence WHERE run_id=?", ("run_a",)
                ).fetchall()
            }
            real_observation_ids = {
                row["observation_id"]
                for row in conn.execute(
                    "SELECT observation_id FROM intel_observations WHERE run_id=?", ("run_a",)
                ).fetchall()
            }
        if indicator_evidence_ids:
            # At least one indicator's "evidence_id" is really an
            # observation_id — the overload this test documents.
            assert indicator_evidence_ids & real_observation_ids
            assert not indicator_evidence_ids.issubset(real_evidence_ids)
