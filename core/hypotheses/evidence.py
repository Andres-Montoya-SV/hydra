"""Gathers exactly the input the hypothesis engine is allowed to read for
one run (docs/HYPOTHESIS_ENGINE_DESIGN.md Section A.1): already-persisted
`intel_relationships`/`intel_entities`, plus `findings` filtered against
`verification_flags`. Never raw collection artifacts — if the correlation
engine hasn't turned something into an `intel_entities`/
`intel_relationships` row, this module has no business reading it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.store import AssetStore

# Matches the correlation engine's own default cap on relationships
# emitted per correlation signal (core/intel/model.py's Bounds), applied
# here as the ceiling on how many relationship rows one gathering pass
# reads for a single run — a run correlating thousands of relationships
# should not silently blow up a single LLM call's input size.
DEFAULT_MAX_RELATIONSHIPS = 200


@dataclass
class RunEvidence:
    """Everything one `suggest-hypotheses` batch is allowed to see for a
    run — already-correlated, already-verified. `relationships`/
    `entities` are raw `sqlite3.Row`-derived dicts (the same shape
    `core.intel.cli`'s own CLI commands print), not re-hydrated
    dataclasses — the hypothesis engine only ever reads these fields back
    out for the prompt and the grounding check, never mutates or
    re-persists them.
    """

    relationships: list[dict[str, Any]] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.relationships and not self.entities and not self.findings

    def relationship_by_id(self, relationship_id: str) -> dict[str, Any] | None:
        for rel in self.relationships:
            if rel.get("relationship_id") == relationship_id:
                return rel
        return None

    def entity_by_id(self, entity_id: str) -> dict[str, Any] | None:
        for ent in self.entities:
            if ent.get("entity_id") == entity_id:
                return ent
        return None


def gather_run_evidence(
    store: AssetStore, run_id: str, *, max_relationships: int = DEFAULT_MAX_RELATIONSHIPS
) -> RunEvidence:
    """Read-only: `intel_relationships` (every `RelationshipType`, ordered
    by type — design Section A.1, not just `SAN_CONTAINS`) and every
    referenced `intel_entities` row, plus `findings` with any finding on a
    host carrying an active, unresolved `INVALIDATES` verification flag
    excluded (design: "an unverified or invalidated finding must never
    become hypothesis input").

    Verified against the real schema before writing this, not assumed
    from the design doc's own framing: `verification_flags` links to a
    `host`, not a specific `findings.id` row (`related_table`/
    `related_id` are only ever populated with `"runs"` in this codebase
    today, per `core/verification/preflight.py` — there is no per-finding
    linkage to adapt to). The design's "invalidated finding must never
    become input" is therefore applied at the host level: a finding is
    excluded if its own `host` has a `CONFIRMED`/`INVALIDATES` flag
    against it, which is the real granularity this codebase's
    verification agent operates at.
    """
    conn = store.intel_connection()
    try:
        relationships = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM intel_relationships WHERE run_id=? "
                "ORDER BY relationship_type, source_entity LIMIT ?",
                (run_id, max_relationships),
            ).fetchall()
        ]
        entities = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM intel_entities WHERE run_id=?",
                (run_id,),
            ).fetchall()
        ]
        invalidated_hosts = {
            row["host"]
            for row in conn.execute(
                "SELECT DISTINCT host FROM verification_flags "
                "WHERE run_id=? AND status='CONFIRMED' AND severity='INVALIDATES' "
                "AND host IS NOT NULL",
                (run_id,),
            ).fetchall()
        }
    finally:
        conn.close()

    findings = [f for f in store.get_findings(run_id) if f.get("host") not in invalidated_hosts]
    return RunEvidence(relationships=relationships, entities=entities, findings=findings)
