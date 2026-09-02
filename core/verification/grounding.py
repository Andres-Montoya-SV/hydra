"""Report-grounding gate (design Part B.3) — before any claim reaches a
report or CLI command, confirm it has a `raw_artifact` reference, that the
file still exists, and that the cited value appears in it literally.

Deviation from the design doc, found while implementing this (documented
in docs/VERIFICATION_AGENT_DESIGN.md's Section 5 tracking, per the
practice established across this whole project): the design named
`core/intel/query.py::evidence_for`/`evidence_by_relationship` as what this
gate sits in front of, assuming `intel_evidence` rows carry a
`raw_artifact` path. Checked the real schema and model before wiring
anything, per this project's standing rule — they don't:
`core/intel/model.py::Evidence` (`evidence_id, source, collector,
observation_id, reason, metadata, observed_at`) and the `intel_evidence`
table have no artifact-path column at all. That subsystem's evidence is
data-only (a certificate fingerprint, an IP, a SAN list embedded directly
in `metadata`) — verified by reading `core/intel/engine.py::_evidence_from`
and every caller that builds a `metadata` dict for it. There is nothing to
grep a file for.

`raw_artifact`/`artifact_path` genuinely exists in exactly two places:
`provenance` rows (`core/store.py`'s `artifact_path` column — present
today, but not currently rendered in any report either, confirmed by
grepping core/reporter.py) and this package's own `verification_flags`
table. `ground_rows` below is written generically (works over any row
shape via `value_field`/`artifact_field`) so it applies to `provenance`
rows the moment a rendering path for them exists, and applies to
`intel_evidence` if that model ever grows a raw_artifact reference — but
it is wired up today against `verification_flags`, the one place both a
claim and a real raw_artifact path already coexist.
"""

from __future__ import annotations

from pathlib import Path

UNVERIFIABLE = "UNVERIFIABLE"


def is_claim_grounded(value: str, raw_artifact: str | None, output_dir: Path) -> bool:
    """Does `raw_artifact` (relative to `output_dir`) exist and literally
    contain `value`? A `grep`, not a semantic check — design Part B.3 is
    explicit this needs no intelligence, only proof the file backs the claim.
    """
    if not value or not raw_artifact:
        return False
    path = (output_dir / raw_artifact).resolve()
    try:
        if output_dir.resolve() not in path.parents and path != output_dir.resolve():
            return False  # never follow a raw_artifact path outside the run directory
        if not path.is_file():
            return False
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return value in content


def ground_rows(
    rows: list[dict],
    output_dir: Path,
    *,
    value_field: str,
    artifact_field: str = "raw_artifact",
) -> list[dict]:
    """Annotate each row with `grounded: bool` — never drop or silently
    alter a row, only add the verdict. An ungrounded row must be marked
    `UNVERIFIABLE` by the caller (report/CLI layer), never hidden or shown
    with the same confidence as a grounded one (design Part B.3).
    """
    annotated: list[dict] = []
    for row in rows:
        value = str(row.get(value_field) or "")
        artifact = row.get(artifact_field)
        grounded = is_claim_grounded(value, artifact, output_dir) if artifact else False
        enriched = dict(row)
        enriched["grounded"] = grounded
        if not grounded:
            enriched["grounding_status"] = UNVERIFIABLE
        annotated.append(enriched)
    return annotated
