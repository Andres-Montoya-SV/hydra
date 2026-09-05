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

from core.verification.model import ContradictionSeverity, VerificationStatus

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


# ---------------------------------------------------------------------------
# Report-side gate (design Part 3 / integration): before summary.json,
# overview.md, the HTML report, or the CLI's completion table show a
# High-Priority Infrastructure host or an Intelligence Relationship, check
# whether this run's own verification_flags already proved something about
# it wrong. Pure functions over `AssetStore.get_verification_flags()`'s
# already-dict-shaped rows — no I/O, no new persistence, callable from
# core/reporter.py, ui/tables.py, and core/intel/cli.py alike.
# ---------------------------------------------------------------------------


def partition_verification_flags_by_host(
    flags: list[dict[str, object]],
) -> tuple[dict[str, list[dict[str, object]]], dict[str, list[dict[str, object]]]]:
    """Group a run's verification_flags rows by host into
    (invalidated, downgraded) maps.

    A host with at least one INVALIDATES flag must be excluded from the
    normal report sections and moved to a visible "Contradicted /
    Unverifiable Findings" section instead (design Part 3, item 3) — the
    detector already proved the claim about it is simply wrong, not merely
    uncertain. A host with only DOWNGRADES_CONFIDENCE flags stays in its
    normal place with a reduced confidence_score and a visible note
    (`downgrade_note` below) instead.

    A flag with no `host` at all (e.g. historical_cross_check's run-level
    findings, which describe the whole run's configuration rather than any
    one host) is not host-scoped and has nothing to attach to in a
    per-host report section — skipped here, not lost: it already surfaced
    as a pre-flight warning when the run started.
    """
    invalidated: dict[str, list[dict[str, object]]] = {}
    downgraded: dict[str, list[dict[str, object]]] = {}
    for flag in flags:
        host = flag.get("host")
        if not host or not isinstance(host, str):
            continue
        severity = flag.get("severity")
        if severity == ContradictionSeverity.INVALIDATES.value:
            invalidated.setdefault(host, []).append(flag)
        elif severity == ContradictionSeverity.DOWNGRADES_CONFIDENCE.value:
            downgraded.setdefault(host, []).append(flag)
    return invalidated, downgraded


# Report-display-only penalty applied to a host's shown confidence_score
# when it has a DOWNGRADES_CONFIDENCE flag — never written back to the
# `hosts` table itself, only to what a report/CLI renders for it.
_DOWNGRADE_PENALTY = 25


def downgraded_confidence_score(confidence_score: int, downgrade_flags: list[dict]) -> int:
    """The confidence_score a report should display for a host with at
    least one DOWNGRADES_CONFIDENCE flag — a flat penalty regardless of how
    many such flags exist (a second and third independent doubt about the
    same host do not make the original evidence progressively less true;
    they are still the same underlying "a second source disagrees" fact),
    floored at 0.
    """
    if not downgrade_flags:
        return confidence_score
    return max(0, confidence_score - _DOWNGRADE_PENALTY)


def downgrade_note(downgrade_flags: list[dict]) -> str:
    """One-line, human-readable reason a host's confidence was reduced —
    the first flag's claim/evidence, plus a count when there is more than
    one."""
    if not downgrade_flags:
        return ""
    first = downgrade_flags[0]
    note = f"{first.get('claim', '')} — {first.get('evidence', '')}"
    if len(downgrade_flags) > 1:
        note += f" (+{len(downgrade_flags) - 1} more)"
    return note


def summarize_verification_flags(flags: list[dict[str, object]]) -> dict[str, int]:
    """Counts for the one-line CLI/report summary (design Part 3, item 4):
    `confirmed` (stays visible in the report, possibly with a reduced
    confidence_score), `pending` (status UNRESOLVED — no verdict yet, e.g.
    catalog item 9's own kind of open question), and `invalidated`
    (excluded from the report entirely, moved to the Contradicted
    Findings section).
    """
    invalidated = 0
    pending = 0
    confirmed = 0
    for flag in flags:
        if flag.get("status") == VerificationStatus.UNRESOLVED.value:
            pending += 1
        elif flag.get("severity") == ContradictionSeverity.INVALIDATES.value:
            invalidated += 1
        else:
            confirmed += 1
    return {
        "confirmed": confirmed,
        "pending": pending,
        "invalidated": invalidated,
        "total": len(flags),
    }
