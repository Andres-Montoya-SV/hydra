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

import difflib
import re
import unicodedata
from pathlib import Path

from core.verification.model import ContradictionSeverity, VerificationStatus

UNVERIFIABLE = "UNVERIFIABLE"


def _read_confined_artifact(raw_artifact: str | None, output_dir: Path) -> str | None:
    """Resolve `raw_artifact` relative to `output_dir`, refusing to follow
    it outside that directory, and return its text — or `None` if it's
    missing, unreadable, or escapes confinement. Shared by every grounding
    check in this module; do not duplicate this path-confinement logic
    elsewhere.
    """
    if not raw_artifact:
        return None
    path = (output_dir / raw_artifact).resolve()
    try:
        if output_dir.resolve() not in path.parents and path != output_dir.resolve():
            return None  # never follow a raw_artifact path outside the run directory
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def is_claim_grounded(value: str, raw_artifact: str | None, output_dir: Path) -> bool:
    """Does `raw_artifact` (relative to `output_dir`) exist and literally
    contain `value`? A `grep`, not a semantic check — design Part B.3 is
    explicit this needs no intelligence, only proof the file backs the claim.
    """
    if not value:
        return False
    content = _read_confined_artifact(raw_artifact, output_dir)
    if content is None:
        return False
    return value in content


# ---------------------------------------------------------------------------
# Citation grounding (docs/REPORTABILITY_AGENT_DESIGN.md Part C.3) — like
# is_claim_grounded above, but with a bounded, still-deterministic (no
# second LLM) tolerance for whitespace/punctuation-only reformatting that
# is_claim_grounded's exact-substring check would reject. is_claim_grounded
# itself is untouched: verification_flags keeps its existing exact-match
# behavior, which has no "paraphrase" to tolerate in the first place (a
# deterministic detector citing its own structured input never rephrases
# anything).
# ---------------------------------------------------------------------------

_WHITESPACE_RE = re.compile(r"\s+")
_TRAILING_PUNCTUATION_RE = re.compile(r"[.…]+$")  # trailing '.' or '…'

# Threshold justified empirically against the real Stripchat program rules
# text (tests/fixtures/stripchat_rules.txt) before being chosen — not
# picked arbitrarily. Measured with difflib.SequenceMatcher.ratio() on
# real sentences from that file:
#   - Genuine minor reformatting (dropped trailing period, case folded,
#     smart quotes) scored 0.987-1.000 — comfortably above any threshold
#     considered here.
#   - A single negation flipped in an otherwise-identical real sentence
#     ("...is prohibited." -> "...is permitted.", "...are not legally
#     guaranteed." -> "...are legally guaranteed.") scored 0.921-0.975 —
#     i.e. dangerously close to "minor paraphrase" territory by raw
#     character similarity alone, because flipping one short word barely
#     changes the string even though it inverts the sentence's meaning.
#   - A fabricated sentence with no real counterpart in the source scored
#     at most 0.430 against any real line.
# 0.98 was chosen specifically because it sits above every measured
# negation-flip case (max observed: 0.975) and below every case that
# needed it (whitespace/case/quote variants are handled by exact matching
# on NORMALIZED text below, before this ratio ever runs, precisely so this
# threshold never has to be loose enough to also cover whitespace noise).
# This is a real, acknowledged residual risk, not a false guarantee: a
# very short sentence where a one-word negation happens to exceed 0.98 is
# not mathematically impossible. `is_citation_grounded` reports which
# check actually matched (see `grounding_method` in `ground_citation_row`)
# so a citation that only passed via this fuzzy fallback — never one that
# matched exactly — can be surfaced for extra scrutiny.
_FUZZY_MATCH_THRESHOLD = 0.98


def _normalize_for_comparison(text: str) -> str:
    """Case-fold, fold smart quotes/dashes to their ASCII form, collapse
    all whitespace runs to a single space, and drop a bare trailing
    '.'/'…' — every one of these is a real, harmless way Claude has been
    observed to reformat a quote when asked to cite verbatim, and none of
    them can change a sentence's meaning. Deliberately NOT dropped: any
    other punctuation, and any word — only whitespace/quote-style/trailing-
    terminator noise is normalized away here.
    """
    folded = unicodedata.normalize("NFKC", text)
    # str.maketrans's single-arg overload is typed over dict[str | int, ...]
    # (a real accepted call shape at runtime), but a bare dict[str, str]
    # literal is invariant and mypy won't widen it implicitly — spell the
    # annotation out explicitly rather than casting past the check.
    quote_and_dash_map: dict[str | int, str | int | None] = {
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "–": "-",
        "—": "-",
    }
    folded = folded.translate(str.maketrans(quote_and_dash_map))
    folded = _WHITESPACE_RE.sub(" ", folded).strip().lower()
    return _TRAILING_PUNCTUATION_RE.sub("", folded).strip()


def _split_into_spans(text: str) -> list[str]:
    """Candidate spans to fuzzy-match a citation against: each non-empty
    line, plus each sentence within a line (split on '. ') — program rules
    text is typically one point per line, but a line can carry more than
    one sentence."""
    spans: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        spans.append(line)
        spans.extend(part.strip() for part in line.split(". ") if part.strip())
    return spans


def is_citation_grounded(
    citation: str,
    raw_artifact: str | None,
    output_dir: Path,
    *,
    allow_minor_paraphrase: bool = True,
) -> tuple[bool, str]:
    """Like `is_claim_grounded`, with a bounded tolerance for minor
    reformatting. Returns `(grounded, method)` — `method` is one of
    `"exact"`, `"normalized"`, `"fuzzy"`, or `"none"`, so a caller can
    surface *how* a citation was grounded (design Part C.3: a citation
    that only passed via the fuzzy fallback is weaker evidence than an
    exact match, and that distinction should stay visible, not be
    collapsed into a single boolean).

    No LLM at any step — every check here is a plain-text algorithm, per
    this design's own non-negotiable constraint (a second model judging
    whether a paraphrase is "close enough" would defeat the entire point
    of demanding literal quotes in the first place).
    """
    if not citation:
        return False, "none"
    content = _read_confined_artifact(raw_artifact, output_dir)
    if content is None:
        return False, "none"

    if citation in content:
        return True, "exact"

    normalized_citation = _normalize_for_comparison(citation)
    normalized_content = _normalize_for_comparison(content)
    if normalized_citation and normalized_citation in normalized_content:
        return True, "normalized"

    if not allow_minor_paraphrase:
        return False, "none"

    best_ratio = 0.0
    for span in _split_into_spans(content):
        ratio = difflib.SequenceMatcher(
            None, normalized_citation, _normalize_for_comparison(span)
        ).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
    if best_ratio >= _FUZZY_MATCH_THRESHOLD:
        return True, "fuzzy"
    return False, "none"


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
