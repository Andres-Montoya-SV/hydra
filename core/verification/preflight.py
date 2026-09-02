"""Pre-flight verification (design Part B.1) — runs before
`PipelineRunner.run()`, using only data already available at that point
(the loaded `Settings`, `SCOPE_FILE`, and prior runs already in SQLite).

Advisory only: every check here returns a `VerificationFinding` (or a list
of them) for the caller to surface to the operator. Nothing in this module
raises, blocks a run, or rewrites `SCOPE_FILE`/`.env` — see
docs/VERIFICATION_AGENT_DESIGN.md Part D.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from core.verification.model import ContradictionSeverity, VerificationFinding

if TYPE_CHECKING:
    from core.store import AssetStore


def compute_scope_file_hash(scope_file: Path | None) -> str | None:
    """A hash of SCOPE_FILE's contents, never the contents themselves — the
    `runs.scope_file_hash` column only needs to answer "is this the same
    file as last time", not reproduce the file.
    """
    if not scope_file:
        return None
    try:
        content = scope_file.read_bytes()
    except OSError:
        return None
    return "sha256:" + hashlib.sha256(content).hexdigest()


def compute_attribution_fingerprint(
    researcher_attribution_header: dict[str, str] | None,
    attribution_user_agent: str | None,
) -> str | None:
    """A fingerprint of the RESEARCHER_ATTRIBUTION_HEADER/ATTRIBUTION_USER_AGENT
    pair actually in effect — never the raw values, which may carry an
    operator handle/token not meant for a queryable `runs` column.
    """
    header = dict(researcher_attribution_header or {})
    user_agent = attribution_user_agent or ""
    if not header and not user_agent:
        return None
    canonical = json.dumps({"header": header, "user_agent": user_agent}, sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_domain(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def historical_cross_check(
    store: AssetStore,
    *,
    program_name: str,
    scope_file_hash: str | None,
    attribution_fingerprint: str | None,
    current_scope_domains: list[str],
) -> list[VerificationFinding]:
    """Compare the current run's configuration against the most recent
    finished run declared under the same PROGRAM_NAME (design Part B.1).

    A first run for a given `program_name` naturally has nothing to compare
    against — returns `[]`, not a "missing history" finding. Every check
    here is DOWNGRADES_CONFIDENCE, never INVALIDATES: a changed scope file
    or attribution header might be entirely intentional (a program's scope
    legitimately grew, a researcher rotated handles) — this raises the
    question for the operator, it does not claim the current run is wrong.
    """
    findings: list[VerificationFinding] = []
    name = (program_name or "").strip()
    if not name:
        return findings

    previous_run_id = store.find_latest_finished_run_for_program(name)
    if previous_run_id is None:
        return findings
    previous = store.get_run(previous_run_id)
    if previous is None:
        return findings

    if (
        scope_file_hash
        and previous.get("scope_file_hash")
        and scope_file_hash != previous["scope_file_hash"]
    ):
        findings.append(
            VerificationFinding(
                claim=f"PROGRAM_NAME {name!r}: SCOPE_FILE matches this program's prior runs",
                evidence=(
                    f"scope_file_hash differs from the most recent finished run for "
                    f"this program ({previous_run_id})"
                ),
                raw_artifact=None,
                severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
                detector="historical_cross_check_scope_file",
                related_table="runs",
                related_id=previous_run_id,
            )
        )

    if (
        attribution_fingerprint
        and previous.get("attribution_fingerprint")
        and attribution_fingerprint != previous["attribution_fingerprint"]
    ):
        findings.append(
            VerificationFinding(
                claim=(
                    f"PROGRAM_NAME {name!r}: attribution header/User-Agent matches "
                    "this program's prior runs"
                ),
                evidence=(
                    f"attribution_fingerprint differs from the most recent finished "
                    f"run for this program ({previous_run_id}) — check "
                    "RESEARCHER_ATTRIBUTION_HEADER/ATTRIBUTION_USER_AGENT against "
                    "PROGRAM_NAME before running anything active"
                ),
                raw_artifact=None,
                severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
                detector="historical_cross_check_attribution",
                related_table="runs",
                related_id=previous_run_id,
            )
        )

    previous_targets = {_normalize_domain(t) for t in previous.get("targets", [])}
    current_domains = {_normalize_domain(d) for d in current_scope_domains if d}
    if previous_targets and current_domains and previous_targets.isdisjoint(current_domains):
        findings.append(
            VerificationFinding(
                claim=(
                    f"PROGRAM_NAME {name!r}: current SCOPE_FILE overlaps this "
                    "program's prior targets"
                ),
                evidence=(
                    f"no domain in the current run overlaps the most recent finished "
                    f"run for this program ({previous_run_id}, targets="
                    f"{sorted(previous_targets)})"
                ),
                raw_artifact=None,
                severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
                detector="historical_cross_check_target_overlap",
                related_table="runs",
                related_id=previous_run_id,
            )
        )

    return findings
