"""`python app.py assess-reportability` — the standalone command (design
Part D.1). Never invoked by `python app.py run`; the operator always
triggers this explicitly, always sees a real cost estimate first, and
always confirms before any API credits are spent.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from core.intel.cli import default_db
from core.reportability.client import ReportabilityAPIError, ReportabilityClient
from core.reportability.model import Eligibility, ReportabilityAssessment
from core.store import AssetStore
from core.verification.grounding import is_citation_grounded
from utils.security import validate_readable_file
from utils.validators import sanitize_run_id

if TYPE_CHECKING:
    from config.settings import Settings

# Published per-million-input-token pricing, current as of this
# implementation (platform.claude.com/docs/en/about-claude/pricing) — a
# point-in-time snapshot for the cost estimate below, not fetched live.
# Confirm current pricing before trusting this for a large batch.
_INPUT_PRICE_PER_MTOK: dict[str, float] = {
    "claude-fable-5-1": 10.00,
    "claude-mythos-5-1": 10.00,
    "claude-fable-5": 10.00,
    "claude-opus-5": 5.00,
    "claude-opus-4-8": 5.00,
    "claude-opus-4-7": 5.00,
    "claude-opus-4-6": 5.00,
    "claude-sonnet-5": 2.00,
    "claude-sonnet-4-6": 3.00,
    "claude-haiku-4-5": 1.00,
    "claude-haiku-4-5-20251001": 1.00,
}

_PROGRAM_RULES_ARTIFACT_NAME = "program_rules_snapshot.txt"


def cmd_assess_reportability(
    settings: Settings,
    run_id: str,
    program_rules_path: Path,
    *,
    severity: str | None = None,
    host: str | None = None,
    limit: int | None = None,
    yes: bool = False,
) -> int:
    # Unlike core/intel/cli.py's other run_id-taking commands (pure reads
    # through parameterized SQL), this command WRITES a file
    # (program_rules_snapshot.txt) to a path built from run_id — sanitize
    # defensively before it ever reaches a filesystem path.
    sanitize_run_id(run_id)

    if not settings.anthropic_api_key:
        print(
            "Error: ANTHROPIC_API_KEY is not configured. This command is opt-in and does "
            "nothing without it — see docs/REPORTABILITY_AGENT_DESIGN.md and "
            "config/.env.example.",
            file=sys.stderr,
        )
        return 1

    db_path = default_db(settings.project_root, settings.output_directory)
    if not db_path.exists():
        print(f"Error: intelligence database not found: {db_path}", file=sys.stderr)
        return 1
    output_dir = db_path.parent / run_id
    if not output_dir.is_dir():
        print(f"Error: run directory not found: {output_dir}", file=sys.stderr)
        return 1

    try:
        rules_path = validate_readable_file(program_rules_path)
    except Exception as exc:  # ValidationError from utils.security
        print(f"Error: --program-rules {exc}", file=sys.stderr)
        return 1
    rules_text = rules_path.read_text(encoding="utf-8", errors="replace")
    if not rules_text.strip():
        print(f"Error: --program-rules file is empty: {rules_path}", file=sys.stderr)
        return 1

    store = AssetStore(db_path)
    severities = [s.strip().lower() for s in severity.split(",") if s.strip()] if severity else None
    findings = store.get_findings(run_id, severity=severities, host=host)
    if not findings:
        print(f"No findings match these filters for run {run_id!r}. Nothing to assess.")
        return 0

    effective_limit = limit if limit is not None else settings.reportability_max_findings_per_batch
    if len(findings) > effective_limit:
        print(
            f"Error: {len(findings)} findings match these filters, which exceeds the "
            f"configured limit of {effective_limit} (REPORTABILITY_MAX_FINDINGS_PER_BATCH, "
            "or --limit). Refusing to silently assess only some of them — narrow the "
            "selection with --severity/--host, or pass --limit to raise the ceiling "
            "explicitly for this run.",
            file=sys.stderr,
        )
        return 1

    try:
        client = ReportabilityClient(
            api_key=settings.anthropic_api_key, model=settings.anthropic_model
        )
    except ReportabilityAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(
        f"{len(findings)} finding(s) selected for run {run_id!r}, model {settings.anthropic_model!r}."
    )
    try:
        input_tokens = client.count_input_tokens(rules_text, findings)
    except ReportabilityAPIError as exc:
        print(f"Error estimating cost: {exc}", file=sys.stderr)
        return 1
    price_per_mtok = _INPUT_PRICE_PER_MTOK.get(settings.anthropic_model)
    if price_per_mtok is not None:
        input_cost = input_tokens / 1_000_000 * price_per_mtok
        print(
            f"Estimated input: {input_tokens:,} tokens (~${input_cost:.4f}). "
            "Output cost is not knowable in advance and is NOT included in this estimate "
            "— see https://platform.claude.com/docs/en/about-claude/pricing for current rates."
        )
    else:
        print(
            f"Estimated input: {input_tokens:,} tokens. No published price is on file for "
            f"model {settings.anthropic_model!r} — check "
            "https://platform.claude.com/docs/en/about-claude/pricing for current rates."
        )

    if not yes:
        if not sys.stdin.isatty():
            print(
                "Non-interactive stdin — refusing to spend API credits without confirmation "
                "(fail closed). Re-run with a terminal attached to confirm, or pass --yes "
                "in an automated context you control.",
                file=sys.stderr,
            )
            return 1
        answer = input("Proceed with this assessment? [y/N]: ")
        if answer.strip().lower() not in {"y", "yes"}:
            print("Declined — no API call made.")
            return 1

    try:
        result = client.assess_batch(rules_text, findings)
    except ReportabilityAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Snapshot the exact rules text this assessment was made against
    # (design Part C.4) — only after a successful call, so a failed/
    # declined run never leaves a stray snapshot with no assessments
    # behind it.
    artifact_path = output_dir / _PROGRAM_RULES_ARTIFACT_NAME
    artifact_path.write_text(rules_text, encoding="utf-8")

    valid_finding_ids = {f["id"] for f in findings}
    assessments: list[ReportabilityAssessment] = []
    counts = {"ELIGIBLE": 0, "NOT_ELIGIBLE": 0, "UNCERTAIN": 0}
    ungrounded: list[tuple[int, str]] = []
    for item in result.assessments:
        if item.finding_id not in valid_finding_ids:
            print(
                f"Warning: Claude returned an assessment for finding_id={item.finding_id}, "
                "which was not in the requested batch — discarded.",
                file=sys.stderr,
            )
            continue
        citation = item.rule_citation.strip()
        grounded: bool | None = None
        if citation:
            grounded, _method = is_citation_grounded(
                citation, _PROGRAM_RULES_ARTIFACT_NAME, output_dir
            )
            if not grounded:
                ungrounded.append((item.finding_id, citation))
        assessments.append(
            ReportabilityAssessment(
                finding_id=item.finding_id,
                eligibility=Eligibility(item.eligibility),
                rule_citation=citation,
                program_rules_artifact=_PROGRAM_RULES_ARTIFACT_NAME,
                model_used=settings.anthropic_model,
                citation_grounded=grounded,
                reasoning=item.reasoning,
            )
        )
        counts[item.eligibility] += 1

    store.record_reportability_assessments(run_id, assessments)

    print()
    print(
        f"Assessed {len(assessments)} finding(s): {counts['ELIGIBLE']} ELIGIBLE, "
        f"{counts['NOT_ELIGIBLE']} NOT_ELIGIBLE, {counts['UNCERTAIN']} UNCERTAIN."
    )
    if ungrounded:
        print(
            f"\n⚠ {len(ungrounded)} citation(s) did NOT verify against the rules text and "
            "are marked UNGROUNDED — treat these verdicts with the same skepticism as an "
            "unsupported claim, not as confirmed:"
        )
        for finding_id, citation in ungrounded:
            print(f"  - finding_id={finding_id}: {citation!r}")
    else:
        print("Every non-empty citation verified against the rules text.")
    return 0
