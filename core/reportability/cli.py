"""`python app.py assess-reportability` — the standalone command (design
Part D.1, v2 addendum for provider selection and adversarial cross-
validation). Never invoked by `python app.py run`; the operator always
triggers this explicitly, always sees a real cost estimate first, and
always confirms before any API credits are spent.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from core.intel.cli import default_db
from core.reportability.batch import validate_exact_batch
from core.reportability.errors import BatchValidationError, ReportabilityAPIError
from core.reportability.model import (
    AdversarialFindingReview,
    Confidence,
    Eligibility,
    ReportabilityAssessment,
    ReviewChallenge,
    combine_eligibility,
)
from core.reportability.prompt import PROMPT_VERSION
from core.reportability.provider import SUPPORTED_PROVIDERS, create_provider
from core.store import AssetStore
from core.verification.grounding import is_citation_grounded
from utils.security import validate_readable_file
from utils.validators import sanitize_run_id

if TYPE_CHECKING:
    from config.settings import Settings
    from core.reportability.provider import ReportabilityProvider

# Published per-million-input-token pricing, current as of this
# implementation — a point-in-time snapshot for the cost estimate below,
# not fetched live. Confirm current pricing before trusting this for a
# large batch. Anthropic prices verified at platform.claude.com/docs/en/
# about-claude/pricing; OpenAI prices verified at
# platform.openai.com/docs/guides/models (Terra, Luna only — Astra/Sol
# pricing was not verified and is deliberately left out rather than
# guessed; see the "no published price on file" fallback below).
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
    "gpt-5.6-terra": 2.00,
    "gpt-5.6-luna": 0.20,
}

_PROGRAM_RULES_ARTIFACT_NAME = "program_rules_snapshot.txt"

# Adversarial review's input includes the full rules text + findings again
# (like the primary call) PLUS every primary verdict appended per finding.
# This is a fixed per-finding token overhead used only to produce a
# pre-spend ESTIMATE for the adversarial call before it has actually been
# made (the real primary output isn't known yet at estimate time) — never
# used for anything except that estimate.
_ADVERSARIAL_OVERHEAD_TOKENS_PER_FINDING = 150


def _provider_env_var(provider_name: str) -> str:
    return "ANTHROPIC_API_KEY" if provider_name == "anthropic" else "OPENAI_API_KEY"


def _provider_credentials(settings: Settings, provider_name: str) -> tuple[str | None, str]:
    if provider_name == "anthropic":
        return settings.anthropic_api_key, settings.anthropic_model
    return settings.openai_api_key, settings.openai_model


def _cost_line(provider_name: str, model: str, tokens: int, *, approximate: bool) -> str:
    label = "~" if approximate else ""
    price_per_mtok = _INPUT_PRICE_PER_MTOK.get(model)
    if price_per_mtok is None:
        return (
            f"{label}{tokens:,} tokens for {provider_name}/{model}. No published price is on "
            f"file for this model — check the provider's current pricing page."
        )
    cost = tokens / 1_000_000 * price_per_mtok
    return f"{label}{tokens:,} tokens for {provider_name}/{model} (~${cost:.4f})"


def cmd_assess_reportability(
    settings: Settings,
    run_id: str,
    program_rules_path: Path,
    *,
    severity: str | None = None,
    host: str | None = None,
    limit: int | None = None,
    yes: bool = False,
    provider: str | None = None,
    adversarial_provider: str | None = None,
    allow_fuzzy_grounding: bool = False,
) -> int:
    # Unlike core/intel/cli.py's other run_id-taking commands (pure reads
    # through parameterized SQL), this command WRITES a file
    # (program_rules_snapshot.txt) to a path built from run_id — sanitize
    # defensively before it ever reaches a filesystem path.
    sanitize_run_id(run_id)

    provider_name = provider or settings.reportability_provider
    adversarial_name = adversarial_provider or settings.reportability_adversarial_provider

    if provider_name not in SUPPORTED_PROVIDERS:
        print(
            f"Error: --provider {provider_name!r} is not supported — must be one of "
            f"{SUPPORTED_PROVIDERS}.",
            file=sys.stderr,
        )
        return 1
    if adversarial_name is not None:
        if adversarial_name not in SUPPORTED_PROVIDERS:
            print(
                f"Error: --adversarial-provider {adversarial_name!r} is not supported — must "
                f"be one of {SUPPORTED_PROVIDERS}.",
                file=sys.stderr,
            )
            return 1
        if adversarial_name == provider_name:
            print(
                "Error: --adversarial-provider must be a different provider than --provider. "
                'Using the same provider to "cross-validate" itself shares the same failure '
                "modes (the same training data, the same blind spots) and defeats the point "
                "of adversarial cross-validation.",
                file=sys.stderr,
            )
            return 1

    api_key, model = _provider_credentials(settings, provider_name)
    if not api_key:
        print(
            f"Error: {_provider_env_var(provider_name)} is not configured. This command is "
            "opt-in and does nothing without it — see docs/REPORTABILITY_AGENT_DESIGN.md and "
            "config/.env.example.",
            file=sys.stderr,
        )
        return 1

    adversarial_api_key: str | None = None
    adversarial_model = ""
    if adversarial_name is not None:
        adversarial_api_key, adversarial_model = _provider_credentials(settings, adversarial_name)
        if not adversarial_api_key:
            print(
                f"Error: {_provider_env_var(adversarial_name)} is not configured — required "
                "for --adversarial-provider.",
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

    # Deferred, not module-level: core.reportability.client/openai_client ->
    # schema.py requires pydantic, and each client module requires its own
    # SDK. Neither is a hard dependency of Hydra as a whole
    # (requirements-optional.txt only) — importing core.reportability.cli
    # itself must never require them, so this whole package stays
    # importable (and its tests collectable) on a machine that only
    # installed requirements-dev.txt.
    try:
        primary: ReportabilityProvider = create_provider(
            provider_name, api_key=api_key, model=model
        )
        adversarial: ReportabilityProvider | None = None
        if adversarial_name is not None and adversarial_api_key is not None:
            adversarial = create_provider(
                adversarial_name, api_key=adversarial_api_key, model=adversarial_model
            )
    except (ReportabilityAPIError, ImportError) as exc:
        print(
            f"Error: {exc}. This command requires the optional reportability dependencies "
            "— install them with `pip install -r requirements-optional.txt`.",
            file=sys.stderr,
        )
        return 1

    print(f"{len(findings)} finding(s) selected for run {run_id!r}.")
    print(f"Primary provider: {provider_name}/{model}")
    if adversarial is not None:
        print(f"Adversarial provider: {adversarial_name}/{adversarial_model}")

    try:
        input_tokens = primary.count_input_tokens(rules_text, findings)
    except ReportabilityAPIError as exc:
        print(f"Error estimating cost: {exc}", file=sys.stderr)
        return 1
    print(
        "Estimated input: "
        + _cost_line(provider_name, model, input_tokens, approximate=(provider_name == "openai"))
    )
    if provider_name == "openai":
        print(
            "  (OpenAI has no free token-count endpoint like Anthropic's — this is a "
            "character-based approximation, not an exact count.)"
        )
    if adversarial is not None:
        adversarial_estimate = input_tokens + _ADVERSARIAL_OVERHEAD_TOKENS_PER_FINDING * len(
            findings
        )
        print(
            "Estimated adversarial review input (approximate — the real primary output size "
            "isn't known until after the primary call): "
            + _cost_line(
                adversarial_name, adversarial_model, adversarial_estimate, approximate=True
            )
        )
    print(
        "Output cost is not knowable in advance and is NOT included in any estimate above — "
        "check each provider's current pricing page for exact rates."
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

    valid_finding_ids = [f["id"] for f in findings]

    try:
        primary_result = primary.assess_batch(rules_text, findings)
    except ReportabilityAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        validate_exact_batch(valid_finding_ids, primary_result.assessments)
    except BatchValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    review_by_finding_id: dict[int, object] = {}
    if adversarial is not None:
        try:
            review_result = adversarial.review_batch(rules_text, findings, primary_result)
        except ReportabilityAPIError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        try:
            validate_exact_batch(valid_finding_ids, review_result.reviews)
        except BatchValidationError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        review_by_finding_id = {r.finding_id: r for r in review_result.reviews}

    # Snapshot the exact rules text this assessment was made against
    # (design Part C.4) — only after both calls structurally validated, so
    # a failed/declined/malformed-batch run never leaves a stray snapshot
    # with no assessments behind it.
    artifact_path = output_dir / _PROGRAM_RULES_ARTIFACT_NAME
    artifact_path.write_text(rules_text, encoding="utf-8")
    rules_hash = hashlib.sha256(rules_text.encode("utf-8")).hexdigest()

    assessments: list[ReportabilityAssessment] = []
    disagreements: list[tuple[int, Eligibility, ReviewChallenge]] = []
    counts = {"ELIGIBLE": 0, "NOT_ELIGIBLE": 0, "UNCERTAIN": 0}
    ungrounded: list[tuple[int, str]] = []
    for item in primary_result.assessments:
        citation = item.rule_citation.strip()
        grounded: bool | None = None
        method = "none"
        if citation:
            grounded, method = is_citation_grounded(
                citation,
                _PROGRAM_RULES_ARTIFACT_NAME,
                output_dir,
                allow_minor_paraphrase=allow_fuzzy_grounding,
            )
            if not grounded:
                ungrounded.append((item.finding_id, citation))

        primary_eligibility = Eligibility(item.eligibility)
        final_eligibility = primary_eligibility
        review = review_by_finding_id.get(item.finding_id)
        if review is not None:
            challenge = ReviewChallenge(review.challenge)
            final_eligibility = combine_eligibility(primary_eligibility, challenge)
            if challenge is not ReviewChallenge.AGREE:
                disagreements.append((item.finding_id, primary_eligibility, challenge))

        assessments.append(
            ReportabilityAssessment(
                finding_id=item.finding_id,
                eligibility=primary_eligibility,
                final_eligibility=final_eligibility,
                rule_citation=citation,
                program_rules_artifact=_PROGRAM_RULES_ARTIFACT_NAME,
                provider=provider_name,
                model_used=model,
                rules_hash=rules_hash,
                prompt_version=PROMPT_VERSION,
                confidence=Confidence(item.confidence),
                citation_grounded=grounded,
                grounding_method=method,
                reasoning=item.reasoning,
            )
        )
        counts[final_eligibility.value] += 1

    inserted_ids = store.record_reportability_assessments(run_id, assessments)

    if adversarial is not None:
        assessment_id_by_finding = {
            a.finding_id: assessment_id
            for a, assessment_id in zip(assessments, inserted_ids, strict=True)
        }
        reviews_to_store = []
        for finding_id, review in review_by_finding_id.items():
            counter = (
                Eligibility(review.counter_eligibility)
                if review.counter_eligibility is not None
                else None
            )
            reviews_to_store.append(
                AdversarialFindingReview(
                    assessment_id=assessment_id_by_finding[finding_id],
                    finding_id=finding_id,
                    reviewer_provider=adversarial_name,
                    reviewer_model=adversarial_model,
                    challenge=ReviewChallenge(review.challenge),
                    prompt_version=PROMPT_VERSION,
                    counter_eligibility=counter,
                    reasoning=review.reasoning,
                )
            )
        store.record_reportability_adversarial_reviews(run_id, reviews_to_store)

    print()
    print(
        f"Assessed {len(assessments)} finding(s): {counts['ELIGIBLE']} ELIGIBLE, "
        f"{counts['NOT_ELIGIBLE']} NOT_ELIGIBLE, {counts['UNCERTAIN']} UNCERTAIN "
        "(final, post-adversarial-review verdict)."
    )
    if disagreements:
        print(
            f"\n⚠ {len(disagreements)} finding(s) had a primary verdict the adversarial "
            "reviewer did NOT confirm — forced to UNCERTAIN rather than trusting either side:"
        )
        for finding_id, primary_eligibility, challenge in disagreements:
            print(
                f"  - finding_id={finding_id}: primary said {primary_eligibility.value}, "
                f"adversarial review was {challenge.value}"
            )
    if ungrounded:
        print(
            f"\n⚠ {len(ungrounded)} citation(s) did NOT verify against the rules text and "
            "are marked UNGROUNDED — treat these verdicts with the same skepticism as an "
            "unsupported claim, not as confirmed:"
        )
        for finding_id, citation in ungrounded:
            print(f"  - finding_id={finding_id}: {citation!r}")
    if not disagreements and not ungrounded:
        print("Every non-empty citation verified against the rules text.")
    print(
        "\nReminder: agreement between two LLMs does not constitute proof that a "
        "vulnerability exists or is in scope. Every verdict here is a triage aid for a human "
        "reviewer, not a substitute for reading the program's own rules."
    )
    return 0
