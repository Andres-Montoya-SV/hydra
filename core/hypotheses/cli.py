"""`python app.py suggest-hypotheses` — the standalone command (design
Part D). Never invoked by `python app.py run`; the operator always
triggers this explicitly, always sees a real cost estimate first, and
always confirms before any API credits are spent. Mirrors
`core.reportability.cli.cmd_assess_reportability`'s exact operational
shape (cost estimate, fail-closed confirmation, batch-limit refusal),
adapted for a task with no fixed per-item response shape: an empty
hypothesis list is a valid, honest answer, not something to validate a
batch count against.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from core.hypotheses.batch import find_reasoning_review_batch_defects
from core.hypotheses.errors import HypothesisAPIError, HypothesisBatchLimitError
from core.hypotheses.evidence import gather_run_evidence
from core.hypotheses.grounding import (
    check_entity_citations,
    check_relationship_citations,
    compute_calibration_status,
    compute_grounding_status,
)
from core.hypotheses.limits import validate_hypothesis_batch_limits
from core.hypotheses.model import LlmHypothesis, ReasoningChallenge, ReasoningReviewStatus
from core.hypotheses.prompt import (
    PROMPT_VERSION,
    build_adversarial_user_message,
    build_user_message,
)
from core.hypotheses.provider import SUPPORTED_PROVIDERS, create_provider
from core.intel.cli import default_db
from core.llm.client import cost_line as _cost_line
from core.store import AssetStore
from utils.validators import sanitize_run_id

if TYPE_CHECKING:
    from config.settings import Settings
    from core.hypotheses.provider import HypothesisProvider

# Reasoning-soundness review's input includes the full evidence set again
# (like the primary call) PLUS every proposed hypothesis appended. A
# fixed per-hypothesis token overhead used only to produce a pre-spend
# ESTIMATE for the review call before it has actually been made (the real
# primary output size isn't known until after the primary call) — never
# used for anything except that estimate.
_REVIEW_OVERHEAD_TOKENS_PER_HYPOTHESIS = 150


def _provider_env_var(provider_name: str) -> str:
    return "ANTHROPIC_API_KEY" if provider_name == "anthropic" else "OPENAI_API_KEY"


def _provider_credentials(settings: Settings, provider_name: str) -> tuple[str | None, str]:
    if provider_name == "anthropic":
        return settings.anthropic_api_key, settings.anthropic_model
    return settings.openai_api_key, settings.openai_model


def cmd_suggest_hypotheses(
    settings: Settings,
    run_id: str,
    *,
    limit: int | None = None,
    yes: bool = False,
    provider: str | None = None,
    adversarial_provider: str | None = None,
) -> int:
    sanitize_run_id(run_id)

    provider_name = provider or settings.hypothesis_provider
    adversarial_name = adversarial_provider or settings.hypothesis_adversarial_provider

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
                'Using the same provider to "review" itself shares the same failure modes '
                "(the same training data, the same blind spots) and defeats the point of "
                "reasoning-soundness review.",
                file=sys.stderr,
            )
            return 1

    api_key, model = _provider_credentials(settings, provider_name)
    if not api_key:
        print(
            f"Error: {_provider_env_var(provider_name)} is not configured. This command is "
            "opt-in and does nothing without it — see docs/HYPOTHESIS_ENGINE_DESIGN.md and "
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

    store = AssetStore(db_path)

    effective_limit = (
        limit if limit is not None else settings.hypothesis_max_relationships_per_batch
    )
    max_relationships = effective_limit + 1
    evidence = gather_run_evidence(store, run_id, max_relationships=max_relationships)
    if len(evidence.relationships) > effective_limit:
        print(
            f"Error: this run has more than {effective_limit} relationships, which exceeds "
            "the configured limit (HYPOTHESIS_MAX_RELATIONSHIPS_PER_BATCH, or --limit). "
            "Refusing to silently consider only some of them — pass --limit to raise the "
            "ceiling explicitly for this run.",
            file=sys.stderr,
        )
        return 1
    if evidence.is_empty:
        print(f"No relationships, entities, or findings for run {run_id!r}. Nothing to do.")
        return 0

    # Deferred, not module-level: core.hypotheses.anthropic_client/
    # openai_client -> schema.py requires pydantic, and each client module
    # requires its own SDK. Neither is a hard dependency of Hydra as a
    # whole (requirements-optional.txt only) — importing core.hypotheses.cli
    # itself must never require them.
    try:
        primary: HypothesisProvider = create_provider(provider_name, api_key=api_key, model=model)
        adversarial: HypothesisProvider | None = None
        if adversarial_name is not None and adversarial_api_key is not None:
            adversarial = create_provider(
                adversarial_name, api_key=adversarial_api_key, model=adversarial_model
            )
    except (HypothesisAPIError, ImportError) as exc:
        print(
            f"Error: {exc}. This command requires the optional hypothesis-engine dependencies "
            "— install them with `pip install -r requirements-optional.txt`.",
            file=sys.stderr,
        )
        return 1

    print(
        f"{len(evidence.relationships)} relationship(s), {len(evidence.entities)} entity(ies), "
        f"{len(evidence.findings)} finding(s) selected for run {run_id!r}."
    )
    print(f"Primary provider: {provider_name}/{model}")
    if adversarial is not None:
        print(f"Adversarial (reasoning-review) provider: {adversarial_name}/{adversarial_model}")

    user_message = build_user_message(evidence.relationships, evidence.entities, evidence.findings)

    try:
        input_tokens = primary.count_input_tokens(user_message)
    except HypothesisAPIError as exc:
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
        review_estimate = input_tokens + _REVIEW_OVERHEAD_TOKENS_PER_HYPOTHESIS * max(
            1, len(evidence.relationships)
        )
        print(
            "Estimated reasoning-review input (approximate — the real primary output size "
            "isn't known until after the primary call): "
            + _cost_line(adversarial_name, adversarial_model, review_estimate, approximate=True)
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
        answer = input("Proceed with hypothesis generation? [y/N]: ")
        if answer.strip().lower() not in {"y", "yes"}:
            print("Declined — no API call made.")
            return 1

    try:
        primary_result = primary.propose_hypotheses(user_message)
    except HypothesisAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        validate_hypothesis_batch_limits(primary_result)
    except HypothesisBatchLimitError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not primary_result.hypotheses:
        print(
            "\nThe model returned no hypotheses — the evidence didn't support any it judged "
            "worth proposing. This is a valid, honest outcome, not a failure."
        )
        return 0

    review_by_index: dict[int, ReasoningChallenge] = {}
    review_reasoning_by_index: dict[int, str] = {}
    review_status = ReasoningReviewStatus.NOT_REQUESTED
    if adversarial is not None:
        review_message = build_adversarial_user_message(
            [p.model_dump(mode="json") for p in primary_result.hypotheses],
            evidence.relationships,
            evidence.entities,
        )
        try:
            review_result = adversarial.review_hypotheses(review_message)
        except HypothesisAPIError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        defects = find_reasoning_review_batch_defects(
            len(primary_result.hypotheses), review_result.reviews
        )
        if defects:
            review_status = ReasoningReviewStatus.INVALID
            print(
                "\n⚠ Reasoning-soundness review returned an invalid batch: "
                + "; ".join(defects)
                + ". Every hypothesis in this generation will still be persisted (they are "
                "independently grounded/calibrated and already real API spend), but none "
                "of them can be trusted based on this review — a provider that cannot "
                "reliably echo back which hypothesis it reviewed has given no reason to "
                "trust that any single verdict corresponds to the hypothesis it's attached "
                "to.",
                file=sys.stderr,
            )
        else:
            review_status = ReasoningReviewStatus.COMPLETE
            for r in review_result.reviews:
                review_by_index[r.hypothesis_index] = ReasoningChallenge(r.challenge)
                review_reasoning_by_index[r.hypothesis_index] = r.reasoning

    hypotheses: list[LlmHypothesis] = []
    for index, proposal in enumerate(primary_result.hypotheses):
        relationship_citations = check_relationship_citations(
            proposal.cited_relationships, evidence
        )
        entity_citations = check_entity_citations(proposal.cited_entity_ids, evidence)
        all_citations = relationship_citations + entity_citations
        grounding_status = compute_grounding_status(all_citations)
        calibration_status = compute_calibration_status(all_citations)
        challenge = (
            review_by_index.get(index) if review_status is ReasoningReviewStatus.COMPLETE else None
        )
        hypotheses.append(
            LlmHypothesis(
                statement=proposal.statement,
                provider=provider_name,
                model_used=model,
                prompt_version=PROMPT_VERSION,
                grounding_status=grounding_status,
                calibration_status=calibration_status,
                evidence=all_citations,
                confidence=proposal.confidence,
                suggested_next_step=proposal.suggested_next_step,
                reasoning_review_challenge=challenge,
                reasoning_review_status=review_status,
                reasoning_review_provider=(
                    adversarial_name
                    if review_status is not ReasoningReviewStatus.NOT_REQUESTED
                    else None
                ),
                reasoning_review_model=(
                    adversarial_model
                    if review_status is not ReasoningReviewStatus.NOT_REQUESTED
                    else None
                ),
            )
        )

    store.record_llm_hypotheses(run_id, hypotheses)

    print(f"\n{len(hypotheses)} hypothesis(es) generated for run {run_id!r}:\n")
    untrustworthy_count = 0
    for index, hypothesis in enumerate(hypotheses):
        marker = "✓" if hypothesis.trustworthy else "⚠"
        if not hypothesis.trustworthy:
            untrustworthy_count += 1
        print(
            f"{marker} [{hypothesis.confidence.value if hypothesis.confidence else '?'}] "
            f"{hypothesis.statement}"
        )
        print(
            f"    grounding={hypothesis.grounding_status.value} "
            f"calibration={hypothesis.calibration_status.value}"
            + (
                f" reasoning_review={hypothesis.reasoning_review_challenge.value}"
                if hypothesis.reasoning_review_challenge is not None
                else ""
            )
            + (
                " reasoning_review=INVALID_BATCH"
                if hypothesis.reasoning_review_status is ReasoningReviewStatus.INVALID
                else ""
            )
        )
        if hypothesis.suggested_next_step:
            print(f"    next step: {hypothesis.suggested_next_step}")
        if index in review_reasoning_by_index:
            print(f"    review reasoning: {review_reasoning_by_index[index]}")
        print()

    if untrustworthy_count:
        print(
            f"⚠ {untrustworthy_count} of {len(hypotheses)} hypothesis(es) did NOT pass every "
            "check (ungrounded citation, overstated evidence strength, an invalid/incomplete "
            "reasoning-review batch, or a reasoning review that found the conclusion "
            "overreaches) — treat these with the same skepticism as an unverified claim, "
            "never as equivalent to a fully-checked one."
        )
    print(
        "\nReminder: a hypothesis is an investigation lead for a human analyst, never a "
        "conclusion, an authorization for new collection, or a report finding."
    )
    return 0
