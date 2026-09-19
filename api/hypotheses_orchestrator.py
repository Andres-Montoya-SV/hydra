"""HTTP-shaped `suggest-hypotheses` (docs/PAID_API_DESIGN.md Part E.1,
Round 3) — the exact same estimate-then-confirm restructuring
`api/reportability_orchestrator.py` applies to
`core/reportability/cli.py`, applied here to
`core/hypotheses/cli.py::cmd_suggest_hypotheses`'s underlying primitives
(`gather_run_evidence`, `build_user_message`, `create_provider`,
`propose_hypotheses`, `review_hypotheses`, the grounding/calibration
citation checks, `AssetStore.record_llm_hypotheses`). See that sibling
module's docstring for the two shared design notes that apply
identically here: operator-wide LLM credentials via `_operator_settings`
(deliberately separate from per-account pipeline settings), and "actual
cost" meaning the pre-call input-token estimate, not a true post-call
billed figure neither provider's Protocol exposes.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from config.settings import Settings
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
from core.hypotheses.prompt import PROMPT_VERSION as HYPOTHESES_PROMPT_VERSION
from core.hypotheses.prompt import build_adversarial_user_message, build_user_message
from core.hypotheses.provider import SUPPORTED_PROVIDERS, create_provider
from core.llm.client import estimated_cost_usd
from core.store import AssetStore

if TYPE_CHECKING:
    from core.hypotheses.provider import HypothesisProvider

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REVIEW_OVERHEAD_TOKENS_PER_HYPOTHESIS = 150


class HypothesesOrchestratorError(Exception):
    pass


def _operator_settings() -> Settings:
    env_file = _REPO_ROOT / ".env"
    return Settings.from_env(
        env_file=env_file if env_file.exists() else None, project_root=_REPO_ROOT
    )


def _provider_env_var(provider_name: str) -> str:
    return "ANTHROPIC_API_KEY" if provider_name == "anthropic" else "OPENAI_API_KEY"


def _provider_credentials(settings: Settings, provider_name: str) -> tuple[str | None, str]:
    if provider_name == "anthropic":
        return settings.anthropic_api_key, settings.anthropic_model
    return settings.openai_api_key, settings.openai_model


def _resolve_provider_or_raise(settings: Settings, provider_name: str) -> tuple[str, str]:
    if provider_name not in SUPPORTED_PROVIDERS:
        raise HypothesesOrchestratorError(
            f"provider {provider_name!r} is not supported — must be one of {SUPPORTED_PROVIDERS}."
        )
    api_key, model = _provider_credentials(settings, provider_name)
    if not api_key:
        raise HypothesesOrchestratorError(
            f"This deployment has no {_provider_env_var(provider_name)} configured."
        )
    return api_key, model


@dataclass(frozen=True)
class HypothesesEstimate:
    relationships_count: int
    provider: str
    model: str
    adversarial_provider: str | None
    degraded_from_adversarial: bool
    input_tokens: int
    estimated_cost_usd: float


async def compute_estimate(
    *,
    db_path: Path,
    run_id: str,
    provider_name: str,
    adversarial_provider_name: str | None,
    degraded_from_adversarial: bool,
    limit: int,
) -> HypothesesEstimate:
    settings = _operator_settings()
    api_key, model = _resolve_provider_or_raise(settings, provider_name)

    store = AssetStore(db_path)
    evidence = await asyncio.to_thread(
        gather_run_evidence, store, run_id, max_relationships=limit + 1
    )
    if len(evidence.relationships) > limit:
        raise HypothesesOrchestratorError(
            f"This run has more than {limit} relationships, exceeding this deployment's "
            "per-batch limit."
        )
    if evidence.is_empty:
        raise HypothesesOrchestratorError(
            "No relationships, entities, or findings for this run. Nothing to do."
        )

    user_message = build_user_message(evidence.relationships, evidence.entities, evidence.findings)

    try:
        primary: HypothesisProvider = await asyncio.to_thread(
            create_provider, provider_name, api_key=api_key, model=model
        )
    except (HypothesisAPIError, ImportError) as exc:
        raise HypothesesOrchestratorError(
            f"{exc}. This deployment is missing the optional hypothesis-engine dependencies."
        ) from exc

    try:
        input_tokens = await asyncio.to_thread(primary.count_input_tokens, user_message)
    except HypothesisAPIError as exc:
        raise HypothesesOrchestratorError(f"Error estimating cost: {exc}") from exc

    total_tokens = input_tokens
    if adversarial_provider_name is not None:
        total_tokens += _REVIEW_OVERHEAD_TOKENS_PER_HYPOTHESIS * max(1, len(evidence.relationships))

    cost = estimated_cost_usd(model, total_tokens)
    if cost is None:
        raise HypothesesOrchestratorError(f"No published price is on file for model {model!r}.")

    return HypothesesEstimate(
        relationships_count=len(evidence.relationships),
        provider=provider_name,
        model=model,
        adversarial_provider=adversarial_provider_name,
        degraded_from_adversarial=degraded_from_adversarial,
        input_tokens=total_tokens,
        estimated_cost_usd=cost,
    )


@dataclass(frozen=True)
class HypothesesOutcome:
    hypotheses_count: int
    trustworthy_count: int


async def run_assessment(
    *,
    db_path: Path,
    run_id: str,
    provider_name: str,
    adversarial_provider_name: str | None,
    limit: int,
) -> HypothesesOutcome:
    settings = _operator_settings()
    api_key, model = _resolve_provider_or_raise(settings, provider_name)

    store = AssetStore(db_path)
    evidence = await asyncio.to_thread(
        gather_run_evidence, store, run_id, max_relationships=limit + 1
    )
    if evidence.is_empty:
        raise HypothesesOrchestratorError("No relationships, entities, or findings anymore.")

    try:
        primary: HypothesisProvider = await asyncio.to_thread(
            create_provider, provider_name, api_key=api_key, model=model
        )
        adversarial: HypothesisProvider | None = None
        adversarial_model = ""
        if adversarial_provider_name is not None:
            adversarial_api_key, adversarial_model = _resolve_provider_or_raise(
                settings, adversarial_provider_name
            )
            adversarial = await asyncio.to_thread(
                create_provider,
                adversarial_provider_name,
                api_key=adversarial_api_key,
                model=adversarial_model,
            )
    except (HypothesisAPIError, ImportError) as exc:
        raise HypothesesOrchestratorError(str(exc)) from exc

    user_message = build_user_message(evidence.relationships, evidence.entities, evidence.findings)
    try:
        primary_result = await asyncio.to_thread(primary.propose_hypotheses, user_message)
    except HypothesisAPIError as exc:
        raise HypothesesOrchestratorError(str(exc)) from exc

    try:
        validate_hypothesis_batch_limits(primary_result)
    except HypothesisBatchLimitError as exc:
        raise HypothesesOrchestratorError(str(exc)) from exc

    if not primary_result.hypotheses:
        return HypothesesOutcome(hypotheses_count=0, trustworthy_count=0)

    review_by_index: dict[int, ReasoningChallenge] = {}
    review_status = ReasoningReviewStatus.NOT_REQUESTED
    if adversarial is not None:
        review_message = build_adversarial_user_message(
            [p.model_dump(mode="json") for p in primary_result.hypotheses],
            evidence.relationships,
            evidence.entities,
        )
        try:
            review_result = await asyncio.to_thread(adversarial.review_hypotheses, review_message)
        except HypothesisAPIError as exc:
            raise HypothesesOrchestratorError(str(exc)) from exc

        defects = find_reasoning_review_batch_defects(
            len(primary_result.hypotheses), review_result.reviews
        )
        if defects:
            review_status = ReasoningReviewStatus.INVALID
        else:
            review_status = ReasoningReviewStatus.COMPLETE
            for r in review_result.reviews:
                review_by_index[r.hypothesis_index] = ReasoningChallenge(r.challenge)

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
                prompt_version=HYPOTHESES_PROMPT_VERSION,
                grounding_status=grounding_status,
                calibration_status=calibration_status,
                evidence=all_citations,
                confidence=proposal.confidence,
                suggested_next_step=proposal.suggested_next_step,
                reasoning_review_challenge=challenge,
                reasoning_review_status=review_status,
                reasoning_review_provider=(
                    adversarial_provider_name
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

    await asyncio.to_thread(store.record_llm_hypotheses, run_id, hypotheses)

    trustworthy_count = sum(1 for h in hypotheses if h.trustworthy)
    return HypothesesOutcome(hypotheses_count=len(hypotheses), trustworthy_count=trustworthy_count)
