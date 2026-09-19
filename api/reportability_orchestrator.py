"""HTTP-shaped `assess-reportability` (docs/PAID_API_DESIGN.md Part E.1,
Round 3) — reuses the exact same primitives
`core/reportability/cli.py::cmd_assess_reportability` uses
(`create_provider`, `count_input_tokens`, `assess_batch`,
`review_batch`, `validate_exact_batch`, `is_citation_grounded`,
`AssetStore.record_reportability_assessments`), restructured around
Part E.1's estimate-token-then-confirm flow instead of the CLI's
interactive `[y/N]` stdin prompt — there is no terminal to block on over
HTTP, and no session state between two separate requests the way one CLI
process has between printing an estimate and reading the next stdin
line.

**LLM provider credentials are an operator-wide secret, not per-account
config** (docs/PAID_API_DESIGN.md Part B: "Hydra's own Anthropic/OpenAI
cost, not client price") — `_operator_settings()` below loads
`ANTHROPIC_API_KEY`/`OPENAI_API_KEY`/`REPORTABILITY_*` from the real
repo-root `.env`/environment, deliberately SEPARATE from
`api/tenancy.py::account_settings()` (which intentionally does NOT
inherit operator environment config, to keep each account's own
recon-pipeline settings isolated — changing that function's behavior
was out of scope for this round and would have risked regressing
Round 1/2's scan orchestration). Only the per-account `recon.db` path
(via `api/tenancy.py::account_db_path`) is account-specific here; the
LLM keys and provider choice are shared, with a PER-ACCOUNT spend
ceiling enforced on top by `api/subscriptions.py`.

**What "actual cost" means once a call is confirmed**: neither
provider's Protocol (`core.reportability.provider.ReportabilityProvider`)
exposes real post-call billed token usage — the CLI itself only ever
shows a pre-call INPUT estimate and explicitly tells the operator output
cost "is not knowable in advance." This module therefore debits the
account's monthly ceiling by the same pre-call input-token estimate
shown at estimate time, not a true post-call billed figure — a
documented, conservative approximation (output tokens are real
additional spend this ledger does not capture), not a silently-assumed
"exact" number.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from config.settings import Settings
from core.llm.client import estimated_cost_usd
from core.reportability.batch import validate_exact_batch
from core.reportability.cli import provider_credentials
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

if TYPE_CHECKING:
    from core.reportability.provider import ReportabilityProvider
    from core.reportability.schema import AdversarialFindingChallenge

_REPO_ROOT = Path(__file__).resolve().parent.parent
# Mirrors core.reportability.cli's own private constants of the same
# name/value — neither is shared production logic (one's an
# estimate-only overhead figure, the other a fixed snapshot filename), so
# a small, explicit duplication here is clearer than reaching into that
# module's underscore-prefixed internals.
_ADVERSARIAL_OVERHEAD_TOKENS_PER_FINDING = 150
_PROGRAM_RULES_ARTIFACT_NAME = "program_rules_snapshot.txt"


class ReportabilityOrchestratorError(Exception):
    """Any caller-facing failure — the router turns this into the right
    HTTP status; the message is always safe to return verbatim."""


def _operator_settings() -> Settings:
    env_file = _REPO_ROOT / ".env"
    return Settings.from_env(
        env_file=env_file if env_file.exists() else None, project_root=_REPO_ROOT
    )


def _resolve_provider_or_raise(settings: Settings, provider_name: str) -> tuple[str, str]:
    if provider_name not in SUPPORTED_PROVIDERS:
        raise ReportabilityOrchestratorError(
            f"provider {provider_name!r} is not supported — must be one of {SUPPORTED_PROVIDERS}."
        )
    api_key, model = provider_credentials(settings, provider_name)
    if not api_key:
        raise ReportabilityOrchestratorError(
            f"This deployment has no API key configured for provider {provider_name!r}."
        )
    return api_key, model


@dataclass(frozen=True)
class ReportabilityEstimate:
    findings_count: int
    provider: str
    model: str
    adversarial_provider: str | None
    degraded_from_adversarial: bool
    input_tokens: int
    estimated_cost_usd: float
    rules_text: str
    severity: str | None
    host: str | None


async def compute_estimate(
    *,
    db_path: Path,
    run_id: str,
    rules_text: str,
    provider_name: str,
    adversarial_provider_name: str | None,
    degraded_from_adversarial: bool,
    severity: str | None,
    host: str | None,
    limit: int,
) -> ReportabilityEstimate:
    if not rules_text.strip():
        raise ReportabilityOrchestratorError("program_rules_text must not be empty.")

    settings = _operator_settings()
    api_key, model = _resolve_provider_or_raise(settings, provider_name)

    store = AssetStore(db_path)
    severities = [s.strip().lower() for s in severity.split(",") if s.strip()] if severity else None
    findings = store.get_findings(run_id, severity=severities, host=host)
    if not findings:
        raise ReportabilityOrchestratorError("No findings match these filters. Nothing to assess.")
    if len(findings) > limit:
        raise ReportabilityOrchestratorError(
            f"{len(findings)} findings match these filters, exceeding this deployment's "
            f"per-batch limit of {limit}. Narrow with severity/host filters."
        )

    try:
        primary: ReportabilityProvider = await asyncio.to_thread(
            create_provider, provider_name, api_key=api_key, model=model
        )
    except (ReportabilityAPIError, ImportError) as exc:
        raise ReportabilityOrchestratorError(
            f"{exc}. This deployment is missing the optional reportability dependencies."
        ) from exc

    try:
        input_tokens = await asyncio.to_thread(primary.count_input_tokens, rules_text, findings)
    except ReportabilityAPIError as exc:
        raise ReportabilityOrchestratorError(f"Error estimating cost: {exc}") from exc

    total_tokens = input_tokens
    if adversarial_provider_name is not None:
        total_tokens += _ADVERSARIAL_OVERHEAD_TOKENS_PER_FINDING * len(findings)

    cost = estimated_cost_usd(model, total_tokens)
    if cost is None:
        raise ReportabilityOrchestratorError(
            f"No published price is on file for model {model!r} — cannot produce a cost "
            "estimate for this provider/model."
        )

    return ReportabilityEstimate(
        findings_count=len(findings),
        provider=provider_name,
        model=model,
        adversarial_provider=adversarial_provider_name,
        degraded_from_adversarial=degraded_from_adversarial,
        input_tokens=total_tokens,
        estimated_cost_usd=cost,
        rules_text=rules_text,
        severity=severity,
        host=host,
    )


@dataclass(frozen=True)
class ReportabilityOutcome:
    assessed_count: int
    eligible_count: int
    not_eligible_count: int
    uncertain_count: int
    cross_validated: bool


async def run_assessment(
    *,
    db_path: Path,
    output_dir: Path,
    run_id: str,
    rules_text: str,
    provider_name: str,
    adversarial_provider_name: str | None,
    severity: str | None,
    host: str | None,
) -> ReportabilityOutcome:
    """Re-fetches CURRENT findings for the same filters the estimate was
    computed against (never trusts a finding list embedded in the
    estimate itself — findings could only have changed by being
    re-collected, which never happens mid-assessment, but re-deriving
    from the live store is the same "never trust a stale snapshot"
    discipline the rest of this project already follows) and performs
    the exact same primary+adversarial call sequence the CLI does."""
    settings = _operator_settings()
    api_key, model = _resolve_provider_or_raise(settings, provider_name)

    store = AssetStore(db_path)
    severities = [s.strip().lower() for s in severity.split(",") if s.strip()] if severity else None
    findings = store.get_findings(run_id, severity=severities, host=host)
    if not findings:
        raise ReportabilityOrchestratorError("No findings match these filters anymore.")
    valid_finding_ids = [int(f["id"]) for f in findings]  # type: ignore[call-overload]

    try:
        primary: ReportabilityProvider = await asyncio.to_thread(
            create_provider, provider_name, api_key=api_key, model=model
        )
        adversarial: ReportabilityProvider | None = None
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
    except (ReportabilityAPIError, ImportError) as exc:
        raise ReportabilityOrchestratorError(str(exc)) from exc

    try:
        primary_result = await asyncio.to_thread(primary.assess_batch, rules_text, findings)
    except ReportabilityAPIError as exc:
        raise ReportabilityOrchestratorError(str(exc)) from exc
    try:
        validate_exact_batch(valid_finding_ids, primary_result.assessments)
    except BatchValidationError as exc:
        raise ReportabilityOrchestratorError(str(exc)) from exc

    review_by_finding_id: dict[int, AdversarialFindingChallenge] = {}
    if adversarial is not None:
        try:
            review_result = await asyncio.to_thread(
                adversarial.review_batch, rules_text, findings, primary_result
            )
        except ReportabilityAPIError as exc:
            raise ReportabilityOrchestratorError(str(exc)) from exc
        try:
            validate_exact_batch(valid_finding_ids, review_result.reviews)
        except BatchValidationError as exc:
            raise ReportabilityOrchestratorError(str(exc)) from exc
        review_by_finding_id = {r.finding_id: r for r in review_result.reviews}

    artifact_path = output_dir / _PROGRAM_RULES_ARTIFACT_NAME
    artifact_path.write_text(rules_text, encoding="utf-8")
    rules_hash = hashlib.sha256(rules_text.encode("utf-8")).hexdigest()

    assessments: list[ReportabilityAssessment] = []
    counts = {"ELIGIBLE": 0, "NOT_ELIGIBLE": 0, "UNCERTAIN": 0}
    for item in primary_result.assessments:
        citation = item.rule_citation.strip()
        grounded: bool | None = None
        method = "none"
        if citation:
            grounded, method = is_citation_grounded(
                citation, _PROGRAM_RULES_ARTIFACT_NAME, output_dir
            )

        primary_eligibility = Eligibility(item.eligibility)
        final_eligibility = primary_eligibility
        review = review_by_finding_id.get(item.finding_id)
        if review is not None:
            challenge = ReviewChallenge(review.challenge)
            final_eligibility = combine_eligibility(primary_eligibility, challenge)

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

    inserted_ids = await asyncio.to_thread(
        store.record_reportability_assessments, run_id, assessments
    )

    if adversarial is not None and adversarial_provider_name is not None:
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
                    reviewer_provider=adversarial_provider_name,
                    reviewer_model=adversarial_model,
                    challenge=ReviewChallenge(review.challenge),
                    prompt_version=PROMPT_VERSION,
                    counter_eligibility=counter,
                    reasoning=review.reasoning,
                )
            )
        await asyncio.to_thread(
            store.record_reportability_adversarial_reviews, run_id, reviews_to_store
        )

    return ReportabilityOutcome(
        assessed_count=len(assessments),
        eligible_count=counts["ELIGIBLE"],
        not_eligible_count=counts["NOT_ELIGIBLE"],
        uncertain_count=counts["UNCERTAIN"],
        cross_validated=adversarial is not None,
    )
