"""The four account tiers (docs/PAID_API_DESIGN.md Part B, Round 3) —
Free/Medium/Pro/Ultra. This table **supersedes** Part B's original
Starter/Pro/Agency draft (three tiers, different numbers) the same way
Round 2 superseded Part A.2/A.3: the task that commissioned this round
gave an exact, different table, and that instruction — more specific and
more recent than the original design draft — is what's implemented here.
See docs/PAID_API_DESIGN.md's "Round 3 implemented" section for the full
reasoning behind every value below, including the ones the task left as
"pick something reasonable and document it" (Pro's LLM ceilings, Ultra's
default retention, the exact "fair use" scan ceiling).

**The Free tier's $0 LLM ceiling is a structural impossibility, not a
low limit**: `TierLimits.reportability` and `.hypotheses` are `None` for
Free — there is no ceiling to check because the feature is not
reachable at all. `api/routers/reportability.py` and
`api/routers/hypotheses.py` both gate on `tier_limits.reportability
is None` / `.hypotheses is None` as the very FIRST thing they do, before
even resolving the scan_id, and respond `404` — identical to a route
that genuinely does not exist — never `403` (which would confirm the
feature exists but is merely forbidden). A tier is data, never a code
branch that "also" needs to reject Free requests after doing other work
first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Tier = Literal["free", "medium", "pro", "ultra"]
AdversarialPolicy = Literal["unavailable", "auto_degrade", "available"]


@dataclass(frozen=True)
class LlmFeatureLimits:
    """`None` on `TierLimits.reportability`/`.hypotheses` means the
    feature does not exist for that tier at all (Free) — this type only
    describes a tier that DOES have the feature, so every field here is
    a real, enforced ceiling, never a placeholder for "unlimited"."""

    monthly_ceiling_usd: float
    adversarial: AdversarialPolicy


@dataclass(frozen=True)
class TierLimits:
    tier: Tier
    scans_per_month: int
    max_concurrent_verified_domains: int | None  # None = unlimited
    reportability: LlmFeatureLimits | None  # None = feature does not exist for this tier
    hypotheses: LlmFeatureLimits | None
    report_formats: frozenset[str]
    report_languages: frozenset[str]
    white_label_report: bool
    retention_days: int | None  # None = configurable per account (Ultra)
    priority_queue: bool


TIERS: dict[Tier, TierLimits] = {
    "free": TierLimits(
        tier="free",
        scans_per_month=1,
        max_concurrent_verified_domains=1,
        reportability=None,
        hypotheses=None,
        report_formats=frozenset({"markdown"}),
        report_languages=frozenset({"es"}),
        white_label_report=False,
        retention_days=7,
        priority_queue=False,
    ),
    "medium": TierLimits(
        tier="medium",
        scans_per_month=10,
        max_concurrent_verified_domains=3,
        # "Sí, un solo proveedor" — the task's table gives Medium
        # reportability but explicitly withholds cross-validation; see
        # `AdversarialPolicy` and api/routers/reportability.py for how
        # `auto_degrade` is enforced (never silently, see the response's
        # own `degraded_from_adversarial` field).
        reportability=LlmFeatureLimits(monthly_ceiling_usd=10.0, adversarial="auto_degrade"),
        hypotheses=None,
        report_formats=frozenset({"markdown", "docx"}),
        report_languages=frozenset({"es", "en"}),
        white_label_report=False,
        retention_days=90,
        priority_queue=False,
    ),
    "pro": TierLimits(
        tier="pro",
        scans_per_month=50,
        max_concurrent_verified_domains=10,
        # The task's table gives Pro cross-validation but no explicit $
        # figure (only Medium's $10 and Ultra's $100 examples are given).
        # Decision: $40/mo — closer to Medium than to Ultra, since Pro's
        # audience is a single active tester/small team (similar usage
        # shape to Medium) who additionally wants the adversarial
        # cross-check, not Ultra's agency-scale volume.
        reportability=LlmFeatureLimits(monthly_ceiling_usd=40.0, adversarial="available"),
        # "Sí, con su propio tope de gasto" — no figure given either;
        # same reasoning, and hypotheses generation runs on a smaller
        # per-call input (relationships/entities, not full findings
        # batches) than reportability, so a lower ceiling is still
        # proportionate.
        hypotheses=LlmFeatureLimits(monthly_ceiling_usd=25.0, adversarial="available"),
        report_formats=frozenset({"markdown", "docx"}),
        report_languages=frozenset({"es", "en"}),
        white_label_report=False,
        retention_days=365,
        priority_queue=True,
    ),
    "ultra": TierLimits(
        tier="ultra",
        scans_per_month=500,  # task's own suggested "fair use" ceiling
        max_concurrent_verified_domains=None,
        reportability=LlmFeatureLimits(monthly_ceiling_usd=100.0, adversarial="available"),
        # Ultra's hypotheses ceiling: no figure given; scaled from Pro's
        # $25 by the same ~2.5x the table uses between Pro's and Ultra's
        # reportability ceilings ($40 -> $100).
        hypotheses=LlmFeatureLimits(monthly_ceiling_usd=60.0, adversarial="available"),
        report_formats=frozenset({"markdown", "docx"}),
        report_languages=frozenset({"es", "en"}),
        white_label_report=True,
        # "Configurable por cuenta" — None here means "no fixed tier
        # default"; api/subscriptions.py resolves the EFFECTIVE retention
        # for an Ultra account from `subscriptions.retention_days_override`
        # (set via the admin reconciliation endpoint), falling back to
        # DEFAULT_ULTRA_RETENTION_DAYS below if the operator never set one
        # — an Ultra account is never left with an undefined retention
        # window just because nobody configured it yet.
        retention_days=None,
        priority_queue=True,
    ),
}

DEFAULT_ULTRA_RETENTION_DAYS = 730

# Scan-queue priority, stated honestly: Round 1/2's scan execution is a
# plain `asyncio.create_task` per scan (api/scan_orchestrator.py) — there
# is no real job queue to reorder (already a documented Round 1
# limitation). `TierLimits.priority_queue` is recorded and surfaced via
# `GET /account/subscription` so the field exists end-to-end and a real
# queue landing later has something to read, but it is currently a NO-OP:
# every scan starts executing the moment it passes the quota gate,
# regardless of tier. Documented here rather than silently implying a
# real scheduler exists.


def retention_days_for(limits: TierLimits, *, retention_days_override: int | None) -> int:
    if limits.retention_days is not None:
        return limits.retention_days
    return (
        retention_days_override
        if retention_days_override is not None
        else DEFAULT_ULTRA_RETENTION_DAYS
    )


def tier_limits(tier: str) -> TierLimits:
    try:
        return TIERS[tier]  # type: ignore[index]
    except KeyError as exc:
        raise ValueError(f"Unknown tier {tier!r} — must be one of {sorted(TIERS)}") from exc


def tiers_supporting(*, reportability: bool = False, hypotheses: bool = False) -> list[Tier]:
    """Used to build "upgrade to X" messages — e.g. a Free account asking
    about `assess-reportability` should be told which tiers actually have
    it, not just that it doesn't."""
    result = []
    for tier, limits in TIERS.items():
        if reportability and limits.reportability is None:
            continue
        if hypotheses and limits.hypotheses is None:
            continue
        result.append(tier)
    return result
