"""Fase 21 (EASM roadmap): deterministic, explainable risk/criticality
classification for one exposure. Combines signals the domain model
already produces — the exposure's own severity, whether its asset's
domain is currently under confirmed (verified) scope vs. only a
candidate/unconfirmed one, how long it has been open, and whether it is
related (Fase 07's relationship graph) to another asset with its own
open high/critical exposure — into a classification whose every level
cites the concrete reasons that produced it.

**No ML, no black-box score, per the roadmap's own explicit invariant**:
a fixed table (severity → base level) plus two deterministic escalation
rules. The same `RiskFactors` input always produces the exact same
`RiskClassification` output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_LEVEL_ORDER: tuple[RiskLevel, ...] = (
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
)

_SEVERITY_BASE_LEVEL: dict[str, RiskLevel] = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
}

# An exposure open this long without resolution escalates one level —
# unattended, aging exposures are a real, additional risk signal beyond
# the fact's own initial severity.
DAYS_OPEN_ESCALATION_THRESHOLD = 30


# Productization Phase 06: an exposure whose detector reported less than
# this confidence is never escalated above its base severity — one weak
# signal must not produce a high-confidence risk claim.
LOW_CONFIDENCE_THRESHOLD = 50

# Declared values that raise business impact.
HIGH_CRITICALITY = frozenset({"critical", "high"})
SENSITIVE_DATA = frozenset({"identity", "payment", "personal_data"})
NON_PRODUCTION = frozenset({"staging", "development", "test"})

FactorSource = Literal["observed", "declared", "unknown"]
FactorEffect = Literal["escalates", "de-escalates", "caps", "none"]


@dataclass(frozen=True)
class BusinessContext:
    """What the organization declared about the asset (Phase 06). Every
    field is optional: an undeclared one is reported as unknown, never
    guessed from the hostname or anything else."""

    environment: str | None = None  # production | staging | development | test
    criticality: str | None = None  # critical | high | medium | low
    data_handled: frozenset[str] = frozenset()  # identity | payment | personal_data
    owner: str | None = None


@dataclass(frozen=True)
class RiskFactors:
    """The DB-free shape `ControlDB.risk_factors_for_exposure` reduces a
    real exposure down to — everything `classify_exposure_risk` needs,
    nothing it has to look up itself (keeping that function pure and
    trivially unit-testable with fixed fixtures).

    Phase 06 fields default to "not known", which reproduces the Fase 21
    classification exactly."""

    severity: str
    domain_verified: bool
    days_open: int
    related_to_critical_asset: bool
    related_critical_asset_reason: str | None = None
    context: BusinessContext | None = None
    confidence_score: int | None = None
    # Where a remote detector observed the exposure, i.e. evidence that it
    # is reachable from the internet as of its last observation.
    detected_location: str | None = None


@dataclass(frozen=True)
class RiskFactor:
    name: str
    value: str
    source: FactorSource
    effect: FactorEffect
    reason: str


@dataclass(frozen=True)
class RiskClassification:
    level: RiskLevel
    reasons: tuple[str, ...]
    # Phase 06: every factor considered, with where it came from and what
    # it did; `unknowns` names the signals Hydra could not assess.
    factors: tuple[RiskFactor, ...] = ()
    unknowns: tuple[str, ...] = ()


def _escalate(level: RiskLevel) -> RiskLevel:
    index = _LEVEL_ORDER.index(level)
    return _LEVEL_ORDER[min(index + 1, len(_LEVEL_ORDER) - 1)]


def _de_escalate(level: RiskLevel) -> RiskLevel:
    return _LEVEL_ORDER[max(_LEVEL_ORDER.index(level) - 1, 0)]


def _core_factors(factors: RiskFactors) -> list[RiskFactor]:
    """The Fase 21 factors, with their original reason text."""
    result = [
        RiskFactor(
            "severity", factors.severity, "observed", "none", f"base severity is {factors.severity}"
        ),
        RiskFactor(
            "confirmed_scope",
            str(factors.domain_verified).lower(),
            "observed",
            "none",
            (
                "asset's domain is under confirmed, verified scope"
                if factors.domain_verified
                else "asset's domain is NOT currently under confirmed scope (candidate/unverified)"
            ),
        ),
    ]
    if factors.days_open >= DAYS_OPEN_ESCALATION_THRESHOLD:
        result.append(
            RiskFactor(
                "exposure_age",
                f"{factors.days_open} days",
                "observed",
                "escalates",
                f"open for {factors.days_open} day(s) without resolution "
                f"(>= {DAYS_OPEN_ESCALATION_THRESHOLD}-day threshold)",
            )
        )
    if factors.related_to_critical_asset:
        result.append(
            RiskFactor(
                "relationship_graph",
                "related to a critical asset",
                "observed",
                "escalates",
                factors.related_critical_asset_reason
                or "related (Fase 07 graph) to another asset with its own open high/critical exposure",
            )
        )
    return result


def _impact_factor(context: BusinessContext) -> RiskFactor | None:
    impact = []
    if context.criticality in HIGH_CRITICALITY:
        impact.append(f"declared business criticality is {context.criticality}")
    sensitive = sorted(context.data_handled & SENSITIVE_DATA)
    if sensitive:
        impact.append(f"declared to handle {', '.join(sensitive)} data")
    if not impact:
        return None
    reason = "; ".join(impact)
    return RiskFactor("business_impact", reason, "declared", "escalates", reason)


def _environment_factor(context: BusinessContext, has_impact: bool) -> RiskFactor | None:
    env = context.environment
    if env is None:
        return None
    if env in NON_PRODUCTION and not has_impact:
        return RiskFactor(
            "environment",
            env,
            "declared",
            "de-escalates",
            f"declared {env} (non-production) environment",
        )
    return RiskFactor("environment", env, "declared", "none", f"declared {env} environment")


def _context_factors(context: BusinessContext | None) -> tuple[list[RiskFactor], list[str]]:
    context = context or BusinessContext()
    impact = _impact_factor(context)
    candidates = [
        impact,
        # A low/medium criticality is cited, but doesn't move the level.
        (
            None
            if context.criticality in HIGH_CRITICALITY or context.criticality is None
            else RiskFactor(
                "business_criticality",
                context.criticality,
                "declared",
                "none",
                f"declared business criticality is {context.criticality}",
            )
        ),
        _environment_factor(context, has_impact=impact is not None),
        (
            None
            if not context.owner
            else RiskFactor("owner", context.owner, "declared", "none", f"owned by {context.owner}")
        ),
    ]
    unknowns = [
        message
        for missing, message in (
            (context.criticality is None, "business criticality: not declared"),
            (
                not context.data_handled,
                "data handled (identity/payment/personal data): not declared",
            ),
            (
                context.environment is None,
                "environment (production/staging/development/test): not declared",
            ),
            (not context.owner, "owner / business unit: not declared"),
        )
        if missing
    ]
    return [f for f in candidates if f is not None], unknowns


def _signal_factors(factors: RiskFactors) -> tuple[list[RiskFactor], list[str]]:
    result: list[RiskFactor] = []
    unknowns = [
        "exploitability: no exploit validation or known-exploited (KEV/EPSS) data source",
    ]
    if factors.confidence_score is None:
        unknowns.append("detector confidence: not reported")
    elif factors.confidence_score < LOW_CONFIDENCE_THRESHOLD:
        result.append(
            RiskFactor(
                "detector_confidence",
                str(factors.confidence_score),
                "observed",
                "caps",
                f"detector confidence {factors.confidence_score} is below "
                f"{LOW_CONFIDENCE_THRESHOLD}: not escalated above base severity",
            )
        )
    if factors.detected_location:
        result.append(
            RiskFactor(
                "internet_reachability",
                "reachable",
                "observed",
                "none",
                f"detected remotely at {factors.detected_location}",
            )
        )
    else:
        unknowns.append("internet reachability: no remote detection location recorded")
    return result, unknowns


def classify_exposure_risk(factors: RiskFactors) -> RiskClassification:
    """Deterministic: the same `RiskFactors` always produces the same
    `RiskClassification`. Every contributing factor appends its own
    concrete reason — `reasons` is never just the final label restated,
    it is the actual explanation a reviewer can cite verbatim ("alto
    porque: ...", the phase's own required shape).

    Phase 06 rule, applied in order:
    1. base level from severity;
    2. +1 per escalating factor (age >= threshold, related critical
       asset, declared business impact) — unless detector confidence is
       below LOW_CONFIDENCE_THRESHOLD, which caps the level at base;
    3. -1 for a declared non-production environment, only when no
       business impact was declared.
    Signals Hydra can't assess are listed in `unknowns`, never guessed."""
    context_factors, context_unknowns = _context_factors(factors.context)
    signal_factors, signal_unknowns = _signal_factors(factors)
    all_factors = [*_core_factors(factors), *context_factors, *signal_factors]

    level = _SEVERITY_BASE_LEVEL.get(factors.severity, RiskLevel.LOW)
    if not any(f.effect == "caps" for f in all_factors):
        for _ in (f for f in all_factors if f.effect == "escalates"):
            level = _escalate(level)
    if any(f.effect == "de-escalates" for f in all_factors):
        level = _de_escalate(level)

    return RiskClassification(
        level=level,
        reasons=tuple(
            f.reason for f in all_factors if f.effect != "none" or f.name in _ALWAYS_CITED
        ),
        factors=tuple(all_factors),
        unknowns=tuple([*context_unknowns, *signal_unknowns]),
    )


# Fase 21 always cited these two even though they don't move the level.
_ALWAYS_CITED = frozenset({"severity", "confirmed_scope"})
