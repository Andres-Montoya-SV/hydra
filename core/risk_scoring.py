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


@dataclass(frozen=True)
class RiskFactors:
    """The DB-free shape `ControlDB.risk_factors_for_exposure` reduces a
    real exposure down to — everything `classify_exposure_risk` needs,
    nothing it has to look up itself (keeping that function pure and
    trivially unit-testable with fixed fixtures)."""

    severity: str
    domain_verified: bool
    days_open: int
    related_to_critical_asset: bool
    related_critical_asset_reason: str | None = None


@dataclass(frozen=True)
class RiskClassification:
    level: RiskLevel
    reasons: tuple[str, ...]


def _escalate(level: RiskLevel) -> RiskLevel:
    index = _LEVEL_ORDER.index(level)
    return _LEVEL_ORDER[min(index + 1, len(_LEVEL_ORDER) - 1)]


def classify_exposure_risk(factors: RiskFactors) -> RiskClassification:
    """Deterministic: the same `RiskFactors` always produces the same
    `RiskClassification`. Every contributing factor appends its own
    concrete reason — `reasons` is never just the final label restated,
    it is the actual explanation a reviewer can cite verbatim ("alto
    porque: ...", the phase's own required shape)."""
    reasons: list[str] = []
    level = _SEVERITY_BASE_LEVEL.get(factors.severity, RiskLevel.LOW)
    reasons.append(f"base severity is {factors.severity}")

    if factors.domain_verified:
        reasons.append("asset's domain is under confirmed, verified scope")
    else:
        reasons.append(
            "asset's domain is NOT currently under confirmed scope (candidate/unverified)"
        )

    if factors.days_open >= DAYS_OPEN_ESCALATION_THRESHOLD:
        reasons.append(
            f"open for {factors.days_open} day(s) without resolution "
            f"(>= {DAYS_OPEN_ESCALATION_THRESHOLD}-day threshold)"
        )
        level = _escalate(level)

    if factors.related_to_critical_asset:
        reasons.append(
            factors.related_critical_asset_reason
            or "related (Fase 07 graph) to another asset with its own open high/critical exposure"
        )
        level = _escalate(level)

    return RiskClassification(level=level, reasons=tuple(reasons))
