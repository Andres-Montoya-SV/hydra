"""One reusable explanation shape for every product assertion (Roadmap
Phase 03): why an asset, an exposure or a relationship exists, where and
when it was observed, and how confident Hydra is — the same fields for all
three, so any client can render them generically.

Product-facing: evidence is attributed to the Hydra capability that
produced it (`core/capabilities.py`), never to the underlying tool. Raw
tool names and records live only in the analyst provenance endpoint.

Evidence lists are bounded (`EVIDENCE_LIMIT`, newest first) with the full
count alongside; the per-subject evidence endpoints page through the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from api.control_db import ControlDB
from api.domain_verification import domain_is_covered

SubjectType = Literal["asset", "exposure", "relationship"]

EVIDENCE_LIMIT = 20


@dataclass(frozen=True)
class ExplanationEvidence:
    capability: str
    observed_at: str
    run_id: str | None
    summary: str


@dataclass(frozen=True)
class Explanation:
    subject_type: SubjectType
    subject_id: str
    claim: str
    status: str
    confidence: str | None
    first_observed_at: str
    last_observed_at: str
    reasons: tuple[str, ...]
    evidence: tuple[ExplanationEvidence, ...]
    evidence_total: int


def capability_of(source: str) -> str:
    """The product capability behind a raw provider/collector name;
    `uncategorized` for anything that isn't a known provider."""
    from api.collection_capabilities import provider_catalog
    from core.capabilities import Capability

    info = provider_catalog().get(source)
    return info.capability if info else Capability.UNCATEGORIZED.value


def _newest_first(items: list[ExplanationEvidence]) -> tuple[ExplanationEvidence, ...]:
    return tuple(sorted(items, key=lambda e: e.observed_at, reverse=True))


def _newest_page(total: int) -> dict[str, int]:
    """`limit`/`offset` selecting the newest `EVIDENCE_LIMIT` rows of an
    oldest-first listing of `total` rows."""
    return {"limit": EVIDENCE_LIMIT, "offset": max(0, total - EVIDENCE_LIMIT)}


def explain_asset(db: ControlDB, organization_id: str, asset_id: str) -> Explanation | None:
    asset = db.get_asset(organization_id, asset_id)
    if asset is None:
        return None
    total, runs, classes = db.observation_summary(asset_id)
    evidence = [
        ExplanationEvidence(
            capability=capability_of(o.evidence.source),
            observed_at=o.observation.observed_at,
            run_id=o.observation.run_id,
            summary=f"{o.observation.observation_type}: {o.evidence.detail}",
        )
        for o in db.list_observations_for_asset(asset_id, newest=EVIDENCE_LIMIT)
    ]
    reasons = [f"observed in {runs} scan(s)"] if runs else ["no observations recorded"]
    _, _, value = asset.identity_key.partition(":")
    reasons += [
        f"covered by verified domain {record.domain}"
        for record in db.get_verified_domains_for_organization(organization_id)
        if asset.asset_type == "domain" and domain_is_covered(value, record.domain)
    ]
    return Explanation(
        subject_type="asset",
        subject_id=asset_id,
        claim=f"{value or asset.identity_key} is a {asset.asset_type} asset of this organization",
        status="active",
        confidence=", ".join(classes) or None,
        first_observed_at=asset.first_seen_at,
        last_observed_at=asset.last_seen_at,
        reasons=tuple(reasons),
        evidence=_newest_first(evidence),
        evidence_total=total,
    )


def explain_exposure(db: ControlDB, organization_id: str, exposure_id: str) -> Explanation | None:
    from core.risk_scoring import classify_exposure_risk

    exposure = db.get_exposure_for_organization(organization_id, exposure_id)
    factors = db.risk_factors_for_exposure(organization_id, exposure_id)
    if exposure is None or factors is None:
        return None
    risk = classify_exposure_risk(factors)
    capability = capability_of(exposure.source)
    total = db.count_exposure_evidence(organization_id, exposure_id)
    evidence = [
        ExplanationEvidence(
            capability=capability,
            observed_at=row.observed_at,
            run_id=row.run_id,
            summary=f"detector result #{row.finding_id} at {exposure.location}",
        )
        for row in db.list_exposure_evidence(organization_id, exposure_id, **_newest_page(total))
    ]
    return Explanation(
        subject_type="exposure",
        subject_id=exposure_id,
        claim=f"{exposure.title} ({exposure.severity}) at {exposure.location}",
        status=exposure.status,
        confidence=None if exposure.confidence_score is None else str(exposure.confidence_score),
        first_observed_at=exposure.first_seen_at,
        last_observed_at=exposure.last_seen_at,
        reasons=(f"risk level {risk.level.value}", *risk.reasons),
        evidence=_newest_first(evidence),
        evidence_total=total,
    )


def explain_relationship(
    db: ControlDB, organization_id: str, relationship_id: str
) -> Explanation | None:
    relationship = db.get_relationship(organization_id, relationship_id)
    if relationship is None:
        return None
    total = db.count_relationship_evidence(organization_id, relationship_id)
    rows = db.list_relationship_evidence(organization_id, relationship_id, **_newest_page(total))
    evidence = [
        ExplanationEvidence(
            capability=capability_of(row.collector or row.source),
            observed_at=row.observed_at,
            run_id=row.run_id,
            summary=row.reason,
        )
        for row in rows
    ]
    return Explanation(
        subject_type="relationship",
        subject_id=relationship_id,
        claim=(
            f"{relationship.source_entity} {relationship.relationship_type} "
            f"{relationship.target_entity}"
        ),
        status="active",
        confidence=relationship.confidence,
        first_observed_at=relationship.first_seen_at,
        last_observed_at=relationship.last_seen_at,
        reasons=tuple(dict.fromkeys(row.reason for row in rows)),
        evidence=_newest_first(evidence),
        evidence_total=total,
    )


EXPLAINERS = {
    "asset": explain_asset,
    "exposure": explain_exposure,
    "relationship": explain_relationship,
}
