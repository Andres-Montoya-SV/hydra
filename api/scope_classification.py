"""What one host is to one organization (Roadmap v2, Phase 01's required
distinction): excluded target, known asset, candidate awaiting review,
observed related infrastructure, authorized scope not yet discovered, or
unknown. Checked in that order; an exclusion wins over everything, since
it is the organization's explicit instruction never to collect against it.

Each answer carries the concrete reason and the record it rests on, so a
client never has to reconstruct why.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from api.control_db import ControlDB
from api.domain_verification import domain_is_covered
from core.scope import host_fully_excluded, split_scope_patterns

ScopeClass = Literal[
    "excluded",
    "known_asset",
    "candidate",
    "observed_related",
    "authorized_scope",
    "unknown",
]


@dataclass(frozen=True)
class ScopeClassification:
    host: str
    classification: ScopeClass
    reason: str
    asset_id: str | None = None
    candidate_asset_id: str | None = None
    exclusion_id: str | None = None


def excluding_pattern(host: str, patterns: dict[str, str]) -> str | None:
    """The id of the first whole-host exclusion (`pattern -> id`) covering
    `host`. A path-only exclusion never excludes the host itself."""
    for pattern, exclusion_id in sorted(patterns.items()):
        _, exclusions = split_scope_patterns([f"!{pattern}"])
        if host_fully_excluded(host, exclusions):
            return exclusion_id
    return None


def classify_host(db: ControlDB, organization_id: str, host: str) -> ScopeClassification:
    exclusions = {e.pattern: e.exclusion_id for e in db.list_scope_exclusions(organization_id)}
    exclusion_id = excluding_pattern(host, exclusions)
    if exclusion_id is not None:
        return ScopeClassification(
            host, "excluded", "matches an active organization exclusion", exclusion_id=exclusion_id
        )
    asset = db.get_asset_by_identity(
        organization_id=organization_id, asset_type="domain", identity_key=f"domain:{host}"
    )
    if asset is not None:
        return ScopeClassification(
            host, "known_asset", "confirmed asset of this organization", asset_id=asset.asset_id
        )
    candidate = db.find_candidate_by_value(organization_id, host)
    if candidate is not None:
        observed = candidate.scope_status != "IN_SCOPE" or candidate.review_status == "discarded"
        return ScopeClassification(
            host,
            "observed_related" if observed else "candidate",
            f"{candidate.scope_status.lower()} candidate ({candidate.review_status}): "
            f"{candidate.reason}",
            candidate_asset_id=candidate.candidate_asset_id,
        )
    for record in db.get_verified_domains_for_organization(organization_id):
        if domain_is_covered(host, record.domain):
            return ScopeClassification(
                host, "authorized_scope", f"covered by verified domain {record.domain}"
            )
    return ScopeClassification(host, "unknown", "not observed, not in authorized scope")
