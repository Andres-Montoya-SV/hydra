"""Fase 06 — Candidate Asset normalization.

A Candidate Asset is something Hydra discovered that may deserve future
investigation. It is deliberately NOT an owned Asset and deliberately NOT an
authorization decision. The run-scoped `core.intel.model.Indicator` already
models this lifecycle inside one scan; this module only provides the pure,
deterministic projection needed to reconcile those Indicators across runs at
organization scope.

Hard invariants:
- discovery != ownership
- discovery != authorization
- OUT_OF_SCOPE / UNKNOWN candidates remain valuable intelligence and may be
  persisted, but persistence never makes them eligible for collection
- lineage_reference is opaque: `intel_indicators.evidence_id` is a known
  legacy overloaded field (sometimes evidence_id, sometimes observation_id)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.assets import normalize_domain, normalize_http_url
from core.intel.model import (
    CollectionStatus,
    IndicatorKind,
    ScopeStatus,
    normalize_fingerprint,
)


@dataclass(frozen=True)
class CandidateAssetDraft:
    candidate_type: str
    normalized_value: str
    display_value: str
    scope_status: str
    collection_status: str
    authorization_status: str
    reason: str
    depth: int
    priority: int
    collector: str
    source_entity_id: str
    parent_indicator_id: str | None
    lineage_reference: str


def normalize_candidate_value(kind: str, value: str) -> str:
    """Canonical identity for one candidate kind/value pair.

    Exact canonical matching is the ONLY cross-run reconciliation rule.
    No shared-IP, certificate, branding, fuzzy URL, or LLM heuristic may
    merge two Candidate Assets.
    """
    raw = (value or "").strip()
    kind_upper = (kind or "").strip().upper()
    if not raw:
        return ""

    if kind_upper == IndicatorKind.DOMAIN.value:
        return normalize_domain(raw)
    if kind_upper == IndicatorKind.IP.value:
        try:
            return ipaddress.ip_address(raw).compressed.lower()
        except ValueError:
            return ""
    if kind_upper == IndicatorKind.CERTIFICATE.value:
        return normalize_fingerprint(raw)
    if kind_upper == IndicatorKind.URL.value:
        normalized = normalize_http_url(raw)
        parsed = urlsplit(normalized)
        return normalized if parsed.hostname else ""
    return ""


def candidate_from_indicator_row(row: dict[str, object]) -> CandidateAssetDraft | None:
    """Project a persisted run-scoped Indicator row into a Candidate draft."""
    kind = str(row.get("kind") or "").strip().upper()
    display_value = str(row.get("value") or "").strip()
    supplied_normalized = str(row.get("normalized_value") or "").strip()

    # Older intel_indicators rows do not persist normalized_value. Always
    # canonicalize ourselves rather than trusting a run's incidental casing.
    normalized = normalize_candidate_value(kind, supplied_normalized or display_value)
    if not normalized:
        return None

    try:
        scope_status = ScopeStatus(str(row.get("scope_status") or ScopeStatus.UNKNOWN.value)).value
    except ValueError:
        scope_status = ScopeStatus.UNKNOWN.value

    try:
        collection_status = CollectionStatus(
            str(row.get("collection_status") or CollectionStatus.DISCOVERED.value)
        ).value
    except ValueError:
        collection_status = CollectionStatus.DISCOVERED.value

    authorization_status = str(row.get("authorization_status") or "").strip()
    if not authorization_status:
        authorization_status = "ALLOW" if scope_status == ScopeStatus.IN_SCOPE.value else "DENY"

    try:
        depth = max(0, int(row.get("depth") or 0))
    except (TypeError, ValueError):
        depth = 0
    try:
        priority = int(row.get("priority") or 100)
    except (TypeError, ValueError):
        priority = 100

    parent = str(row.get("parent_id") or "").strip() or None
    lineage = str(row.get("evidence_id") or "").strip()

    return CandidateAssetDraft(
        candidate_type=kind,
        normalized_value=normalized,
        display_value=display_value,
        scope_status=scope_status,
        collection_status=collection_status,
        authorization_status=authorization_status,
        reason=str(row.get("reason") or "").strip(),
        depth=depth,
        priority=priority,
        collector=str(row.get("collector") or "").strip(),
        source_entity_id=str(
            row.get("source_entity_id") or row.get("discovered_from") or ""
        ).strip(),
        parent_indicator_id=parent,
        lineage_reference=lineage,
    )
