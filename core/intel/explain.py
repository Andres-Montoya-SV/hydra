"""Human-readable, evidence-backed relationship explanations.

Correlation language only. Never actor, owner, or threat-group attribution.
"""

from __future__ import annotations

from typing import Any

_FORBIDDEN = (
    "same owner",
    "same actor",
    "same threat group",
    "threat actor",
    "owned by",
    "attributed to",
)


def _label(entity_id: str, entity: dict[str, Any] | None = None) -> str:
    if entity and entity.get("key"):
        return str(entity["key"])
    if ":" in entity_id:
        return entity_id.split(":", 1)[1]
    return entity_id


def _collection_status(
    source_entity: dict[str, Any] | None,
    target_entity: dict[str, Any] | None,
    fallback: str | None,
) -> str | None:
    statuses: list[str] = []
    for entity in (source_entity, target_entity):
        if not entity:
            continue
        if str(entity.get("entity_type") or "") != "DOMAIN":
            continue
        status = str(entity.get("collection_status") or "")
        if status:
            statuses.append(status)
    if "NOT_ALLOWED" in statuses:
        return "NOT_ALLOWED"
    if fallback:
        return fallback
    return statuses[0] if statuses else None


def explain_relationship(
    relationship: dict[str, Any],
    evidence: dict[str, Any] | None,
    *,
    collection_status: str | None = None,
    source_entity: dict[str, Any] | None = None,
    target_entity: dict[str, Any] | None = None,
    observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an analyst-facing explanation from persisted SQLite rows."""
    rel_type = str(relationship.get("relationship_type") or "")
    source_id = str(relationship.get("source_entity") or "")
    target_id = str(relationship.get("target_entity") or "")
    source = _label(source_id, source_entity)
    target = _label(target_id, target_entity)
    confidence = str(relationship.get("confidence") or "")
    strength = str(relationship.get("strength") or "")
    meta = dict(relationship.get("data") or {})
    if evidence:
        meta.update(dict(evidence.get("metadata") or {}))
    source_name = (evidence or {}).get("source") or meta.get("source") or ""
    collector = (evidence or {}).get("collector") or ""
    observed_sources: list[str] = []
    for obs in observations or []:
        src = str(obs.get("source") or "")
        col = str(obs.get("collector") or "")
        if src and src != "correlation":
            observed_sources.append(f"{src}/{col}" if col else src)
    if observed_sources:
        source_name = "/".join(dict.fromkeys(observed_sources))
    elif source_name == "correlation" and collector:
        source_name = f"{source_name}/{collector}"
    elif source_name and collector and collector not in str(source_name):
        source_name = f"{source_name}/{collector}"
    active = _collection_status(source_entity, target_entity, collection_status)
    facts: list[str] = []
    fingerprint = meta.get("fingerprint_sha256") or meta.get("certificate_fingerprint")
    if fingerprint:
        facts.append(f"certificate fingerprint: {fingerprint}")
    if meta.get("san_cardinality") is not None:
        facts.append(f"SAN cardinality: {meta.get('san_cardinality')}")
    if meta.get("ip"):
        ip = str(meta.get("ip"))
        facts.append(f"IPv4: {ip}" if ":" not in ip else f"IP: {ip}")
    if meta.get("provider"):
        facts.append(f"cloud tenancy: {meta.get('provider')}")
    if meta.get("shared_cloud_tenancy") or strength == "shared_cloud_tenancy":
        facts.append("shared cloud tenancy (not ownership)")
    if source_name:
        facts.append(f"observed source: {source_name}")
    if active:
        facts.append(f"active_collection: {active}")
    text = "\n".join(
        [
            f"{source}",
            f"  {rel_type}",
            f"{target}",
            "",
            "Evidence:",
            *[f"  {item}" for item in facts],
            f"  confidence: {confidence}",
            f"  signal: {strength}",
        ]
    )
    lowered = text.lower()
    if any(word in lowered for word in _FORBIDDEN):
        text = "\n".join(
            line
            for line in text.splitlines()
            if not any(word in line.lower() for word in _FORBIDDEN)
        )
    return {
        "source_entity": source,
        "relationship_type": rel_type,
        "target_entity": target,
        "confidence": confidence,
        "strength": strength,
        "facts": facts,
        "text": text,
    }
