"""Canonical relationship representation for CLI, HTML, Markdown, and JSON."""

from __future__ import annotations

from typing import Any

from core.intel.explain import explain_relationship


def serialize_relationship(
    row: dict[str, Any],
    *,
    evidence: dict[str, Any] | None = None,
    source_entity: dict[str, Any] | None = None,
    target_entity: dict[str, Any] | None = None,
    run_id: str | None = None,
    explanation: str | None = None,
) -> dict[str, Any]:
    """One relationship object. Reporters must not re-format independently."""
    data = dict(row.get("data") or row.get("data_json") or {})
    if isinstance(row.get("data_json"), str) and not row.get("data"):
        data = {}
    evidence_meta = dict((evidence or {}).get("metadata") or {})
    fingerprint = (
        data.get("certificate_fingerprint")
        or data.get("fingerprint_sha256")
        or evidence_meta.get("certificate_fingerprint")
        or evidence_meta.get("fingerprint_sha256")
        or ""
    )
    serial = (
        data.get("certificate_serial")
        or data.get("serial")
        or evidence_meta.get("certificate_serial")
        or ""
    )
    shared_ip = str(data.get("ip") or data.get("shared_ip") or evidence_meta.get("ip") or "")
    san_cardinality = data.get("san_cardinality")
    if san_cardinality is None:
        san_cardinality = evidence_meta.get("san_cardinality")
    evidence_row = evidence or {}
    if explanation is None:
        explained = explain_relationship(
            row,
            evidence,
            source_entity=source_entity,
            target_entity=target_entity,
        )
        explanation = str(explained.get("text") or "")
    evidence_ids = []
    eid = row.get("evidence_id") or evidence_row.get("evidence_id")
    if eid:
        evidence_ids.append(eid)
    extra_ids = data.get("evidence_ids") or evidence_meta.get("evidence_ids") or []
    if isinstance(extra_ids, list):
        for item in extra_ids:
            if item and item not in evidence_ids:
                evidence_ids.append(item)
    observed_at = (
        evidence_row.get("observed_at")
        or data.get("observed_at")
        or evidence_meta.get("observed_at")
        or ""
    )
    return {
        "relationship_id": row.get("relationship_id"),
        "source_entity": row.get("source_entity"),
        "target_entity": row.get("target_entity"),
        "relationship_type": row.get("relationship_type"),
        "confidence_band": row.get("confidence") or row.get("confidence_band"),
        "strength": row.get("strength"),
        "evidence_id": eid,
        "evidence_ids": evidence_ids,
        "evidence_type": evidence_row.get("reason") or row.get("strength") or "",
        "certificate_fingerprint": fingerprint,
        "certificate_serial": serial,
        "shared_ip": shared_ip,
        "san_cardinality": san_cardinality,
        "source_artifact": evidence_row.get("source") or data.get("source") or "",
        "source_plugin": evidence_row.get("collector") or data.get("collector") or "",
        "run_id": run_id or row.get("run_id") or "",
        "explanation": explanation,
        "rationale": explanation,
        "observed_at": observed_at,
        "collection_status": (
            (source_entity or {}).get("collection_status")
            or (target_entity or {}).get("collection_status")
            or row.get("collection_status")
            or ""
        ),
        "scope_status": (
            (source_entity or {}).get("scope_status")
            or (target_entity or {}).get("scope_status")
            or row.get("scope_status")
            or ""
        ),
    }


def relationship_view(*args, **kwargs) -> dict[str, Any]:
    """Canonical RelationshipView. Reporters must not invent a second serializer."""
    return serialize_relationship(*args, **kwargs)


def serialize_relationships(
    rows: list[dict[str, Any]],
    *,
    evidence_by_id: dict[str, dict[str, Any]] | None = None,
    entities_by_id: dict[str, dict[str, Any]] | None = None,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    evidence_by_id = evidence_by_id or {}
    entities_by_id = entities_by_id or {}
    out: list[dict[str, Any]] = []
    for row in rows:
        eid = str(row.get("evidence_id") or "")
        src = str(row.get("source_entity") or "")
        dst = str(row.get("target_entity") or "")
        out.append(
            serialize_relationship(
                row,
                evidence=evidence_by_id.get(eid),
                source_entity=entities_by_id.get(src),
                target_entity=entities_by_id.get(dst),
                run_id=run_id,
            )
        )
    return out
