"""Fase 07 — pure normalization for the consolidated relationship graph.

Run-scoped `core.intel.model.Relationship` is the canonical vocabulary.
This module does not infer new edges and never uses the legacy
`graph_nodes`/`graph_edges` representation.

A relationship is accepted only when its source Evidence row was resolved in
that SAME run by the I/O layer. Missing evidence means no EASM relationship.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from core.intel.model import ConfidenceBand, RelationshipType


@dataclass(frozen=True)
class RelationshipEvidenceDraft:
    source_evidence_id: str
    source: str
    collector: str
    reason: str
    metadata_json: str
    observed_at: str


@dataclass(frozen=True)
class RelationshipDraft:
    source_entity: str
    relationship_type: str
    target_entity: str
    confidence: str
    strength: str
    data_json: str
    evidence: RelationshipEvidenceDraft


def relationship_from_rows(
    relationship_row: dict[str, object],
    evidence_row: dict[str, object] | None,
) -> RelationshipDraft | None:
    """Normalize one relationship + its mechanically-resolved evidence.

    No evidence row -> no relationship. Unknown relationship/confidence enum
    values are also rejected instead of quietly widening the vocabulary.
    """
    if evidence_row is None:
        return None

    source_entity = str(relationship_row.get("source_entity") or "").strip()
    target_entity = str(relationship_row.get("target_entity") or "").strip()
    relationship_type_raw = str(relationship_row.get("relationship_type") or "").strip()
    evidence_id = str(relationship_row.get("evidence_id") or "").strip()
    resolved_evidence_id = str(evidence_row.get("evidence_id") or "").strip()

    if (
        not source_entity
        or not target_entity
        or not relationship_type_raw
        or not evidence_id
        or evidence_id != resolved_evidence_id
    ):
        return None

    try:
        relationship_type = RelationshipType(relationship_type_raw).value
    except ValueError:
        return None

    confidence_raw = str(relationship_row.get("confidence") or "").strip()
    try:
        confidence = ConfidenceBand(confidence_raw).value
    except ValueError:
        return None

    raw_data = relationship_row.get("data_json")
    if isinstance(raw_data, str) and raw_data.strip():
        try:
            parsed_data = json.loads(raw_data)
        except json.JSONDecodeError:
            parsed_data = {}
    elif isinstance(raw_data, dict):
        parsed_data = raw_data
    else:
        parsed_data = {}

    raw_metadata = evidence_row.get("metadata_json")
    if isinstance(raw_metadata, str) and raw_metadata.strip():
        try:
            parsed_metadata = json.loads(raw_metadata)
        except json.JSONDecodeError:
            parsed_metadata = {}
    elif isinstance(raw_metadata, dict):
        parsed_metadata = raw_metadata
    else:
        parsed_metadata = {}

    return RelationshipDraft(
        source_entity=source_entity,
        relationship_type=relationship_type,
        target_entity=target_entity,
        confidence=confidence,
        strength=str(relationship_row.get("strength") or "").strip(),
        data_json=json.dumps(parsed_data, sort_keys=True, separators=(",", ":")),
        evidence=RelationshipEvidenceDraft(
            source_evidence_id=evidence_id,
            source=str(evidence_row.get("source") or "").strip(),
            collector=str(evidence_row.get("collector") or "").strip(),
            reason=str(evidence_row.get("reason") or "").strip(),
            metadata_json=json.dumps(parsed_metadata, sort_keys=True, separators=(",", ":")),
            observed_at=str(evidence_row.get("observed_at") or "").strip(),
        ),
    )
