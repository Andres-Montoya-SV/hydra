"""Fase 07 — consolidate run-scoped intel relationships across runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.relationship_identity import relationship_from_rows
from api.tenancy import account_db_path
from core.store import AssetStore

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings


@dataclass(frozen=True)
class RelationshipBackfillSummary:
    scans_processed: int
    source_relationships_seen: int
    relationships_created: int
    relationships_touched: int
    evidence_rows_recorded: int
    ungrounded_relationships_skipped: int


def backfill_relationships_for_organization(
    *,
    control_db: ControlDB,
    api_settings: APISettings,
    organization_id: str,
) -> RelationshipBackfillSummary:
    """Replay completed scans into the organization-scoped typed graph.

    The source query INNER JOINs evidence on both run_id and evidence_id.
    A relationship that cannot satisfy that join is counted as ungrounded and
    is never inserted into the consolidated graph.
    """
    scans = [
        scan
        for scan in control_db.list_scans_for_organization(organization_id)
        if scan.status == "completed"
    ]
    scans.sort(key=lambda scan: scan.created_at)
    existing_assets = control_db.existing_assets_for_organization(organization_id)

    source_relationships_seen = 0
    relationships_created = 0
    relationships_touched = 0
    evidence_rows_recorded = 0
    ungrounded_relationships_skipped = 0

    for scan in scans:
        store = AssetStore(account_db_path(api_settings, scan.account_id))
        conn = store.intel_connection()
        try:
            all_rows = conn.execute(
                "SELECT * FROM intel_relationships WHERE run_id = ? "
                "ORDER BY relationship_type, source_entity, target_entity",
                (scan.scan_id,),
            ).fetchall()
            evidence_rows = conn.execute(
                "SELECT * FROM intel_evidence WHERE run_id = ?",
                (scan.scan_id,),
            ).fetchall()
        finally:
            conn.close()

        evidence_by_id = {str(row["evidence_id"]): dict(row) for row in evidence_rows}
        observed_at = scan.updated_at or scan.created_at

        for source_row in all_rows:
            source_relationships_seen += 1
            row = dict(source_row)
            evidence_id = str(row.get("evidence_id") or "")
            draft = relationship_from_rows(row, evidence_by_id.get(evidence_id))
            if draft is None:
                ungrounded_relationships_skipped += 1
                continue

            source_asset = existing_assets.get(draft.source_entity)
            target_asset = existing_assets.get(draft.target_entity)
            _relationship_id, created, evidence_created = control_db.upsert_relationship(
                organization_id=organization_id,
                run_id=scan.scan_id,
                draft=draft,
                source_asset_id=source_asset.asset_id if source_asset else None,
                target_asset_id=target_asset.asset_id if target_asset else None,
                observed_at=observed_at,
            )
            if created:
                relationships_created += 1
            else:
                relationships_touched += 1
            if evidence_created:
                evidence_rows_recorded += 1

    return RelationshipBackfillSummary(
        scans_processed=len(scans),
        source_relationships_seen=source_relationships_seen,
        relationships_created=relationships_created,
        relationships_touched=relationships_touched,
        evidence_rows_recorded=evidence_rows_recorded,
        ungrounded_relationships_skipped=ungrounded_relationships_skipped,
    )
