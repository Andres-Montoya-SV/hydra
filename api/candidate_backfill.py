"""Fase 06 — reconcile run-scoped intel Indicators into Candidate Assets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.candidate_assets import candidate_from_indicator_row
from api.tenancy import account_db_path
from core.store import AssetStore

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings


@dataclass(frozen=True)
class CandidateBackfillSummary:
    scans_processed: int
    indicator_rows_seen: int
    candidates_created: int
    candidates_touched: int
    malformed_rows_skipped: int


def backfill_candidate_assets_for_organization(
    *,
    control_db: ControlDB,
    api_settings: APISettings,
    organization_id: str,
) -> CandidateBackfillSummary:
    """Replay completed scans oldest-first and persist their Indicators cross-run.

    This does not authorize, collect, or promote anything. It is a read-only
    projection from each account's run-scoped AssetStore into control.db's
    organization-scoped Candidate Asset registry.
    """
    scans = [
        scan
        for scan in control_db.list_scans_for_organization(organization_id)
        if scan.status == "completed"
    ]
    scans.sort(key=lambda scan: scan.created_at)

    indicator_rows_seen = 0
    candidates_created = 0
    candidates_touched = 0
    malformed_rows_skipped = 0

    for scan in scans:
        store = AssetStore(account_db_path(api_settings, scan.account_id))
        observed_at = scan.updated_at or scan.created_at
        for row in store.get_intel_indicators(scan.scan_id):
            indicator_rows_seen += 1
            draft = candidate_from_indicator_row(row)
            if draft is None:
                malformed_rows_skipped += 1
                continue
            _candidate_id, created = control_db.upsert_candidate_asset(
                organization_id=organization_id,
                run_id=scan.scan_id,
                draft=draft,
                observed_at=observed_at,
            )
            if created:
                candidates_created += 1
            else:
                candidates_touched += 1

    return CandidateBackfillSummary(
        scans_processed=len(scans),
        indicator_rows_seen=indicator_rows_seen,
        candidates_created=candidates_created,
        candidates_touched=candidates_touched,
        malformed_rows_skipped=malformed_rows_skipped,
    )
