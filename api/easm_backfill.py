"""Fase 18 (EASM roadmap): the missing wiring found while implementing
monitoring integration — every EASM backfill function (Fases 03-14) had
zero callers anywhere in the live pipeline before this phase; they were
only ever invoked from tests. That meant `assets`, `observations`,
`change_events`, `candidate_assets`, `relationships`, `exposures`,
`certificate_events`, and `technology_events` were NEVER actually
populated by a real scan, which in turn meant Fase 18's own goal
("el disparador de notificaciones lee de change_events y exposures, no
de snapshots crudos") was impossible to deliver safely — those tables
would always be empty. Andrés confirmed this needed fixing as
groundwork before Fase 18 could proceed (see the phase's own PR/report
for the stop-and-report that surfaced this).

This module is that missing piece: one function,
`run_easm_backfill_for_organization()`, called from
`api/scan_orchestrator.py::execute_scan()` right after a scan completes,
in its own try/except (a backfill bug must never retroactively fail an
already-completed scan — the same isolation
`_enqueue_high_severity_findings_event` already gets there).

**Known, pre-existing scaling characteristic, not introduced by this
phase**: every one of these backfill functions replays ALL of an
organization's completed scans from scratch, oldest-first (this is how
Fases 03-14 were each independently built and tested) — never
incrementally, just this scan's own new data. Calling them after every
scan completion means backfill cost grows with an organization's total
scan history, not just its latest scan. This is accepted here rather
than fixed, since making these 7 functions incremental would be a much
larger, riskier rewrite across phases this one does not own — flagged
explicitly in `docs/easm/18_monitoring_integration.md` as a real,
known risk for a future phase (likely Fase 20's own retention/
performance scope) to address, not silently absorbed or hidden.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.asset_backfill import backfill_assets_for_organization
from api.candidate_backfill import backfill_candidate_assets_for_organization
from api.certificate_backfill import detect_certificate_events_for_organization
from api.change_backfill import detect_and_record_changes_for_organization
from api.exposure_backfill import backfill_exposures_for_organization
from api.relationship_backfill import backfill_relationships_for_organization
from api.technology_backfill import detect_technology_events_for_organization

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings

logger = logging.getLogger("hydra.api.easm_backfill")


@dataclass(frozen=True)
class EasmBackfillSummary:
    assets_created: int
    change_events_recorded: int
    candidates_created: int
    relationships_created: int
    exposures_created: int
    certificate_events_recorded: int
    technology_events_recorded: int


def run_easm_backfill_for_organization(
    *, control_db: ControlDB, api_settings: APISettings, organization_id: str
) -> EasmBackfillSummary:
    """Runs every EASM backfill step in real dependency order — assets
    before anything that reads them, observations before the two
    per-observation-type event classifiers. Each step is independently
    idempotent (Fases 03-14's own established guarantee), so calling
    this after every scan, replaying full history every time, never
    duplicates a row; it only ever costs more time as history grows (see
    module docstring)."""
    asset_summary = backfill_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    change_summary = detect_and_record_changes_for_organization(
        control_db=control_db, organization_id=organization_id
    )
    candidate_summary = backfill_candidate_assets_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    relationship_summary = backfill_relationships_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    exposure_summary = backfill_exposures_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    certificate_summary = detect_certificate_events_for_organization(
        control_db=control_db, organization_id=organization_id
    )
    technology_summary = detect_technology_events_for_organization(
        control_db=control_db, organization_id=organization_id
    )
    return EasmBackfillSummary(
        assets_created=asset_summary.assets_created,
        change_events_recorded=change_summary.change_events_recorded,
        candidates_created=candidate_summary.candidates_created,
        relationships_created=relationship_summary.relationships_created,
        exposures_created=exposure_summary.exposures_created,
        certificate_events_recorded=certificate_summary.events_recorded,
        technology_events_recorded=technology_summary.events_recorded,
    )


def run_easm_backfill_for_organization_safely(
    *, control_db: ControlDB, api_settings: APISettings, organization_id: str
) -> EasmBackfillSummary | None:
    """The exact call `execute_scan()` makes — never raises. A backfill
    failure is logged and swallowed, same isolation
    `_enqueue_high_severity_findings_event` already gets in that same
    function: a bug here must never turn an already-successfully-
    completed scan into a failed one from the client's point of view."""
    try:
        return run_easm_backfill_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
    except Exception:
        logger.exception(
            "EASM backfill failed for organization %s -- scan status is unaffected", organization_id
        )
        return None
