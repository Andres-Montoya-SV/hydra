"""Fase 14 (EASM roadmap): walks each domain asset's own
`OBSERVATION_TYPE_TECHNOLOGY_DETECTED` evidence history (already recorded
by Fase 04/06 from real httpx/browser_probe/WhatWeb captures — no new
collection), grouped by the run that produced each fact, and records the
deterministic `ADDED`/`REMOVED`/`VERSION_CHANGED` events
`api/technology_events.py::classify_technology_transition` decides
between each pair of consecutive runs.

A separate pass from `api/change_backfill.py`/`api/certificate_backfill.py`,
same reasoning both already established: this answers the specific,
richer question "which technologies were added, removed, or changed
version" rather than "did any fact change" — reusing the exact same
Evidence/Observation rows, never a second collection or a new asset
type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.observation_identity import OBSERVATION_TYPE_TECHNOLOGY_DETECTED
from api.technology_catalog import parse_technology_detail
from api.technology_events import classify_technology_transition

if TYPE_CHECKING:
    from api.control_db import ControlDB


@dataclass(frozen=True)
class TechnologyBackfillSummary:
    domain_assets_processed: int
    run_transitions_seen: int
    events_recorded: int
    events_already_present: int


def detect_technology_events_for_organization(
    *, control_db: ControlDB, organization_id: str
) -> TechnologyBackfillSummary:
    """Idempotent: `record_technology_event`'s own
    `UNIQUE(asset_id, run_id, event_type, technology_name, reason)`
    constraint means running this twice over the same organization's
    data produces zero duplicate rows — every event on the second pass
    lands in `events_already_present` instead."""
    domain_assets = control_db.list_assets_for_organization(organization_id, asset_type="domain")

    domain_assets_processed = 0
    run_transitions_seen = 0
    events_recorded = 0
    events_already_present = 0

    for asset in domain_assets:
        tech_observations = [
            entry
            for entry in control_db.list_observations_for_asset(asset.asset_id)
            if entry.observation.observation_type == OBSERVATION_TYPE_TECHNOLOGY_DETECTED
        ]
        if not tech_observations:
            continue
        domain_assets_processed += 1

        # One "run snapshot" is the full set of distinct canonical
        # technologies that ONE run observed for this domain -- unlike a
        # certificate, several technologies can be true at once, so the
        # unit being compared across runs is a {name: version} mapping,
        # never a single value.
        run_snapshots: dict[str, dict[str, str | None]] = {}
        run_order_key: dict[str, str] = {}
        for entry in tech_observations:
            run_id = entry.observation.run_id
            name, version = parse_technology_detail(entry.evidence.detail)
            run_snapshots.setdefault(run_id, {})[name] = version
            existing_key = run_order_key.get(run_id)
            if existing_key is None or entry.observation.observed_at < existing_key:
                run_order_key[run_id] = entry.observation.observed_at

        ordered_run_ids = sorted(run_snapshots, key=lambda run_id: (run_order_key[run_id], run_id))

        previous_snapshot: dict[str, str | None] | None = None
        for run_id in ordered_run_ids:
            current_snapshot = run_snapshots[run_id]
            run_transitions_seen += 1
            for event in classify_technology_transition(
                previous=previous_snapshot, current=current_snapshot
            ):
                result = control_db.record_technology_event(
                    organization_id=organization_id,
                    asset_id=asset.asset_id,
                    run_id=run_id,
                    event_type=event.event_type.value,
                    technology_name=event.technology_name,
                    reason=event.reason,
                    detected_at=run_order_key[run_id],
                )
                if result is not None:
                    events_recorded += 1
                else:
                    events_already_present += 1
            previous_snapshot = current_snapshot

    return TechnologyBackfillSummary(
        domain_assets_processed=domain_assets_processed,
        run_transitions_seen=run_transitions_seen,
        events_recorded=events_recorded,
        events_already_present=events_already_present,
    )
