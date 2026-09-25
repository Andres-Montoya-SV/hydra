"""Fase 03 (EASM roadmap): runs the pure reconciliation logic in
`api/asset_identity.py` against an organization's REAL, already-existing
run history — never against the live scan-completion path.

Deliberately NOT wired into `api/scan_orchestrator.py`/
`api/monitoring_worker.py` in this phase — the phase's own prompt is
explicit that this phase is about "qué pasa DESPUÉS de que el scan ya
corrió y guardó sus resultados crudos," never the scanning flow itself,
and a later phase (04, "Observaciones y evidencia," is the natural
candidate) is where live, per-scan-completion wiring belongs. This
module is what phase 03's own required "correr la reconciliación contra
el histórico de runs ya existente" backfill test actually calls.

One backfill call is scoped to ONE organization — every `ScanRecord`
`list_scans_for_organization` returns carries its own `account_id`
(different scans under one organization are not guaranteed to share an
account_id in the general case — a future multi-owner-account
organization — so each scan's OWN account is used to open the right
`AssetStore` file, never an account assumed from the organization or
from a prior scan in the same loop).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.asset_identity import ExistingAsset, reconcile_host_observations
from api.tenancy import account_db_path
from core.store import AssetStore

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings


@dataclass(frozen=True)
class BackfillSummary:
    scans_processed: int
    hosts_processed: int
    assets_created: int
    assets_touched: int


def backfill_assets_for_organization(
    *, control_db: ControlDB, api_settings: APISettings, organization_id: str
) -> BackfillSummary:
    """Replays every `'completed'` scan this organization has ever had,
    oldest first, reconciling each scan's `Host` rows (read back from
    that scan's OWN account's `AssetStore` — never mutated, never
    deleted, per the phase's own "no destructive migration of run_id-
    scoped tables" rule) into the organization's `assets`/
    `asset_identifiers` tables.

    The in-memory `existing` map is seeded once from every asset already
    persisted for this organization, then updated as this SAME call
    mints new ones — so a host observed for the first time in an early
    scan and seen again in a later scan within this one backfill run
    correctly reconciles to the same asset, not two, without needing a
    round trip to the database between scans."""
    scans = [
        s
        for s in control_db.list_scans_for_organization(organization_id)
        if s.status == "completed"
    ]
    scans.sort(key=lambda s: s.created_at)

    existing = control_db.existing_assets_for_organization(organization_id)
    scans_processed = 0
    hosts_processed = 0
    assets_created = 0
    assets_touched = 0

    for scan in scans:
        store = AssetStore(account_db_path(api_settings, scan.account_id))
        hosts = store.get_hosts(scan.scan_id)
        scans_processed += 1
        observed_at = scan.updated_at or scan.created_at
        for host in hosts:
            hosts_processed += 1
            decisions = reconcile_host_observations(
                host=host,
                existing_by_identity_key=existing,
                new_asset_id=lambda: secrets.token_hex(16),
            )
            control_db.apply_asset_reconciliation(
                organization_id=organization_id,
                run_id=scan.scan_id,
                decisions=decisions,
                observed_at=observed_at,
            )
            for decision in decisions:
                if decision.is_new:
                    assets_created += 1
                else:
                    assets_touched += 1
                existing[decision.identity_key] = ExistingAsset(
                    asset_id=decision.asset_id,
                    asset_type=decision.asset_type,
                    identity_key=decision.identity_key,
                )

    return BackfillSummary(
        scans_processed=scans_processed,
        hosts_processed=hosts_processed,
        assets_created=assets_created,
        assets_touched=assets_touched,
    )
