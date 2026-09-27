"""Fase 10 (EASM roadmap): the I/O layer that actually writes external
observations somewhere real — reusing Fase 03/04/06's existing tables
and methods end to end, never a second observation/asset pipeline.

**The one rule this module exists to enforce**: `Observed != Owned`,
`Imported != Authorized`. A fact about something that is ALREADY a real,
known `assets` row (previously discovered by a real scan, or previously
promoted — Fase 06) is recorded as ordinary Evidence/Observation,
exactly like a scan's own findings. A fact about something that is NOT
already a known asset is never inserted into `assets` — it becomes a
`candidate_assets` row instead (Fase 06), fully reviewable, promotable,
and discardable through the exact same human confirm/discard workflow
every other candidate goes through, with no shortcut for "but this one
came from an import."

Deliberately thin: no new identity scheme (candidate normalization reuses
`api/candidate_assets.py::normalize_candidate_value` verbatim; asset
identity reuses `api/asset_identity.py`'s `domain_identity_key`/
`url_identity_key`), no new evidence/observation shape (reuses
`api/observation_identity.py::EvidenceContent` and
`ControlDB.find_or_create_evidence`/`record_observation` exactly as
Fase 04 already built them), no new authorization primitive (every
imported fact about something not already an asset fails closed into
`candidate_assets` with `authorization_status="DENY"`, the same
fail-closed default `api/candidate_assets.py::candidate_from_indicator_row`
already uses for missing historical authorization data).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.asset_identity import (
    ASSET_TYPE_DOMAIN,
    ASSET_TYPE_URL,
    domain_identity_key,
    url_identity_key,
)
from api.candidate_assets import CandidateAssetDraft, normalize_candidate_value
from api.external_observation import ExternalObservationDraft
from api.observation_identity import EvidenceContent
from core.intel.model import CollectionStatus, ScopeStatus

if TYPE_CHECKING:
    from api.control_db import ControlDB

_ASSET_IDENTITY_BUILDERS = {
    "DOMAIN": (ASSET_TYPE_DOMAIN, domain_identity_key),
    "URL": (ASSET_TYPE_URL, url_identity_key),
}


@dataclass(frozen=True)
class ExternalIngestSummary:
    batch_id: str
    drafts_processed: int
    observations_recorded_on_known_assets: int
    candidates_created: int
    candidates_touched: int
    malformed_drafts_skipped: int


def ingest_external_observation_batch(
    *,
    control_db: ControlDB,
    organization_id: str,
    account_id: str,
    drafts: list[ExternalObservationDraft],
    raw_artifact_reference: str = "",
) -> ExternalIngestSummary:
    """Ingests one batch of `ExternalObservationDraft`s. Every draft in
    the batch shares one `source`/`confidence_class` pair by construction
    (`ExternalObservationDraft` carries its own, but a real batch — one
    Nmap XML file, one RDAP lookup — is from a single source; a caller
    mixing sources in one call is calling this once per source, not a
    bug this function needs to guard against, since nothing here assumes
    otherwise)."""
    if not drafts:
        raise ValueError("a batch must contain at least one observation")

    batch_id = control_db.create_observation_batch(
        organization_id=organization_id,
        account_id=account_id,
        source=drafts[0].source.value,
        confidence_class=drafts[0].confidence_class.value,
        raw_artifact_reference=raw_artifact_reference,
    )

    drafts_processed = 0
    observations_recorded_on_known_assets = 0
    candidates_created = 0
    candidates_touched = 0
    malformed_drafts_skipped = 0

    for draft in drafts:
        drafts_processed += 1
        normalized = normalize_candidate_value(draft.candidate_type, draft.normalized_value)
        if not normalized:
            malformed_drafts_skipped += 1
            continue

        identity_builder = _ASSET_IDENTITY_BUILDERS.get(draft.candidate_type)
        existing_asset = None
        if identity_builder is not None:
            asset_type, identity_key_fn = identity_builder
            existing_asset = control_db.get_asset_by_identity(
                organization_id=organization_id,
                asset_type=asset_type,
                identity_key=identity_key_fn(normalized),
            )

        if existing_asset is not None:
            # Observed != Owned is already satisfied — this asset is
            # ALREADY a known, authorized part of the organization's
            # footprint (a real scan found it, or a human already
            # promoted it). Recording new corroborating/updating
            # evidence about it is ordinary Fase 04 observation
            # recording, not a scope decision.
            evidence_id = control_db.find_or_create_evidence(
                organization_id=organization_id,
                asset_id=existing_asset.asset_id,
                content=EvidenceContent(
                    source=draft.source.value,
                    detail=draft.detail,
                    confidence_score=None,
                    confidence_class=draft.confidence_class.value,
                ),
                run_id=batch_id,
            )
            control_db.record_observation(
                organization_id=organization_id,
                asset_id=existing_asset.asset_id,
                run_id=batch_id,
                account_id=account_id,
                observation_type=draft.observation_type,
                evidence_id=evidence_id,
            )
            observations_recorded_on_known_assets += 1
            continue

        # Not already a known asset — imported data is NEVER
        # authorization, so this can only ever become a reviewable
        # Candidate Asset (Fase 06), fail-closed, exactly like any other
        # unauthorized discovery.
        candidate_draft = CandidateAssetDraft(
            candidate_type=draft.candidate_type,
            normalized_value=normalized,
            display_value=draft.display_value,
            scope_status=ScopeStatus.UNKNOWN.value,
            collection_status=CollectionStatus.NOT_COLLECTED.value,
            authorization_status="DENY",
            reason=f"external observation ({draft.source.value}): {draft.detail}",
            depth=0,
            priority=100,
            collector=draft.source.value,
            source_entity_id="",
            parent_indicator_id=None,
            lineage_reference=batch_id,
        )
        _candidate_id, created = control_db.upsert_candidate_asset(
            organization_id=organization_id,
            run_id=batch_id,
            draft=candidate_draft,
        )
        if created:
            candidates_created += 1
        else:
            candidates_touched += 1

    return ExternalIngestSummary(
        batch_id=batch_id,
        drafts_processed=drafts_processed,
        observations_recorded_on_known_assets=observations_recorded_on_known_assets,
        candidates_created=candidates_created,
        candidates_touched=candidates_touched,
        malformed_drafts_skipped=malformed_drafts_skipped,
    )
