"""Fase 12 (EASM roadmap): RDAP enrichment for an already-known domain
asset, feeding its result through Fase 10's existing ingestion pipeline
exactly like Fase 11's importers did — no second evidence pipeline.

**RDAP result != authorized target, registration data != ownership
proof** — the phase's own core rule. This module only ever enriches a
domain that is ALREADY a real, known `assets` row in the organization
(the caller supplies it); it never creates a new candidate or asset from
an RDAP response, and never uses the registrar/entity name it reports to
attribute ownership of anything. If the domain being looked up is not
already a known asset, this module still performs the RDAP lookup (it is
a harmless, read-only third-party query) but records nothing — there is
no candidate-creation path for "an RDAP fact about something not yet
known," because RDAP is an ENRICHMENT capability, never a discovery
one (see `docs/easm/12_certificate_and_rdap.md`'s own "non-goals" for
the deliberate reasoning behind not treating RDAP nameservers/related
entities as new candidate signal in this first cut).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.asset_identity import domain_identity_key
from api.external_observation import (
    DEFAULT_SOURCE_CONFIDENCE_CLASS,
    ExternalObservationDraft,
    ObservationSource,
)
from api.external_observation_ingest import ExternalIngestSummary, ingest_external_observation_batch
from api.observation_identity import OBSERVATION_TYPE_DOMAIN_REGISTRATION_INFO
from core.collection.rdap_client import RdapResult, fetch_rdap_domain
from core.parsers.rdap import RdapDomainInfo, parse_rdap_domain_response

if TYPE_CHECKING:
    from api.control_db import ControlDB


@dataclass(frozen=True)
class RdapLookupSummary:
    domain: str
    rdap_blocked: bool
    rdap_blocked_reason: str
    domain_was_known_asset: bool
    ingest: ExternalIngestSummary | None


def _registration_detail(info: RdapDomainInfo) -> str:
    return (
        f"registrar={info.registrar}|"
        f"created={info.registration_created_at}|"
        f"expires={info.registration_expires_at}"
    )


def lookup_rdap_for_domain(
    *,
    control_db: ControlDB,
    organization_id: str,
    account_id: str,
    domain: str,
    timeout: float = 10.0,
) -> RdapLookupSummary:
    """Looks up `domain` via RDAP and, only if it is already a known
    asset in this organization AND the response has at least one
    reportable field, records one `OBSERVATION_TYPE_DOMAIN_REGISTRATION_INFO`
    evidence row via Fase 10's `ingest_external_observation_batch`."""
    result: RdapResult = fetch_rdap_domain(domain, timeout=timeout)
    if result.blocked or result.body is None:
        return RdapLookupSummary(
            domain=domain,
            rdap_blocked=True,
            rdap_blocked_reason=result.blocked_reason,
            domain_was_known_asset=False,
            ingest=None,
        )

    info = parse_rdap_domain_response(result.body)
    existing_asset = control_db.get_asset_by_identity(
        organization_id=organization_id,
        asset_type="domain",
        identity_key=domain_identity_key(domain),
    )
    domain_was_known_asset = existing_asset is not None

    has_reportable_field = bool(
        info.registrar or info.registration_created_at or info.registration_expires_at
    )
    if not domain_was_known_asset or not has_reportable_field:
        return RdapLookupSummary(
            domain=domain,
            rdap_blocked=False,
            rdap_blocked_reason="",
            domain_was_known_asset=domain_was_known_asset,
            ingest=None,
        )

    draft = ExternalObservationDraft(
        candidate_type="DOMAIN",
        normalized_value=domain,
        display_value=domain,
        observation_type=OBSERVATION_TYPE_DOMAIN_REGISTRATION_INFO,
        detail=_registration_detail(info),
        source=ObservationSource.RDAP,
        confidence_class=DEFAULT_SOURCE_CONFIDENCE_CLASS[ObservationSource.RDAP],
    )

    ingest_summary = ingest_external_observation_batch(
        control_db=control_db,
        organization_id=organization_id,
        account_id=account_id,
        drafts=[draft],
    )
    return RdapLookupSummary(
        domain=domain,
        rdap_blocked=False,
        rdap_blocked_reason="",
        domain_was_known_asset=True,
        ingest=ingest_summary,
    )
