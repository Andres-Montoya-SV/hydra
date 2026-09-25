"""Fase 04 (EASM roadmap, docs/easm/00_consolidation_plan.md): what a
single run concretely observed about an asset, and the evidence that
backs it — the other half of Fase 03's cross-run Asset identity. Pure
module, same discipline as `api/asset_identity.py`: no database access,
no `datetime.now()`, no randomness.

**Deliberately NOT matched against `core.provenance.ProvenanceRecord`/
`Host.provenance`, even though that looks like the obvious "evidence"
source at first glance.** Checked against real call sites
(`core/parsers/registry.py`) before building this: `field="port"`
records `value=f"{port.port}/{port.protocol}"` but `field="url"` records
`value=line[:200]` — a truncated RAW line, not the canonical, normalized
`URL.url` a `url` observation is keyed on. Matching an observation back
to a `Host.provenance` entry by field/value string equality would be
fragile and could silently produce wrong or missing evidence links,
which is unacceptable given the phase's own "trazabilidad completa...
siempre" requirement. Instead, this module reuses the evidence that is
ALREADY attached directly to the exact sub-entity each observation is
about — `Port.source`/`.confidence_score`, `DnsRecord.source`/
`.confidence_score`, `URL.source`/`.confidence_score`,
`TechnologyFinding.source`/`.confidence`,
`HttpService.source`/`.confidence_score` for a detected security header
— which is precise by construction (it is quite literally the record
that carries the fact), never a match that could silently point at the
wrong thing. This is Fase 01's "absorb, don't reinvent" applied to the
provenance shape `core/assets.py`'s own sub-entities already carry
(`source`/`confidence`/`confidence_score`), not to the separate,
free-text-keyed `Host.provenance` list.

**Why observation types beyond the four Fase 03 asset types exist
here**: the phase's own prompt names "puerto abierto, header presente,
tecnología detectada" as example observations — headers and
technologies are facts about a `domain` asset's HTTP surface, not
separate asset types of their own (Fase 03 deliberately did not create
a `technology`/`header` asset type, and this phase does not either —
see its own "no mezclar observación con exposure" instruction: a
detected technology or missing header is a neutral fact, not a risk
judgment). `technology_detected`/`security_header_present` observations
are therefore attached to the `domain` asset's own identity, with the
specific technology name / header name carried in the evidence's
`detail` field — never a new asset_type.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.asset_identity import (
    ASSET_TYPE_DNS_RECORD,
    ASSET_TYPE_DOMAIN,
    ASSET_TYPE_PORT,
    ASSET_TYPE_URL,
    dns_record_identity_key,
    domain_identity_key,
    port_identity_key,
    url_identity_key,
)
from core.assets import Host

OBSERVATION_TYPE_DOMAIN_RESOLVED = "domain_resolved"
OBSERVATION_TYPE_PORT_OPEN = "port_open"
OBSERVATION_TYPE_DNS_RECORD_PRESENT = "dns_record_present"
OBSERVATION_TYPE_URL_DISCOVERED = "url_discovered"
OBSERVATION_TYPE_TECHNOLOGY_DETECTED = "technology_detected"
OBSERVATION_TYPE_SECURITY_HEADER_PRESENT = "security_header_present"


@dataclass(frozen=True)
class EvidenceContent:
    """The exact, precise fact backing one observation — never a fuzzy
    match, always read directly off the sub-entity the observation is
    about. Two `EvidenceContent` values that compare equal (same
    `source`/`detail`/`confidence_score`) are, by definition, the exact
    same fact — this equality IS the deduplication key
    `api/control_db.py::record_observation` uses, the same "exact value
    match, no heuristics" discipline `api/asset_identity.py` already
    established for asset identity."""

    source: str
    detail: str
    confidence_score: int | None


@dataclass(frozen=True)
class ObservationDraft:
    """One fact ONE run observed about ONE asset — `asset_type`/
    `identity_key` identify WHICH asset (resolved to a real `asset_id`
    by the caller, using the exact same reconciliation map
    `api/asset_identity.py::reconcile_host_observations` already
    produced for this same `Host`/run — this module never re-derives
    asset identity itself, only observation content)."""

    asset_type: str
    identity_key: str
    observation_type: str
    evidence: EvidenceContent


def observations_for_host(host: Host) -> list[ObservationDraft]:
    """Every observation this ONE `Host` (one run's data for one
    hostname) implies. Mirrors `api/asset_identity.py::identities_for_host`
    in shape and scope deliberately — same four base types, plus the two
    HTTP-surface-derived types the phase's own prompt names."""
    drafts: list[ObservationDraft] = [
        ObservationDraft(
            asset_type=ASSET_TYPE_DOMAIN,
            identity_key=domain_identity_key(host.domain),
            observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
            evidence=EvidenceContent(
                source=",".join(sorted(host.discovery_sources)) or "unknown",
                detail="",
                confidence_score=host.confidence_score,
            ),
        )
    ]

    for port in host.ports:
        drafts.append(
            ObservationDraft(
                asset_type=ASSET_TYPE_PORT,
                identity_key=port_identity_key(
                    host=port.host, port=port.port, protocol=port.protocol
                ),
                observation_type=OBSERVATION_TYPE_PORT_OPEN,
                evidence=EvidenceContent(
                    source=port.source,
                    detail=port.service or "",
                    confidence_score=port.confidence_score,
                ),
            )
        )

    for record in host.dns_records:
        drafts.append(
            ObservationDraft(
                asset_type=ASSET_TYPE_DNS_RECORD,
                identity_key=dns_record_identity_key(
                    host=record.host, record_type=record.record_type, value=record.value
                ),
                observation_type=OBSERVATION_TYPE_DNS_RECORD_PRESENT,
                evidence=EvidenceContent(
                    source=record.source, detail="", confidence_score=record.confidence_score
                ),
            )
        )

    for url in host.urls:
        drafts.append(
            ObservationDraft(
                asset_type=ASSET_TYPE_URL,
                identity_key=url_identity_key(url.url),
                observation_type=OBSERVATION_TYPE_URL_DISCOVERED,
                evidence=EvidenceContent(
                    source=url.source, detail="", confidence_score=url.confidence_score
                ),
            )
        )

    domain_key = domain_identity_key(host.domain)
    for service in host.http_services:
        for tech in service.technologies:
            drafts.append(
                ObservationDraft(
                    asset_type=ASSET_TYPE_DOMAIN,
                    identity_key=domain_key,
                    observation_type=OBSERVATION_TYPE_TECHNOLOGY_DETECTED,
                    evidence=EvidenceContent(
                        source=tech.source, detail=tech.name, confidence_score=tech.confidence
                    ),
                )
            )
        for header_name in service.security_headers:
            drafts.append(
                ObservationDraft(
                    asset_type=ASSET_TYPE_DOMAIN,
                    identity_key=domain_key,
                    observation_type=OBSERVATION_TYPE_SECURITY_HEADER_PRESENT,
                    evidence=EvidenceContent(
                        source=service.source,
                        detail=header_name,
                        confidence_score=service.confidence_score,
                    ),
                )
            )

    return drafts
