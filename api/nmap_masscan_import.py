"""Fase 11 (EASM roadmap): safe import of Nmap XML and Masscan JSON scan
reports produced OUTSIDE Hydra (a customer's own scan, an Nmap run done
by hand) — never a scanner invocation of Hydra's own. Nmap and Masscan
are both explicitly out of scope as active scanners the roadmap itself
runs (section 3's exclusions, and Fase 10's own "Masscan nunca se agrega
como scanner activo").

Reuses Fase 10's ingestion pipeline
(`api/external_observation_ingest.py::ingest_external_observation_batch`)
end to end — this module's only job is: validate the uploaded artifact
safely, parse it with a pure, hardened parser
(`core/parsers/nmap_import.py`, `core/parsers/masscan_import.py`), and
turn each host's facts into `ExternalObservationDraft`s. No second
evidence/candidate pipeline, no new asset type.

**The one rule this module exists to enforce, same as Fase 10's own**:
`Imported != Authorized`. Every host this module finds becomes an
IP-type Candidate Asset — never an authorized target, regardless of how
many open ports Nmap/Masscan reported for it — carrying a human-readable
summary of every discovered port/service in its evidence `detail`. Any
hostname Nmap also resolved for that host is reported separately as an
ordinary DOMAIN observation through the exact same route Fase 10 already
built: corroborating evidence if that domain is already a known, owned
asset, or a DOMAIN candidate otherwise. There is no code path here that
promotes anything to `assets` directly.

**IVRE**: evaluated per this phase's own instruction to treat it as an
import source, not another scanning framework. Not implemented — IVRE
requires its own MongoDB deployment and a live scan-orchestration layer
of its own, which fails this phase's own "acotado, testeable,
mantenible" bar for a first cut (a new required infrastructure
dependency, not just a new parser). If IVRE integration is revisited
later, the adapter shape is exactly `_import_hosts` below: a byte-string
parser producing `list[ImportedHostRecord]`, nothing IVRE-specific
leaking past that boundary.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from api.candidate_assets import normalize_candidate_value
from api.external_observation import (
    DEFAULT_SOURCE_CONFIDENCE_CLASS,
    ExternalObservationDraft,
    ObservationSource,
)
from api.external_observation_ingest import ExternalIngestSummary, ingest_external_observation_batch
from api.observation_identity import OBSERVATION_TYPE_DOMAIN_RESOLVED, OBSERVATION_TYPE_PORT_OPEN
from core.parsers.imported_hosts import ImportedHostRecord, ImportParseError
from core.parsers.masscan_import import parse_masscan_json
from core.parsers.nmap_import import parse_nmap_xml

if TYPE_CHECKING:
    from api.control_db import ControlDB

# Generous for a real Nmap/Masscan report against a handful of hosts,
# small enough to bound memory and parse time for an untrusted upload —
# the phase's own "tamaño acotado" requirement.
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024

# Magic bytes for the common compressed-archive formats. Rejected
# outright with a clear error rather than attempted as XML/JSON — this
# module never decompresses anything (the phase's own "sin extracción
# insegura de archivos comprimidos" requirement), so a gzip/zip upload
# must fail loudly, not silently misparse as garbage XML/JSON.
_COMPRESSED_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x1f\x8b",  # gzip
    b"PK\x03\x04",  # zip
    b"PK\x05\x06",  # empty zip
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
)


class ImportValidationError(ValueError):
    """The uploaded artifact was rejected before any database write
    happened — empty, oversized, compressed, or not parsable as the
    expected format at all."""


@dataclass(frozen=True)
class HostImportSummary:
    """What one `import_nmap_xml`/`import_masscan_json` call actually
    did. `already_imported=True` means this exact artifact (same bytes,
    same organization, same source) was seen before — the call still ran
    the full pipeline (safe to repeat, see `ControlDB.
    create_observation_batch`'s own idempotency), it just produced no new
    rows anywhere."""

    dry_run: bool
    already_imported: bool
    hosts_parsed: int
    hosts_skipped_invalid_ip: int
    ingest: ExternalIngestSummary | None


def _port_summary(host: ImportedHostRecord) -> str:
    if not host.ports:
        return "no ports reported"
    parts = []
    for port in sorted(host.ports, key=lambda p: (p.protocol, p.port)):
        service = port.service_name or "unknown service"
        if port.product:
            version_suffix = (
                f" ({port.product} {port.version})" if port.version else f" ({port.product})"
            )
        else:
            version_suffix = ""
        parts.append(f"{port.port}/{port.protocol} {port.state} {service}{version_suffix}")
    return "; ".join(parts)


def _drafts_for_host(
    host: ImportedHostRecord, *, source: ObservationSource
) -> list[ExternalObservationDraft]:
    confidence_class = DEFAULT_SOURCE_CONFIDENCE_CLASS[source]
    drafts: list[ExternalObservationDraft] = [
        ExternalObservationDraft(
            candidate_type="IP",
            normalized_value=host.ip_address,
            display_value=host.ip_address,
            observation_type=OBSERVATION_TYPE_PORT_OPEN,
            detail=f"{source.value} import: {_port_summary(host)}",
            source=source,
            confidence_class=confidence_class,
        )
    ]
    for hostname in host.hostnames:
        drafts.append(
            ExternalObservationDraft(
                candidate_type="DOMAIN",
                normalized_value=hostname,
                display_value=hostname,
                observation_type=OBSERVATION_TYPE_DOMAIN_RESOLVED,
                detail=f"resolved to {host.ip_address} via {source.value} import",
                source=source,
                confidence_class=confidence_class,
            )
        )
    return drafts


def _reject_if_compressed(raw_bytes: bytes) -> None:
    for magic in _COMPRESSED_MAGIC_PREFIXES:
        if raw_bytes.startswith(magic):
            raise ImportValidationError(
                "compressed archives are not accepted — upload the raw XML/JSON report"
            )


def _reject_unsafe_bytes(raw_bytes: bytes) -> None:
    """Compressed archives first (the clearer message for a gzip upload),
    then NUL (Phase 11g): raw or escaped in JSON, it never belongs in a
    report, and PostgreSQL refuses one in text."""
    _reject_if_compressed(raw_bytes)
    if b"\x00" in raw_bytes or b"\\u0000" in raw_bytes.lower():
        raise ImportValidationError("the report contains a NUL character")


def _import_hosts(
    *,
    control_db: ControlDB,
    organization_id: str,
    account_id: str,
    raw_bytes: bytes,
    parser: Callable[[bytes], list[ImportedHostRecord]],
    source: ObservationSource,
    raw_artifact_reference: str,
    dry_run: bool,
) -> HostImportSummary:
    if not raw_bytes:
        raise ImportValidationError("empty artifact")
    if len(raw_bytes) > MAX_ARTIFACT_BYTES:
        raise ImportValidationError(f"artifact exceeds the {MAX_ARTIFACT_BYTES} byte limit")
    _reject_unsafe_bytes(raw_bytes)

    artifact_hash = hashlib.sha256(raw_bytes).hexdigest()
    existing_batch = control_db.find_observation_batch_by_artifact_hash(
        organization_id=organization_id, source=source.value, artifact_hash=artifact_hash
    )
    already_imported = existing_batch is not None

    try:
        hosts = parser(raw_bytes)
    except ImportParseError as exc:
        raise ImportValidationError(str(exc)) from exc

    valid_hosts: list[ImportedHostRecord] = []
    hosts_skipped_invalid_ip = 0
    for host in hosts:
        if not normalize_candidate_value("IP", host.ip_address):
            hosts_skipped_invalid_ip += 1
            continue
        valid_hosts.append(host)

    drafts: list[ExternalObservationDraft] = []
    for host in valid_hosts:
        drafts.extend(_drafts_for_host(host, source=source))

    if dry_run or not drafts:
        return HostImportSummary(
            dry_run=dry_run,
            already_imported=already_imported,
            hosts_parsed=len(hosts),
            hosts_skipped_invalid_ip=hosts_skipped_invalid_ip,
            ingest=None,
        )

    ingest_summary = ingest_external_observation_batch(
        control_db=control_db,
        organization_id=organization_id,
        account_id=account_id,
        drafts=drafts,
        raw_artifact_reference=raw_artifact_reference,
        artifact_hash=artifact_hash,
    )
    return HostImportSummary(
        dry_run=False,
        already_imported=already_imported,
        hosts_parsed=len(hosts),
        hosts_skipped_invalid_ip=hosts_skipped_invalid_ip,
        ingest=ingest_summary,
    )


def import_nmap_xml(
    *,
    control_db: ControlDB,
    organization_id: str,
    account_id: str,
    xml_bytes: bytes,
    raw_artifact_reference: str = "",
    dry_run: bool = False,
) -> HostImportSummary:
    return _import_hosts(
        control_db=control_db,
        organization_id=organization_id,
        account_id=account_id,
        raw_bytes=xml_bytes,
        parser=parse_nmap_xml,
        source=ObservationSource.NMAP,
        raw_artifact_reference=raw_artifact_reference,
        dry_run=dry_run,
    )


def import_masscan_json(
    *,
    control_db: ControlDB,
    organization_id: str,
    account_id: str,
    json_bytes: bytes,
    raw_artifact_reference: str = "",
    dry_run: bool = False,
) -> HostImportSummary:
    return _import_hosts(
        control_db=control_db,
        organization_id=organization_id,
        account_id=account_id,
        raw_bytes=json_bytes,
        parser=parse_masscan_json,
        source=ObservationSource.MASSCAN,
        raw_artifact_reference=raw_artifact_reference,
        dry_run=dry_run,
    )
