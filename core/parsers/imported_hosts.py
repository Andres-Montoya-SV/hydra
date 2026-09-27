"""Fase 11 (EASM roadmap): the shared, tool-neutral shape both the Nmap
XML parser and the Masscan JSON parser reduce their input to. One host,
identified by IP, with whatever hostnames and open ports were reported
for it — deliberately the smallest common shape both formats can fill in
without inventing per-tool fields the rest of the import pipeline
(`api/nmap_masscan_import.py`) would have to special-case.

Pure dataclasses only — no parsing logic lives here (that's each format's
own module), consistent with `api/asset_identity.py`/
`api/observation_identity.py`'s "identity/shape modules never do I/O"
discipline.
"""

from __future__ import annotations

from dataclasses import dataclass


class ImportParseError(ValueError):
    """The artifact could not be parsed as the expected format at all
    (invalid XML/JSON syntax, wrong root shape) — raised BEFORE any
    database write happens, so a caller catching this is guaranteed the
    batch left zero partial state. Individual malformed sub-records
    (one bad `<host>`, one port entry missing a required field) are
    never raised as this — they are skipped and counted by the parser
    itself, the same "skip and count, never abort the whole batch"
    discipline `api/change_backfill.py` already established."""


@dataclass(frozen=True)
class ImportedPortRecord:
    port: int
    protocol: str
    state: str
    service_name: str
    product: str
    version: str


@dataclass(frozen=True)
class ImportedHostRecord:
    ip_address: str
    hostnames: tuple[str, ...]
    ports: tuple[ImportedPortRecord, ...]
