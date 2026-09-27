"""Fase 11 (EASM roadmap): parses a Masscan JSON report (`masscan -oJ`)
into `ImportedHostRecord`s. Masscan is imported as an observation
source, never run as an active scanner — see the roadmap's own explicit
"Masscan/RustScan como scanners activos" exclusion (section 3) and Fase
10's "Masscan nunca se agrega como scanner activo" instruction. This
module never shells out to `masscan`; it only reads a report file
someone else produced.

JSON only (Masscan's XML output is a rarer path and JSON is the
documented default for `-oJ`) — plain `json.loads`, not vulnerable to
XXE/entity-expansion the way XML is, so no extra hardening library is
needed here the way `nmap_import.py` needs `defusedxml`.
"""

from __future__ import annotations

import json

from core.parsers.imported_hosts import ImportedHostRecord, ImportedPortRecord, ImportParseError

_MAX_JSON_NESTING_ENTRIES = 500_000  # a generous cap on total port entries, not a real-world size


def parse_masscan_json(payload: bytes) -> list[ImportedHostRecord]:
    """Raises `ImportParseError` only when the artifact isn't parsable
    Masscan JSON at all (invalid JSON, or valid JSON that isn't the
    documented `-oJ` array-of-records shape). One malformed record
    inside an otherwise valid array is skipped silently, same discipline
    as `nmap_import.py`."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ImportParseError(f"not valid UTF-8: {exc}") from exc

    text = text.strip()
    if not text:
        return []

    # Masscan writes a trailing comma before the final "]" when a scan is
    # killed mid-run (its own well-known quirk, not a Hydra bug) —
    # tolerate exactly that one shape, nothing broader.
    if text.endswith(",\n]"):
        text = text[: -len(",\n]")] + "\n]"
    elif text.endswith(",]"):
        text = text[: -len(",]")] + "]"

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportParseError(f"malformed Masscan JSON: {exc}") from exc

    if not isinstance(data, list):
        raise ImportParseError("expected a JSON array of Masscan records (masscan -oJ output)")

    hosts_by_ip: dict[str, list[ImportedPortRecord]] = {}
    entries_seen = 0
    for entry in data:
        if entries_seen > _MAX_JSON_NESTING_ENTRIES:
            raise ImportParseError("Masscan report exceeds the supported number of records")
        if not isinstance(entry, dict):
            continue
        ip_address = entry.get("ip")
        if not isinstance(ip_address, str) or not ip_address.strip():
            continue
        ports_field = entry.get("ports")
        if not isinstance(ports_field, list):
            continue
        for port_entry in ports_field:
            entries_seen += 1
            if not isinstance(port_entry, dict):
                continue
            port_number = port_entry.get("port")
            if not isinstance(port_number, int) or not (0 < port_number < 65536):
                continue
            protocol = str(port_entry.get("proto") or "tcp").lower()
            status = str(port_entry.get("status") or "open").lower()
            service_field = port_entry.get("service")
            service_name = ""
            if isinstance(service_field, dict):
                service_name = str(service_field.get("name") or "")
            hosts_by_ip.setdefault(ip_address, []).append(
                ImportedPortRecord(
                    port=port_number,
                    protocol=protocol,
                    state=status,
                    service_name=service_name,
                    product="",
                    version="",
                )
            )

    return [
        ImportedHostRecord(ip_address=ip, hostnames=(), ports=tuple(ports))
        for ip, ports in hosts_by_ip.items()
    ]
