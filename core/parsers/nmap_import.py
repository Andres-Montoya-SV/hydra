"""Fase 11 (EASM roadmap): parses a previously-run Nmap XML scan report
into `ImportedHostRecord`s. Never invokes `nmap` itself — Hydra already
runs `nmap` as an active service-verification pass
(`modules/port_verify.py`), which is a completely separate concern; this
module only reads a file someone hands it (a customer's own scan, an
Nmap run outside Hydra) and treats it as untrusted input.

Uses `defusedxml`, never stdlib `xml.etree`, because an uploaded Nmap
report is attacker-controlled input — `xml.etree` is explicitly
documented as unsafe against XML bombs/external entity expansion.

Nmap's own product/version fingerprint (`<service product="..."
version="...">`) is carried through as-is in `ImportedPortRecord`, never
treated as ground truth beyond "this is what Nmap's service-detection
guessed" — the phase's own "el fingerprint de Nmap no se trata como
verdad absoluta" instruction. Nothing here judges or verifies it; that
distinction lives entirely in how `api/nmap_masscan_import.py` labels the
resulting evidence (`ObservationConfidenceClass.THIRD_PARTY_CURRENT`,
never `DIRECT_CURRENT`).
"""

from __future__ import annotations

# Type annotation only — actual parsing uses defusedxml.fromstring below.
from xml.etree.ElementTree import Element  # nosec B405

from defusedxml.ElementTree import ParseError, fromstring

from core.parsers.imported_hosts import ImportedHostRecord, ImportedPortRecord, ImportParseError

# Nmap's own greppable/XML report has no concept of "one host with two
# different IP families reported in the same <host> block" for a single
# scan target, so one <address> element (the first "ipv4"/"ipv6" one
# found — never a "mac" one, which Nmap also emits for local ARP scans)
# is what identifies each <host>.
_ADDRESS_TYPES = ("ipv4", "ipv6")


def _first_address(host_el: Element) -> str | None:
    """Only picks the right <address> element by `addrtype` — it does
    NOT validate that `addr` is a real, well-formed IP. That check is
    deliberately centralized once, in
    `api/nmap_masscan_import.py::_import_hosts` (via
    `api/candidate_assets.py::normalize_candidate_value`), the same
    validator every other candidate-producing path already uses, rather
    than re-implemented here and in `masscan_import.py` separately."""
    for address_el in host_el.findall("address"):
        addrtype = address_el.get("addrtype", "")
        addr = address_el.get("addr")
        if not addr:
            continue
        if addrtype in _ADDRESS_TYPES or not addrtype:
            return addr.strip()
    return None


def parse_nmap_xml(xml_bytes: bytes) -> list[ImportedHostRecord]:
    """Raises `ImportParseError` only when the artifact isn't parsable
    Nmap XML at all (bad XML syntax, wrong root element) — never for one
    bad `<host>`/`<port>` inside an otherwise valid report, which is
    silently skipped (the caller doesn't need per-host parse failures to
    know a report was garbage; it needs the report as a whole to either
    be a real Nmap XML file or not)."""
    try:
        root = fromstring(xml_bytes)
    except ParseError as exc:
        raise ImportParseError(f"malformed Nmap XML: {exc}") from exc
    except ValueError as exc:  # defusedxml raises ValueError for entity/DTD abuse
        raise ImportParseError(f"rejected Nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ImportParseError(f"not an Nmap XML report (root element is {root.tag!r})")

    hosts: list[ImportedHostRecord] = []
    for host_el in root.findall("host"):
        ip_address = _first_address(host_el)
        if ip_address is None:
            continue

        hostnames = tuple(
            sorted(
                {
                    name
                    for hn_el in host_el.findall("hostnames/hostname")
                    if (name := (hn_el.get("name") or "").strip())
                }
            )
        )

        ports: list[ImportedPortRecord] = []
        for port_el in host_el.findall("ports/port"):
            portid = port_el.get("portid")
            if portid is None:
                continue
            try:
                port_number = int(portid)
            except ValueError:
                continue
            if not (0 < port_number < 65536):
                continue
            protocol = (port_el.get("protocol") or "tcp").strip().lower()

            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else None) or "unknown"

            service_el = port_el.find("service")
            service_name = (service_el.get("name") if service_el is not None else "") or ""
            product = (service_el.get("product") if service_el is not None else "") or ""
            version = (service_el.get("version") if service_el is not None else "") or ""

            ports.append(
                ImportedPortRecord(
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    product=product,
                    version=version,
                )
            )

        hosts.append(
            ImportedHostRecord(ip_address=ip_address, hostnames=hostnames, ports=tuple(ports))
        )
    return hosts
