"""Historical scan comparison — host-set and field-level changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.assets import Host
from core.store import AssetStore


@dataclass
class FieldChange:
    """A single field-level difference on a shared host/entity."""

    entity: str
    field: str
    change_type: str
    old: Any
    new: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "field": self.field,
            "change_type": self.change_type,
            "old": self.old,
            "new": self.new,
        }


@dataclass
class ScanDiff:
    """Difference between two reconnaissance runs."""

    previous_run_id: str
    current_run_id: str
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_http: list[str] = field(default_factory=list)
    removed_http: list[str] = field(default_factory=list)
    field_changes: list[FieldChange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_run_id": self.previous_run_id,
            "current_run_id": self.current_run_id,
            "new_hosts": self.new_hosts,
            "removed_hosts": self.removed_hosts,
            "new_http": self.new_http,
            "removed_http": self.removed_http,
            "field_changes": [c.to_dict() for c in self.field_changes],
        }


def diff_runs(
    store: AssetStore, current_run_id: str, previous_run_id: str | None = None
) -> ScanDiff | None:
    """Compare current run against a previous run with overlapping targets."""
    if previous_run_id is None:
        previous_run_id = store.find_previous_run(current_run_id)
    if not previous_run_id:
        return None

    current_hosts = {h.domain: h for h in store.get_hosts(current_run_id)}
    previous_hosts = {h.domain: h for h in store.get_hosts(previous_run_id)}

    current_http = _http_urls(current_hosts)
    previous_http = _http_urls(previous_hosts)
    # new_http / removed_http are the HTTP URL set, populated from persisted
    # HttpService.url values only — never inferred.

    diff = ScanDiff(
        previous_run_id=previous_run_id,
        current_run_id=current_run_id,
        new_hosts=sorted(set(current_hosts) - set(previous_hosts)),
        removed_hosts=sorted(set(previous_hosts) - set(current_hosts)),
        new_http=sorted(current_http - previous_http),
        removed_http=sorted(previous_http - current_http),
        field_changes=_field_changes(previous_hosts, current_hosts),
    )
    return diff


def _http_urls(hosts: dict[str, Host]) -> set[str]:
    urls: set[str] = set()
    for host in hosts.values():
        for svc in host.http_services:
            if svc.url:
                urls.add(svc.url)
    return urls


def _field_changes(previous: dict[str, Host], current: dict[str, Host]) -> list[FieldChange]:
    changes: list[FieldChange] = []
    for domain in sorted(set(previous) & set(current)):
        old = previous[domain]
        new = current[domain]
        changes.extend(_host_field_changes(domain, old, new))
    return changes


def _host_field_changes(domain: str, old: Host, new: Host) -> list[FieldChange]:
    out: list[FieldChange] = []

    def add(field: str, change_type: str, old_value: Any, new_value: Any) -> None:
        if old_value != new_value:
            out.append(
                FieldChange(
                    entity=domain,
                    field=field,
                    change_type=change_type,
                    old=old_value,
                    new=new_value,
                )
            )

    old_v4 = sorted(ip for ip in old.ips if ":" not in ip)
    new_v4 = sorted(ip for ip in new.ips if ":" not in ip)
    old_v6 = sorted(ip for ip in old.ips if ":" in ip)
    new_v6 = sorted(ip for ip in new.ips if ":" in ip)
    add("ip", "IP_CHANGED", sorted(old.ips), sorted(new.ips))
    add("ipv4", "IPV4_CHANGED", old_v4, new_v4)
    add("ipv6", "IPV6_CHANGED", old_v6, new_v6)

    old_fp = old.tls.fingerprint_sha256 if old.tls else None
    new_fp = new.tls.fingerprint_sha256 if new.tls else None
    add("certificate_fingerprint", "CERTIFICATE_CHANGED", old_fp, new_fp)

    old_sans = set(old.tls.sans) if old.tls else set()
    new_sans = set(new.tls.sans) if new.tls else set()
    added = sorted(new_sans - old_sans)
    removed = sorted(old_sans - new_sans)
    if added:
        out.append(FieldChange(domain, "certificate_san_set", "SAN_ADDED", sorted(old_sans), added))
    if removed:
        out.append(
            FieldChange(domain, "certificate_san_set", "SAN_REMOVED", removed, sorted(new_sans))
        )
    add(
        "certificate_validity",
        "CERTIFICATE_VALIDITY_CHANGED",
        old.tls.not_after if old.tls else None,
        new.tls.not_after if new.tls else None,
    )

    old_ports = sorted((p.port, p.protocol) for p in old.ports)
    new_ports = sorted((p.port, p.protocol) for p in new.ports)
    add("ports", "PORTS_CHANGED", old_ports, new_ports)

    old_http = _primary_http(old)
    new_http = _primary_http(new)
    add("http_status", "HTTP_STATUS_CHANGED", old_http.get("status"), new_http.get("status"))
    add("http_title", "HTTP_TITLE_CHANGED", old_http.get("title"), new_http.get("title"))
    add("technologies", "TECHNOLOGIES_CHANGED", old_http.get("tech"), new_http.get("tech"))
    add("favicon_hash", "FAVICON_CHANGED", old_http.get("favicon"), new_http.get("favicon"))
    add("body_hash", "BODY_HASH_CHANGED", old_http.get("body"), new_http.get("body"))
    add("asn", "ASN_CHANGED", old.asn, new.asn)

    old_ns = sorted(rec.value for rec in old.dns_records if rec.record_type == "NS" and rec.value)
    new_ns = sorted(rec.value for rec in new.dns_records if rec.record_type == "NS" and rec.value)
    add("nameserver", "NAMESERVER_CHANGED", old_ns, new_ns)
    return out


def _primary_http(host: Host) -> dict[str, Any]:
    if not host.http_services:
        return {}
    svc = host.http_services[0]
    return {
        "status": svc.status_code,
        "title": svc.title,
        "tech": sorted(svc.tech_names()) if hasattr(svc, "tech_names") else [],
        "favicon": svc.favicon_hash,
        "body": svc.body_hash,
    }
