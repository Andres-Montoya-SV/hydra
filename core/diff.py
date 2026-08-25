"""Historical scan comparison — host-set and field-level changes."""

from __future__ import annotations

import json
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
    new_relationships: list[dict[str, Any]] = field(default_factory=list)
    removed_relationships: list[dict[str, Any]] = field(default_factory=list)
    changed_relationships: list[dict[str, Any]] = field(default_factory=list)
    new_entities: list[dict[str, Any]] = field(default_factory=list)
    removed_entities: list[dict[str, Any]] = field(default_factory=list)
    new_observations: list[dict[str, Any]] = field(default_factory=list)
    removed_observations: list[dict[str, Any]] = field(default_factory=list)
    new_evidence: list[dict[str, Any]] = field(default_factory=list)
    removed_evidence: list[dict[str, Any]] = field(default_factory=list)
    indicator_changes: list[dict[str, Any]] = field(default_factory=list)
    certificate_rotations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_run_id": self.previous_run_id,
            "current_run_id": self.current_run_id,
            "new_hosts": self.new_hosts,
            "removed_hosts": self.removed_hosts,
            "new_http": self.new_http,
            "removed_http": self.removed_http,
            "field_changes": [c.to_dict() for c in self.field_changes],
            "new_relationships": self.new_relationships,
            "removed_relationships": self.removed_relationships,
            "changed_relationships": self.changed_relationships,
            "new_entities": self.new_entities,
            "removed_entities": self.removed_entities,
            "new_observations": self.new_observations,
            "removed_observations": self.removed_observations,
            "new_evidence": self.new_evidence,
            "removed_evidence": self.removed_evidence,
            "indicator_changes": self.indicator_changes,
            "certificate_rotations": self.certificate_rotations,
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
        **_intel_history_diff(store, previous_run_id, current_run_id),
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


def _intel_history_diff(
    store: AssetStore, previous_run_id: str, current_run_id: str
) -> dict[str, list[dict[str, Any]]]:
    """Compare intel tables by stable identity. Relationships remain evidence-backed."""
    rel = _intel_relationship_diff(store, previous_run_id, current_run_id)
    previous_entities = _load_intel_rows(store, "intel_entities", "entity_id", previous_run_id)
    current_entities = _load_intel_rows(store, "intel_entities", "entity_id", current_run_id)
    previous_obs = _load_intel_rows(store, "intel_observations", "observation_id", previous_run_id)
    current_obs = _load_intel_rows(store, "intel_observations", "observation_id", current_run_id)
    previous_ev = _load_intel_rows(store, "intel_evidence", "evidence_id", previous_run_id)
    current_ev = _load_intel_rows(store, "intel_evidence", "evidence_id", current_run_id)
    previous_ind = _load_intel_rows(store, "intel_indicators", "indicator_id", previous_run_id)
    current_ind = _load_intel_rows(store, "intel_indicators", "indicator_id", current_run_id)
    return {
        **rel,
        "new_entities": _appeared(current_entities, previous_entities, "ENTITY_APPEARED"),
        "removed_entities": _appeared(previous_entities, current_entities, "ENTITY_DISAPPEARED"),
        "new_observations": _appeared(current_obs, previous_obs, "OBSERVATION_APPEARED"),
        "removed_observations": _appeared(previous_obs, current_obs, "OBSERVATION_DISAPPEARED"),
        "new_evidence": _appeared(current_ev, previous_ev, "EVIDENCE_APPEARED"),
        "removed_evidence": _appeared(previous_ev, current_ev, "EVIDENCE_DISAPPEARED"),
        "indicator_changes": _indicator_changes(previous_ind, current_ind),
        "certificate_rotations": _certificate_rotations(previous_entities, current_entities),
    }


def _intel_relationship_diff(
    store: AssetStore, previous_run_id: str, current_run_id: str
) -> dict[str, list[dict[str, Any]]]:
    """Compare intel_relationships by stable evidence-backed identity."""
    previous = _load_intel_relationships(store, previous_run_id)
    current = _load_intel_relationships(store, current_run_id)
    new_ids = sorted(set(current) - set(previous))
    gone_ids = sorted(set(previous) - set(current))
    changed: list[dict[str, Any]] = []
    for rid in sorted(set(previous) & set(current)):
        old = previous[rid]
        new = current[rid]
        confidence_changed = old.get("confidence") != new.get("confidence")
        evidence_changed = old.get("evidence_id") != new.get("evidence_id")
        if confidence_changed or evidence_changed:
            change_type = "RELATIONSHIP_CHANGED"
            if confidence_changed and not evidence_changed:
                old_band = str(old.get("confidence") or "")
                new_band = str(new.get("confidence") or "")
                order = ("LOW", "MEDIUM", "HIGH", "VERY_HIGH")
                if old_band in order and new_band in order:
                    change_type = (
                        "CONFIDENCE_INCREASED"
                        if order.index(new_band) > order.index(old_band)
                        else "CONFIDENCE_DECREASED"
                    )
            elif evidence_changed and not confidence_changed:
                change_type = "EVIDENCE_CHANGED"
            changed.append(
                {
                    "relationship_id": rid,
                    "change_type": change_type,
                    "relationship_type": new.get("relationship_type"),
                    "old_confidence": old.get("confidence"),
                    "new_confidence": new.get("confidence"),
                    "old_evidence_id": old.get("evidence_id"),
                    "new_evidence_id": new.get("evidence_id"),
                    "source_entity": new.get("source_entity"),
                    "target_entity": new.get("target_entity"),
                }
            )
    return {
        "new_relationships": [
            _relationship_summary(current[rid], "RELATIONSHIP_APPEARED") for rid in new_ids
        ],
        "removed_relationships": [
            _relationship_summary(previous[rid], "RELATIONSHIP_DISAPPEARED") for rid in gone_ids
        ],
        "changed_relationships": changed,
    }


def _relationship_summary(row: dict[str, Any], change_type: str) -> dict[str, Any]:
    return {
        "relationship_id": row.get("relationship_id"),
        "change_type": change_type,
        "relationship_type": row.get("relationship_type"),
        "source_entity": row.get("source_entity"),
        "target_entity": row.get("target_entity"),
        "confidence": row.get("confidence"),
        "evidence_id": row.get("evidence_id"),
        "data": row.get("data") or {},
    }


def _load_intel_relationships(store: AssetStore, run_id: str) -> dict[str, dict[str, Any]]:
    try:
        conn = store.intel_connection()
    except Exception:
        return {}
    try:
        rows = conn.execute(
            "SELECT relationship_id, source_entity, relationship_type, target_entity, "
            "confidence, strength, evidence_id, data_json FROM intel_relationships WHERE run_id=?",
            (run_id,),
        ).fetchall()
    except Exception:
        return {}
    finally:
        conn.close()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        data = item.get("data_json")
        if data:
            try:
                item["data"] = json.loads(data)
            except (TypeError, ValueError):
                item["data"] = {}
        else:
            item["data"] = {}
        rid = str(item.get("relationship_id") or "")
        if rid:
            out[rid] = item
    return out


def _appeared(
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    change_type: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(previous)):
        row = current[key]
        out.append(
            {
                "id": key,
                "change_type": change_type,
                "entity_type": row.get("entity_type"),
                "key": row.get("key") or row.get("value"),
                "kind": row.get("kind"),
            }
        )
    return out


def _indicator_changes(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for key in sorted(set(current) - set(previous)):
        row = current[key]
        status = str(row.get("collection_status") or "")
        change_type = "INDICATOR_DISCOVERED"
        if status == "COLLECTED":
            change_type = "INDICATOR_COLLECTED"
        elif status == "FAILED":
            change_type = "INDICATOR_FAILED"
        changes.append(
            {
                "indicator_id": key,
                "change_type": change_type,
                "value": row.get("value"),
                "collection_status": status,
                "failure_reason": row.get("failure_reason"),
            }
        )
    for key in sorted(set(previous) & set(current)):
        old = previous[key]
        new = current[key]
        if old.get("collection_status") == new.get("collection_status"):
            continue
        new_status = str(new.get("collection_status") or "")
        change_type = "INDICATOR_STATUS_CHANGED"
        if new_status == "COLLECTED":
            change_type = "INDICATOR_COLLECTED"
        elif new_status == "FAILED":
            change_type = "INDICATOR_FAILED"
        changes.append(
            {
                "indicator_id": key,
                "change_type": change_type,
                "value": new.get("value"),
                "old_collection_status": old.get("collection_status"),
                "collection_status": new_status,
                "failure_reason": new.get("failure_reason"),
            }
        )
    return changes


def _certificate_rotations(
    previous: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    prev_certs = {
        key: row
        for key, row in previous.items()
        if str(row.get("entity_type") or "") == "CERTIFICATE"
    }
    curr_certs = {
        key: row
        for key, row in current.items()
        if str(row.get("entity_type") or "") == "CERTIFICATE"
    }
    out: list[dict[str, Any]] = []
    for key in sorted(set(curr_certs) - set(prev_certs)):
        out.append(
            {
                "entity_id": key,
                "change_type": "CERTIFICATE_APPEARED",
                "key": curr_certs[key].get("key"),
            }
        )
    for key in sorted(set(prev_certs) - set(curr_certs)):
        out.append(
            {
                "entity_id": key,
                "change_type": "CERTIFICATE_DISAPPEARED",
                "key": prev_certs[key].get("key"),
            }
        )
    return out


def _load_intel_rows(
    store: AssetStore, table: str, id_column: str, run_id: str
) -> dict[str, dict[str, Any]]:
    allowed = {
        "intel_entities",
        "intel_observations",
        "intel_evidence",
        "intel_indicators",
    }
    if table not in allowed:
        return {}
    try:
        conn = store.intel_connection()
    except Exception:
        return {}
    try:
        # table is checked against the allow-list above; run_id is bound, not interpolated
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE run_id=?",  # noqa: S608 # nosec B608
            (run_id,),
        ).fetchall()
    except Exception:
        return {}
    finally:
        conn.close()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        key = str(item.get(id_column) or "")
        if key:
            out[key] = item
    return out
