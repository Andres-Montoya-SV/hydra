"""Project run-scoped Hydra host state into persistent EASM state.

The projector is intentionally pure with respect to collection: it consumes
already-normalized ``Host`` objects and writes persistent asset observations and
change events.  It never authorizes or performs network activity.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from core.assets import Host
from core.easm.model import AssetEventType, AssetType
from core.easm.store import EasmStore

PROJECTOR_VERSION = "host-state-v1"


@dataclass(frozen=True)
class ProjectionResult:
    run_id: str
    organization_id: str
    assets_seen: int
    observations_written: int
    events_written: int
    skipped: bool = False


def _port_key(port: Any) -> str:
    return f"{int(port.port)}/{str(port.protocol or 'tcp').lower()}"


def _technology_names(host: Host) -> list[str]:
    names: set[str] = set()
    for service in host.http_services:
        for technology in service.technologies:
            name = (technology.name or "").strip().lower()
            if name:
                names.add(name)
    return sorted(names)


def _http_state(host: Host) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for service in host.http_services:
        rows.append(
            {
                "url": service.url,
                "status_code": service.status_code,
                "title": service.title,
                "webserver": service.webserver,
                "tls_version": service.tls_version,
                "response_fingerprint": service.response_fingerprint,
            }
        )
    return sorted(rows, key=lambda row: str(row["url"]))


def host_state(host: Host) -> dict[str, Any]:
    """Return the stable, comparison-oriented state for one Host.

    Raw provenance and noisy timestamps intentionally stay out of this state so
    two semantically-identical runs produce the same transition comparison.
    """

    tls = host.tls
    return {
        "domain": host.domain,
        "ips": sorted(set(host.ips)),
        "dns_records": sorted(
            {
                f"{record.record_type.upper()}:{record.value}"
                for record in host.dns_records
                if record.record_type and record.value
            }
        ),
        "ports": sorted({_port_key(port) for port in host.ports}),
        "technologies": _technology_names(host),
        "http": _http_state(host),
        "certificate": (
            {
                "fingerprint_sha256": tls.fingerprint_sha256,
                "issuer": tls.issuer,
                "subject": tls.subject,
                "sans": sorted(set(tls.sans)),
                "not_before": tls.not_before,
                "not_after": tls.not_after,
            }
            if tls is not None
            else None
        ),
        "asn": host.asn,
        "nameservers": sorted(set(host.nameservers)),
        "cloud_provider": host.cloud_provider,
        "risk": {
            "level": host.risk_level.value,
            "score": host.risk_score,
        },
    }


def _load_previous_state(
    conn: sqlite3.Connection,
    *,
    asset_id: str,
    observed_at: str,
) -> tuple[dict[str, Any] | None, bool]:
    """Load the closest observation before ``observed_at``.

    Returns ``(state, has_future)``.  ``has_future`` tells the caller that a
    newer observation already exists.  In that case this projection is a
    historical backfill: the observation is persisted, but transition events
    are not emitted because comparing it with future state would manufacture a
    false chronology.
    """

    previous = conn.execute(
        """
        SELECT data_json FROM easm_asset_observations
        WHERE asset_id = ? AND observed_at < ?
        ORDER BY observed_at DESC, observation_id DESC
        LIMIT 1
        """,
        (asset_id, observed_at),
    ).fetchone()
    future = conn.execute(
        """
        SELECT 1 FROM easm_asset_observations
        WHERE asset_id = ? AND observed_at > ?
        LIMIT 1
        """,
        (asset_id, observed_at),
    ).fetchone()
    state = json.loads(previous[0]) if previous is not None else None
    return state, future is not None


def _emit_set_changes(
    store: EasmStore,
    *,
    organization_id: str,
    asset_id: str,
    observation_id: str,
    observed_at: str,
    previous: dict[str, Any],
    current: dict[str, Any],
    key: str,
    opened_type: AssetEventType,
    closed_type: AssetEventType,
    severity: str | None = None,
) -> int:
    before = set(previous.get(key) or [])
    after = set(current.get(key) or [])
    count = 0
    for value in sorted(after - before):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=opened_type,
            detected_at=observed_at,
            confidence=100,
            severity=severity,
            source_observation_id=observation_id,
            previous_state={key: sorted(before)},
            current_state={key: sorted(after), "changed_value": value},
        )
        count += 1
    for value in sorted(before - after):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=closed_type,
            detected_at=observed_at,
            confidence=100,
            severity=severity,
            source_observation_id=observation_id,
            previous_state={key: sorted(before), "changed_value": value},
            current_state={key: sorted(after)},
        )
        count += 1
    return count


def _emit_transition_events(
    store: EasmStore,
    *,
    organization_id: str,
    asset_id: str,
    observation_id: str,
    observed_at: str,
    previous: dict[str, Any],
    current: dict[str, Any],
) -> int:
    count = 0

    previous_ips = previous.get("ips") or []
    current_ips = current.get("ips") or []
    if previous_ips != current_ips:
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=AssetEventType.IP_CHANGED,
            detected_at=observed_at,
            confidence=100,
            source_observation_id=observation_id,
            previous_state={"ips": previous_ips},
            current_state={"ips": current_ips},
        )
        count += 1

    count += _emit_set_changes(
        store,
        organization_id=organization_id,
        asset_id=asset_id,
        observation_id=observation_id,
        observed_at=observed_at,
        previous=previous,
        current=current,
        key="ports",
        opened_type=AssetEventType.PORT_OPENED,
        closed_type=AssetEventType.PORT_CLOSED,
        severity="medium",
    )

    if (previous.get("dns_records") or []) != (current.get("dns_records") or []):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=AssetEventType.DNS_CHANGED,
            detected_at=observed_at,
            confidence=100,
            source_observation_id=observation_id,
            previous_state={"dns_records": previous.get("dns_records") or []},
            current_state={"dns_records": current.get("dns_records") or []},
        )
        count += 1

    if (previous.get("technologies") or []) != (current.get("technologies") or []):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=AssetEventType.TECHNOLOGY_CHANGED,
            detected_at=observed_at,
            confidence=90,
            source_observation_id=observation_id,
            previous_state={"technologies": previous.get("technologies") or []},
            current_state={"technologies": current.get("technologies") or []},
        )
        count += 1

    if previous.get("http") != current.get("http"):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=AssetEventType.HTTP_CHANGED,
            detected_at=observed_at,
            confidence=90,
            source_observation_id=observation_id,
            previous_state={"http": previous.get("http") or []},
            current_state={"http": current.get("http") or []},
        )
        count += 1

    if previous.get("certificate") != current.get("certificate"):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=AssetEventType.CERTIFICATE_CHANGED,
            detected_at=observed_at,
            confidence=95,
            source_observation_id=observation_id,
            previous_state={"certificate": previous.get("certificate")},
            current_state={"certificate": current.get("certificate")},
        )
        count += 1

    if previous.get("risk") != current.get("risk"):
        store.record_event(
            organization_id=organization_id,
            asset_id=asset_id,
            event_type=AssetEventType.RISK_CHANGED,
            detected_at=observed_at,
            confidence=100,
            source_observation_id=observation_id,
            previous_state={"risk": previous.get("risk")},
            current_state={"risk": current.get("risk")},
        )
        count += 1

    return count


def project_hosts(
    conn: sqlite3.Connection,
    *,
    organization_id: str,
    run_id: str,
    hosts: Iterable[Host],
    projected_at: str | None = None,
) -> ProjectionResult:
    """Project one completed Hydra run into persistent EASM state.

    Projection is idempotent per ``(organization_id, run_id,
    PROJECTOR_VERSION)``.  Existing run-scoped tables remain authoritative raw
    input; this layer is a derived persistent view.
    """

    store = EasmStore(conn)
    already = conn.execute(
        """
        SELECT 1 FROM easm_run_projections
        WHERE organization_id = ? AND run_id = ? AND projector_version = ?
        """,
        (organization_id, run_id, PROJECTOR_VERSION),
    ).fetchone()
    if already is not None:
        return ProjectionResult(run_id, organization_id, 0, 0, 0, skipped=True)

    run_exists = conn.execute(
        "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if run_exists is None:
        raise ValueError(f"unknown run_id: {run_id}")

    assets_seen = observations_written = events_written = 0
    ordered_hosts = sorted(hosts, key=lambda host: host.domain)

    for host in ordered_hosts:
        observed_at = host.scan_timestamp or host.last_seen
        if not observed_at:
            raise ValueError(f"host {host.domain!r} has no observation timestamp")

        state = host_state(host)
        # Resolve stable identity before reading history. ``upsert_asset`` also
        # maintains first_seen/last_seen monotonically for backfills.
        asset_id, created = store.upsert_asset(
            organization_id=organization_id,
            asset_type=AssetType.HOSTNAME,
            canonical_key=host.domain,
            display_name=host.domain,
            seen_at=observed_at,
            metadata={"root_domain": host.root_domain, "hostname": host.hostname},
        )
        assets_seen += 1

        previous, has_future = _load_previous_state(
            conn, asset_id=asset_id, observed_at=observed_at
        )
        observation_id = store.record_observation(
            asset_id=asset_id,
            run_id=run_id,
            source="hydra_host_projection",
            collector=PROJECTOR_VERSION,
            confidence=max(0, min(100, host.confidence_score)),
            observed_at=observed_at,
            data=state,
        )
        observations_written += 1

        if created:
            # ``upsert_asset`` emitted NEW_ASSET. Count it as projector output.
            events_written += 1
        elif previous is not None and not has_future:
            events_written += _emit_transition_events(
                store,
                organization_id=organization_id,
                asset_id=asset_id,
                observation_id=observation_id,
                observed_at=observed_at,
                previous=previous,
                current=state,
            )

    conn.execute(
        """
        INSERT INTO easm_run_projections(
            organization_id, run_id, projector_version, projected_at,
            asset_count, observation_count, event_count
        ) VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?)
        """,
        (
            organization_id,
            run_id,
            PROJECTOR_VERSION,
            projected_at,
            assets_seen,
            observations_written,
            events_written,
        ),
    )
    return ProjectionResult(
        run_id=run_id,
        organization_id=organization_id,
        assets_seen=assets_seen,
        observations_written=observations_written,
        events_written=events_written,
    )
