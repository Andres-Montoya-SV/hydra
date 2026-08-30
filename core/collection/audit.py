"""Durable, per-destination network authorization audit trail.

`intel_collection_attempts` records one row per plugin-capability attempt
(e.g. "dnsx tried to resolve this host"). It does not capture the
finer-grained decisions made *inside* a single plugin invocation — every hop
httpx's redirect resolver evaluates, or every connection the crawler-
confinement proxy allows or refuses. Those decisions previously lived only
in memory (`ScopeEnforcingProxy.denied`/`.allowed_hosts`) or as free-text
`context.add_warning(...)` messages — real, but not queryable from SQLite
after the run ends.

`NetworkRequestRecord` is the row shape for `intel_network_requests`
(`core/store.py`). Accumulate instances' `.to_dict()` into
`context.metadata["network_requests"]`; `core/runner.py` persists that list
at finalize via `AssetStore.record_network_requests`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NetworkRequestRecord:
    collector: str
    url: str
    decision: str  # "ALLOW" | "DENY"
    reason: str = ""
    capability: str = ""
    method: str = "GET"
    normalized_hostname: str = ""
    resolved_ip: str = ""
    port: int | None = None
    redirect_hop: int = 0
    network_attempted: bool = False
    network_completed: bool = False
    response_status: int | None = None
    response_location: str = ""
    parent_request_id: str = ""
    observed_at: str = ""
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "collector": self.collector,
            "capability": self.capability,
            "method": self.method,
            "url": self.url,
            "normalized_hostname": self.normalized_hostname,
            "resolved_ip": self.resolved_ip,
            "port": self.port,
            "redirect_hop": self.redirect_hop,
            "decision": self.decision,
            "reason": self.reason,
            "network_attempted": self.network_attempted,
            "network_completed": self.network_completed,
            "response_status": self.response_status,
            "response_location": self.response_location,
            "parent_request_id": self.parent_request_id,
            "observed_at": self.observed_at,
        }


def append_network_request(context: object, record: NetworkRequestRecord) -> None:
    """Accumulate one audit record onto `context.metadata["network_requests"]`."""
    metadata = getattr(context, "metadata", None)
    if not isinstance(metadata, dict):
        return
    bucket = metadata.setdefault("network_requests", [])
    if isinstance(bucket, list):
        bucket.append(record.to_dict())
