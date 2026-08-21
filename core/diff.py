"""Historical scan comparison."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.store import AssetStore


@dataclass
class ScanDiff:
    """Difference between two reconnaissance runs."""

    previous_run_id: str
    current_run_id: str
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_http: list[str] = field(default_factory=list)
    removed_http: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_run_id": self.previous_run_id,
            "current_run_id": self.current_run_id,
            "new_hosts": self.new_hosts,
            "removed_hosts": self.removed_hosts,
            "new_http": self.new_http,
            "removed_http": self.removed_http,
        }


def diff_runs(
    store: AssetStore, current_run_id: str, previous_run_id: str | None = None
) -> ScanDiff | None:
    """Compare current run against previous run."""
    run_ids = store.get_run_ids()
    if not run_ids:
        return None

    if previous_run_id is None:
        others = [r for r in run_ids if r != current_run_id]
        if not others:
            return None
        previous_run_id = others[0]

    current_hosts = {h.domain for h in store.get_hosts(current_run_id)}
    previous_hosts = {h.domain for h in store.get_hosts(previous_run_id)}

    diff = ScanDiff(
        previous_run_id=previous_run_id,
        current_run_id=current_run_id,
        new_hosts=sorted(current_hosts - previous_hosts),
        removed_hosts=sorted(previous_hosts - current_hosts),
    )
    return diff
