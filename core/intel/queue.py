"""Bounded, deduplicating indicator queue with real state transitions."""

from __future__ import annotations

from dataclasses import dataclass

from core.intel.bounds import DiscoveryBounds
from core.intel.model import (
    CollectionStatus,
    CollectReason,
    Indicator,
    IndicatorKind,
    ScopeStatus,
    stable_id,
)
from core.intel.scope import scope_status_allows_collection

_TERMINAL = frozenset(
    {
        CollectionStatus.COLLECTED,
        CollectionStatus.NOT_ALLOWED,
        CollectionStatus.REJECTED,
        CollectionStatus.FAILED,
    }
)


@dataclass(frozen=True)
class StatusTransition:
    value: str
    previous: str
    current: str
    reason: str


class IndicatorQueue:
    """Deduped indicators with depth, scope, and collection status."""

    def __init__(self, bounds: DiscoveryBounds) -> None:
        self.bounds = bounds
        self._items: dict[str, Indicator] = {}
        self._per_source: dict[str, int] = {}
        self.followups_enqueued = 0
        self.budget_used = 0
        self.trace: list[StatusTransition] = []

    def __len__(self) -> int:
        return len(self._items)

    def values(self) -> list[Indicator]:
        return list(self._items.values())

    def get(self, kind: IndicatorKind, value: str) -> Indicator | None:
        return self._items.get(_key(kind, value))

    def add(
        self,
        *,
        kind: IndicatorKind,
        value: str,
        depth: int,
        parent_id: str | None,
        reason: CollectReason,
        scope_status: ScopeStatus,
        evidence_id: str,
        discovered_from: str = "",
        collected: bool = False,
        is_seed: bool = False,
        priority: int = 100,
    ) -> Indicator:
        key = _key(kind, value)
        existing = self._items.get(key)
        if existing:
            if collected and scope_status_allows_collection(existing.scope_status):
                self._transition(existing, CollectionStatus.COLLECTED, "mark_collected_on_add")
            if is_seed:
                existing.priority = min(existing.priority, 0)
            if depth < existing.depth:
                existing.depth = depth
                existing.parent_id = parent_id
            return existing

        if collected and scope_status_allows_collection(scope_status):
            status = CollectionStatus.COLLECTED
        elif not scope_status_allows_collection(scope_status):
            status = CollectionStatus.NOT_ALLOWED
        elif depth > self.bounds.max_discovery_depth:
            status = CollectionStatus.REJECTED
        elif not is_seed and self._source_full(discovered_from or parent_id or ""):
            status = CollectionStatus.REJECTED
        else:
            status = CollectionStatus.ELIGIBLE

        indicator = Indicator(
            indicator_id=stable_id("indicator", kind.value, value),
            kind=kind,
            value=value,
            depth=depth,
            parent_id=parent_id,
            reason=reason,
            scope_status=scope_status,
            collection_status=status,
            evidence_id=evidence_id,
            priority=0 if is_seed else priority,
            discovered_from=discovered_from,
        )
        self._items[key] = indicator
        self.trace.append(
            StatusTransition(value, "", status.value, reason.value if reason else "add")
        )
        if status is CollectionStatus.ELIGIBLE and not is_seed:
            source = discovered_from or parent_id or ""
            self._per_source[source] = self._per_source.get(source, 0) + 1
        if status is CollectionStatus.COLLECTED and not is_seed:
            self.budget_used += 1
        return indicator

    def mark_collected(self, kind: IndicatorKind, value: str) -> None:
        """Mark COLLECTED only when the indicator is authorized for probing."""
        item = self.get(kind, value)
        if item is None:
            return
        if not scope_status_allows_collection(item.scope_status):
            return
        if item.collection_status in {CollectionStatus.NOT_ALLOWED, CollectionStatus.REJECTED}:
            return
        self._transition(item, CollectionStatus.COLLECTED, "collected")

    def mark_rejected(self, kind: IndicatorKind, value: str, *, reason: str = "rejected") -> None:
        item = self.get(kind, value)
        if item is None:
            return
        if item.collection_status is CollectionStatus.COLLECTED:
            return
        self._transition(item, CollectionStatus.REJECTED, reason)

    def mark_failed(self, kind: IndicatorKind, value: str, *, reason: str = "failed") -> None:
        item = self.get(kind, value)
        if item is None:
            return
        if item.collection_status is CollectionStatus.IN_FLIGHT:
            self._transition(item, CollectionStatus.FAILED, reason)

    def eligible_followups(self, kind: IndicatorKind | None = None) -> list[Indicator]:
        """Claim ELIGIBLE indicators as IN_FLIGHT. A second call returns nothing new."""
        if not self.bounds.enable_followup_collection:
            return []
        candidates = [
            item
            for item in self._items.values()
            if item.collection_status is CollectionStatus.ELIGIBLE
            and scope_status_allows_collection(item.scope_status)
            and item.depth >= 1
            and item.depth <= self.bounds.max_discovery_depth
            and (kind is None or item.kind is kind)
        ]
        candidates.sort(key=lambda i: (i.priority, i.depth, i.value))
        remaining = max(0, self.bounds.max_followup_indicators - self.followups_enqueued)
        budget_left = max(0, self.bounds.max_collection_budget - self.budget_used)
        chosen = candidates[: min(remaining, budget_left)]
        self.followups_enqueued += len(chosen)
        self.budget_used += len(chosen)
        for item in chosen:
            self._transition(item, CollectionStatus.IN_FLIGHT, "claimed")
        return chosen

    def _source_full(self, source: str) -> bool:
        return self._per_source.get(source, 0) >= self.bounds.max_domains_per_source

    def _transition(self, item: Indicator, new: CollectionStatus, reason: str) -> None:
        if item.collection_status is new:
            return
        if item.collection_status in _TERMINAL:
            return
        previous = item.collection_status
        item.collection_status = new
        self.trace.append(StatusTransition(item.value, previous.value, new.value, reason))


def _key(kind: IndicatorKind, value: str) -> str:
    return f"{kind.value}:{value.lower()}"
