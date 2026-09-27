"""Fase 14 (EASM roadmap): deterministic classification of what changed
in a domain's technology inventory between two consecutive runs. Pure
module — no database access, no clock.

Unlike a certificate (one active certificate per domain at a time), a
domain can run many technologies simultaneously, so a "snapshot" here is
a `{canonical_name: version}` mapping — the full set of distinct
technologies one run observed for one domain — rather than a single
value. Comparing two such mappings by set difference is what makes
`TECHNOLOGY_ADDED`/`TECHNOLOGY_REMOVED` well-defined: a technology
present in the earlier run but absent from the later one was removed
(or simply stopped being detected — the reason text says exactly which);
one absent before and present now was added; one present in both with a
different version was a `TECHNOLOGY_VERSION_CHANGED`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TechnologyEventType(str, Enum):
    ADDED = "TECHNOLOGY_ADDED"
    REMOVED = "TECHNOLOGY_REMOVED"
    VERSION_CHANGED = "TECHNOLOGY_VERSION_CHANGED"


@dataclass(frozen=True)
class TechnologyEvent:
    event_type: TechnologyEventType
    technology_name: str
    reason: str


def _describe(name: str, version: str | None) -> str:
    return f"{name} {version}" if version else name


def classify_technology_transition(
    *, previous: dict[str, str | None] | None, current: dict[str, str | None]
) -> list[TechnologyEvent]:
    """Deterministic and explainable: every event cites the concrete
    technology (and version, when known) that produced it. `previous is
    None` (the very first run this domain was ever observed with) treats
    every currently-detected technology as newly `ADDED` — there is no
    "before" to compare against, so nothing can be reported as changed or
    removed."""
    if previous is None:
        return [
            TechnologyEvent(
                TechnologyEventType.ADDED, name, f"first observed: {_describe(name, current[name])}"
            )
            for name in sorted(current)
        ]

    events: list[TechnologyEvent] = []
    for name in sorted(set(current) - set(previous)):
        events.append(
            TechnologyEvent(
                TechnologyEventType.ADDED, name, f"newly observed: {_describe(name, current[name])}"
            )
        )
    for name in sorted(set(previous) - set(current)):
        events.append(
            TechnologyEvent(
                TechnologyEventType.REMOVED,
                name,
                f"no longer observed: {_describe(name, previous[name])}",
            )
        )
    for name in sorted(set(current) & set(previous)):
        if current[name] != previous[name]:
            events.append(
                TechnologyEvent(
                    TechnologyEventType.VERSION_CHANGED,
                    name,
                    f"{name} version changed: {previous[name]!r} -> {current[name]!r}",
                )
            )
    return events
