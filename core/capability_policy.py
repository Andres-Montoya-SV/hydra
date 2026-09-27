"""Fase 17 (EASM roadmap): capability-level enable/disable policy.

**A policy never authorizes anything** — the phase's own explicit
invariant ("una política nunca autoriza"). This module only ever narrows
whether a provider's own `is_enabled()`/per-tool feature flag is allowed
to take effect; it can turn a capability OFF, never ON, and it never
touches `CollectionGateway`/`ScopeEnforcingProxy`/scope authorization in
any way.

**Backward-compatible with every existing per-tool flag, deliberately not
replacing them** (the phase's own "capa de compatibilidad para los flags
actuales, sin eliminarlos todavía" requirement): every one of the ~30
`config.settings.Settings.enable_<tool>` booleans keeps meaning exactly
what it already means. This module adds one NEW, coarser lever on top —
"disable the whole Cloud capability" — without removing or reinterpreting
any existing flag. `capability_enabled()` is a pure function over an
explicit `disabled_capabilities` set (not read from `Settings`/env in
this cut — see `docs/easm/17_capability_architecture.md` for why keeping
this out of the heavily-relied-on `config/settings.py` was the safer,
narrower scope for a first pass); a real config/CLI surface for setting
that set is a small, separate follow-up, not a reason to block this
layer's own correctness.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.capabilities import Capability, capability_for
from core.plugin_base import ReconPlugin


def capability_enabled(
    capability: Capability,
    *,
    plugins: Iterable[ReconPlugin],
    disabled_capabilities: frozenset[Capability] = frozenset(),
) -> bool:
    """A capability is enabled iff it is not explicitly disabled by
    policy AND at least one of its underlying providers is itself
    enabled (its own existing `is_enabled()` — never re-implemented or
    bypassed here). `plugins` are already-instantiated `ReconPlugin`
    objects (their `.is_enabled()` needs a live `Settings`, which this
    pure function never constructs itself) — callers pass
    `ToolManager(settings).get_all_plugins()`'s own result."""
    if capability in disabled_capabilities:
        return False
    for plugin in plugins:
        if capability_for(plugin.capability) != capability:
            continue
        if plugin.is_enabled():
            return True
    return False


def providers_for_capability(
    capability: Capability, *, plugin_classes: Iterable[type[ReconPlugin]]
) -> list[type[ReconPlugin]]:
    """Every registered provider class belonging to one capability
    category — the replaceability guarantee made concrete: swapping one
    of these for another provider of the same real-world function never
    changes which `Capability` this list answers for."""
    return [cls for cls in plugin_classes if capability_for(cls.capability) == capability]
