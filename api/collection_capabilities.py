"""Per-organization collection capabilities (Productization Roadmap v2,
"Capability & Tool Access").

Which optional providers may run is now organization state, not the
process-global `ENABLE_*` flags: an organization default, optionally
overridden for a single scan, always clipped to the tier's ceiling
(`api/tiers.py::TIER_PROVIDER_INTENSITIES`).

Enablement is NOT authorization. It only narrows what may be collected
within a scope that was already authorized by domain verification; nothing
here can widen which targets a scan may reach.

Required providers (the base pipeline: subdomain enumeration, DNS
resolution, HTTP probing) have no `enable_*` flag and always run — they are
not part of any capability set and can't be toggled.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from functools import lru_cache
from typing import TYPE_CHECKING

from api.tiers import TIER_PROVIDER_INTENSITIES

if TYPE_CHECKING:
    from config.settings import Settings


@dataclass(frozen=True)
class ProviderInfo:
    name: str
    capability: str
    intensity: str
    required: bool
    default_enabled: bool
    produces: tuple[str, ...]


class CapabilityRequestError(ValueError):
    """A requested provider set that can never be valid, regardless of
    tier: an unknown provider, or a required one (always on, not toggleable)."""


@lru_cache(maxsize=1)
def provider_catalog() -> dict[str, ProviderInfo]:
    """Every registered provider with its capability, intensity, and the
    default `enable_*` value. Imports the plugin registry, so it is only
    called lazily (routers/orchestrator), and cached for the process."""
    import modules  # noqa: F401 - registers every ReconPlugin subclass
    from config.settings import Settings
    from core.plugin_base import ReconPlugin
    from core.provider_contract import provider_descriptor

    defaults = {f.name: f.default for f in fields(Settings) if f.name.startswith("enable_")}
    catalog: dict[str, ProviderInfo] = {}
    for cls in ReconPlugin.all_plugins():
        descriptor = provider_descriptor(cls)
        flag = f"enable_{cls.name}"
        catalog[cls.name] = ProviderInfo(
            name=cls.name,
            capability=descriptor.capability.value,
            intensity=descriptor.intensity.value,
            required=flag not in defaults,
            default_enabled=bool(defaults.get(flag, True)),
            produces=descriptor.produces,
        )
    return catalog


def optional_providers() -> frozenset[str]:
    return frozenset(name for name, info in provider_catalog().items() if not info.required)


def builtin_default() -> frozenset[str]:
    """The optional providers on by default when an organization has never
    saved its own set — identical to today's per-account settings."""
    return frozenset(
        name
        for name, info in provider_catalog().items()
        if not info.required and info.default_enabled
    )


def tier_ceiling(tier: str) -> frozenset[str]:
    allowed = next((v for k, v in TIER_PROVIDER_INTENSITIES.items() if k == tier), None)
    if allowed is None:
        raise ValueError(f"unknown tier {tier!r}")
    return frozenset(
        name
        for name, info in provider_catalog().items()
        if not info.required and info.intensity in allowed
    )


def validate_requested(providers: list[str]) -> frozenset[str]:
    """Normalizes and checks a requested provider set. Raises
    `CapabilityRequestError` for unknown or required providers; entitlement
    (tier) is a separate, later check with its own typed error."""
    catalog = provider_catalog()
    requested = frozenset(p.strip() for p in providers)
    unknown = sorted(p for p in requested if p not in catalog)
    if unknown:
        raise CapabilityRequestError(f"unknown provider(s): {', '.join(unknown)}")
    required = sorted(p for p in requested if catalog[p].required)
    if required:
        raise CapabilityRequestError(
            f"always-on provider(s) can't be toggled: {', '.join(required)}"
        )
    return requested


def not_entitled(requested: frozenset[str], tier: str) -> list[str]:
    return sorted(requested - tier_ceiling(tier))


def resolve_scan_providers(
    *,
    override: frozenset[str] | None,
    org_default: frozenset[str] | None,
    current: frozenset[str],
    tier: str,
) -> frozenset[str]:
    """The providers a scan runs with: its own override if it has one, else
    the organization's saved default, else what the account's settings
    already enable — always clipped to the tier's ceiling. Clipping matters
    only when a tier was lowered after the set was saved or the scan was
    queued; requests are rejected up front when they exceed the ceiling."""
    if override is not None:
        requested = override
    elif org_default is not None:
        requested = org_default
    else:
        requested = current
    return requested & tier_ceiling(tier)


def enabled_in_settings(settings: Settings) -> frozenset[str]:
    return frozenset(p for p in optional_providers() if getattr(settings, f"enable_{p}", False))


def apply_to_settings(settings: Settings, enabled: frozenset[str]) -> None:
    """Sets every optional provider's `enable_*` flag to exactly `enabled`."""
    for provider in optional_providers():
        setattr(settings, f"enable_{provider}", provider in enabled)


def hostname_producers() -> frozenset[str]:
    """Providers whose output includes hostnames — the only ones whose
    failure can make hosts disappear from a run."""
    return frozenset(
        name for name, info in provider_catalog().items() if "domains" in info.produces
    )
