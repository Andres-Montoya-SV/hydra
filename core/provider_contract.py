"""Minimal EASM provider contract (Fase 09).

This module does not replace the dependency registry or ReconPlugin. It projects
those existing declarations into product-level provider metadata and owns the
small execution-outcome vocabulary required by later EASM phases.

Dependency capabilities ("binary supports X") and EASM product capabilities
("Hydra offers Technology Intelligence") remain distinct concepts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Literal

import modules  # noqa: F401  # register ReconPlugin subclasses
from core.capabilities import Capability, capability_for
from core.collection.crawler_proxy import PROXY_VERIFIED_TOOLS
from core.dependencies.registry import get_tool_definition
from core.models import ToolInfo, ToolStatus
from core.plugin_base import PluginResult, ReconPlugin


class ProviderKind(str, Enum):
    DISCOVERY = "discovery"
    INTELLIGENCE = "intelligence"
    EXPOSURE = "exposure"
    IMPORT = "import"


class ProviderIntensity(str, Enum):
    """Fase 17 (EASM roadmap): cost/intensity metadata, deliberately NOT
    a billing engine — just enough for a future policy or scheduler
    (Fase 18's own concern) to distinguish "safe to run on every cycle"
    from "expensive, use sparingly.\" """

    PASSIVE = "passive"
    ACTIVE_STANDARD = "active_standard"
    ACTIVE_HIGH_VOLUME = "active_high_volume"
    THIRD_PARTY_API = "third_party_api"
    LLM_BACKED = "llm_backed"


# Intensity is a property of the SPECIFIC tool, not of its capability
# category (two Domain Discovery providers can have very different
# costs) -- keyed by plugin name. A plugin missing here falls back to
# ACTIVE_STANDARD/PASSIVE by `active_collection`, never guessed beyond
# that binary split (see `_intensity` below).
_INTENSITY_OVERRIDES: dict[str, ProviderIntensity] = {
    "amass": ProviderIntensity.PASSIVE,
    "assetfinder": ProviderIntensity.PASSIVE,
    "subfinder": ProviderIntensity.PASSIVE,
    "asn_lookup": ProviderIntensity.PASSIVE,
    "anew": ProviderIntensity.PASSIVE,
    "unfurl": ProviderIntensity.PASSIVE,
    "vuln_match": ProviderIntensity.PASSIVE,
    "security_headers": ProviderIntensity.PASSIVE,
    "ctlogs": ProviderIntensity.THIRD_PARTY_API,
    "gau": ProviderIntensity.THIRD_PARTY_API,
    "waybackurls": ProviderIntensity.THIRD_PARTY_API,
    "github_secrets": ProviderIntensity.THIRD_PARTY_API,
    "passive_dns": ProviderIntensity.THIRD_PARTY_API,
    "theharvester": ProviderIntensity.THIRD_PARTY_API,
    "threat_intel": ProviderIntensity.THIRD_PARTY_API,
    "whois": ProviderIntensity.THIRD_PARTY_API,
    "naabu": ProviderIntensity.ACTIVE_HIGH_VOLUME,
    "ffuf": ProviderIntensity.ACTIVE_HIGH_VOLUME,
    "param_fuzz": ProviderIntensity.ACTIVE_HIGH_VOLUME,
    "cloud_bucket_enum": ProviderIntensity.ACTIVE_HIGH_VOLUME,
}


class AuthorizationRequirement(str, Enum):
    NONE = "none"
    SCOPE_REQUIRED = "scope_required"


class ConfinementLevel(str, Enum):
    NONE = "none"
    INPUT_GATED = "input_gated"
    PROXY_VERIFIED = "proxy_verified"
    BUILTIN_PER_REQUEST = "builtin_per_request"


_DISCOVERY_CAPABILITIES = frozenset(
    {
        "enumerate_domains",
        "resolve_dns",
        "url_archive",
        "crawl",
        "cloud_bucket_enum",
    }
)
_EXPOSURE_CAPABILITIES = frozenset(
    {
        "vulnerability_scan",
        "content_discovery",
        "subdomain_takeover",
        "github_secrets",
        "security_headers",
        "soft404",
        "param_fuzz",
    }
)


@dataclass(frozen=True)
class ProviderDescriptor:
    provider: str
    display_name: str
    provider_kind: ProviderKind
    product_capability: str
    capability: Capability
    intensity: ProviderIntensity
    active_collection: bool
    authorization_requirement: AuthorizationRequirement
    confinement: ConfinementLevel
    external_dependency: bool
    required: bool
    produces: tuple[str, ...]
    supported_asset_types: tuple[str, ...]
    dependency_capabilities: tuple[str, ...]
    provenance_source: str
    optional: bool

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["provider_kind"] = self.provider_kind.value
        payload["capability"] = self.capability.value
        payload["intensity"] = self.intensity.value
        payload["authorization_requirement"] = self.authorization_requirement.value
        payload["confinement"] = self.confinement.value
        return payload


def _provider_kind(plugin_cls: type[ReconPlugin]) -> ProviderKind:
    explicit = getattr(plugin_cls, "provider_kind", "")
    if explicit:
        return ProviderKind(explicit)
    capability = plugin_cls.capability
    if capability in _EXPOSURE_CAPABILITIES:
        return ProviderKind.EXPOSURE
    if capability in _DISCOVERY_CAPABILITIES or capability.startswith("enumerate_"):
        return ProviderKind.DISCOVERY
    return ProviderKind.INTELLIGENCE


def _intensity(plugin_cls: type[ReconPlugin]) -> ProviderIntensity:
    override = _INTENSITY_OVERRIDES.get(plugin_cls.name)
    if override is not None:
        return override
    return (
        ProviderIntensity.ACTIVE_STANDARD
        if plugin_cls.active_collection
        else ProviderIntensity.PASSIVE
    )


def _confinement(plugin_cls: type[ReconPlugin]) -> ConfinementLevel:
    if not plugin_cls.active_collection:
        return ConfinementLevel.NONE
    if plugin_cls.name in PROXY_VERIFIED_TOOLS:
        return ConfinementLevel.PROXY_VERIFIED
    if not plugin_cls.external_dependency:
        return ConfinementLevel.BUILTIN_PER_REQUEST
    return ConfinementLevel.INPUT_GATED


def provider_descriptor(plugin_cls: type[ReconPlugin]) -> ProviderDescriptor:
    dependency = get_tool_definition(plugin_cls.name)
    supported = tuple(getattr(plugin_cls, "supported_asset_types", ()))
    return ProviderDescriptor(
        provider=plugin_cls.name,
        display_name=plugin_cls.display_name,
        provider_kind=_provider_kind(plugin_cls),
        product_capability=plugin_cls.capability or plugin_cls.name,
        capability=capability_for(plugin_cls.capability),
        intensity=_intensity(plugin_cls),
        active_collection=plugin_cls.active_collection,
        authorization_requirement=(
            AuthorizationRequirement.SCOPE_REQUIRED
            if plugin_cls.active_collection
            else AuthorizationRequirement.NONE
        ),
        confinement=_confinement(plugin_cls),
        external_dependency=plugin_cls.external_dependency,
        required=plugin_cls.required,
        produces=tuple(plugin_cls.produces),
        supported_asset_types=supported,
        dependency_capabilities=tuple(sorted(dependency.capabilities)),
        provenance_source=plugin_cls.name,
        optional=not plugin_cls.required,
    )


def provider_inventory() -> list[ProviderDescriptor]:
    """Machine-readable provider inventory derived from existing registries."""
    return [provider_descriptor(cls) for cls in ReconPlugin.all_plugins()]


def execution_status_for_result(result: PluginResult) -> ToolStatus:
    """Map one provider result to the normalized EASM execution outcome."""
    if result.blocked_by_scope:
        return ToolStatus.BLOCKED_BY_SCOPE
    if result.skipped:
        return ToolStatus.SKIPPED
    if result.unavailable:
        return ToolStatus.UNAVAILABLE
    if result.partial:
        return ToolStatus.PARTIAL
    if not result.success:
        return ToolStatus.FAILED
    if result.lines_produced > 0:
        return ToolStatus.SUCCESS_WITH_RESULTS
    return ToolStatus.SUCCESS_NO_RESULTS


# States a tool can still be in when a run ends without ever having run it:
# its prerequisite input never appeared (e.g. no host resolved, so httpx
# and naabu were never called). "Not executed" is SKIPPED, never a success.
_NEVER_EXECUTED = frozenset({ToolStatus.PENDING, ToolStatus.CHECKING, ToolStatus.READY})

FailureClass = Literal["transient", "configuration", "unknown"]


def recorded_outcome(info: ToolInfo) -> ToolStatus:
    """The execution outcome to record for a tool's end-of-run state.
    Every lifecycle or legacy state maps to one of the terminal outcomes
    the provider ledger accepts."""
    if info.status in _NEVER_EXECUTED:
        return ToolStatus.SKIPPED
    if info.status is ToolStatus.MISSING:
        # Enabled but not installed: coverage is missing, the same meaning
        # ToolManager gives an optional tool it can't run.
        return ToolStatus.UNAVAILABLE
    if info.status is ToolStatus.RUNNING:
        return ToolStatus.FAILED  # the run ended while this tool was mid-flight
    if info.status is ToolStatus.COMPLETED:
        return (
            ToolStatus.SUCCESS_WITH_RESULTS
            if info.output_lines > 0
            else ToolStatus.SUCCESS_NO_RESULTS
        )
    return info.status


def failure_class(info: ToolInfo) -> FailureClass | None:
    """Whether re-running is likely to help, from signals the pipeline
    already records, never from error text:

    - `transient`: the upstream was unreachable (UNAVAILABLE), only some
      queries failed (PARTIAL), or a FAILED run hit timeouts/rate limits.
    - `configuration`: the tool is enabled but not installed; re-running
      changes nothing until someone installs or disables it.
    - `unknown`: any other failure. Not guessed.
    - `None`: not a failure (success, intentional skip, scope block).
    """
    if info.status is ToolStatus.MISSING:
        return "configuration"
    outcome = recorded_outcome(info)
    if outcome in (ToolStatus.UNAVAILABLE, ToolStatus.PARTIAL):
        return "transient"
    if outcome is ToolStatus.FAILED:
        return "transient" if info.timeouts or info.rate_limits else "unknown"
    return None
