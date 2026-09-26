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

import modules  # noqa: F401  # register ReconPlugin subclasses

from core.collection.crawler_proxy import PROXY_VERIFIED_TOOLS
from core.dependencies.registry import get_tool_definition
from core.models import ToolStatus
from core.plugin_base import PluginResult, ReconPlugin


class ProviderKind(str, Enum):
    DISCOVERY = "discovery"
    INTELLIGENCE = "intelligence"
    EXPOSURE = "exposure"
    IMPORT = "import"


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
    if result.partial:
        return ToolStatus.PARTIAL
    if not result.success:
        return ToolStatus.FAILED
    if result.lines_produced > 0:
        return ToolStatus.SUCCESS_WITH_RESULTS
    return ToolStatus.SUCCESS_NO_RESULTS
