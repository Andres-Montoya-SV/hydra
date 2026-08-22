"""Collector capability sets derived from plugin class declarations.

The runner groups work by capability and authorization, not by a growing
list of plugin names maintained in two places. Plugins still run as isolated
subprocesses; this module only reads class attributes.
"""

from __future__ import annotations

import modules  # noqa: F401  # registers ReconPlugin subclasses
from core.plugin_base import ReconPlugin


def plugin_classes() -> list[type[ReconPlugin]]:
    return list(ReconPlugin.all_plugins())


def names(
    *,
    capability: str | None = None,
    active_collection: bool | None = None,
    strict_opsec_allowed: bool | None = None,
) -> frozenset[str]:
    result: list[str] = []
    for cls in plugin_classes():
        if capability is not None and cls.capability != capability:
            continue
        if active_collection is not None and cls.active_collection != active_collection:
            continue
        if strict_opsec_allowed is not None and cls.strict_opsec_allowed != strict_opsec_allowed:
            continue
        result.append(cls.name)
    return frozenset(result)


SUBDOMAIN_PLUGINS = names(capability="enumerate_domains")
URL_DISCOVERY_PLUGINS = names(capability="url_archive")
POST_HTTP_PLUGINS = names(capability="post_http")
RESOLVE_DNS_PLUGINS = names(capability="resolve_dns")
ACTIVE_COLLECTION_PLUGINS = names(active_collection=True)
STRICT_OPSEC_ALLOWED_PLUGINS = names(strict_opsec_allowed=True)
