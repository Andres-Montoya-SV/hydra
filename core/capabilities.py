"""Fase 17 (EASM roadmap): a stable, product-level capability taxonomy.

Distinct from two things that already exist and are NOT replaced here:
`core/plugin_base.py::ReconPlugin.capability` (a free-text string every
one of the 33 plugin modules already sets, e.g. `"enumerate_domains"`,
`"technology_intelligence"`) and `core/provider_contract.py`'s
`ProviderDescriptor` (per-provider execution/authorization metadata).
Neither of those is a stable, closed CATEGORY tree a product surface
(the frontend, `heads`, a future policy toggle) can group providers by.

This module is a pure, additive mapping layer: `capability_for()`
projects each plugin's EXISTING `capability` string onto one of a small,
closed set of categories, justified by what the tool actually does, not
by re-deriving or renaming anything already declared. No plugin module
needs to change — this is the incremental migration the phase itself
asks for ("migrar los módulos que falten... de forma incremental"):
every one of the 33 already has a `capability` string, so there is
nothing left to migrate at the plugin level, only this taxonomy layer on
top of what already exists.

Swapping the underlying tool for a `Capability` (WhatWeb for a different
technology-detection provider, Subfinder for a different domain
enumerator) never changes the category — this is what "replaceability"
(the phase's requirement 3) means in practice, and is already true by
construction here: nothing in this module or in
`core/provider_contract.py` names a specific tool as load-bearing.
"""

from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    DOMAIN_DISCOVERY = "domain_discovery"
    DNS = "dns"
    NETWORK_DISCOVERY = "network_discovery"
    HTTP = "http"
    TECHNOLOGY = "technology"
    VISUAL = "visual"
    TLS = "tls"
    CLOUD = "cloud"
    EXPOSURE_DETECTION = "exposure_detection"
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    IMPORT = "import"
    UNCATEGORIZED = "uncategorized"


# Exhaustive as of Fase 17 for every `ReconPlugin.capability` string set
# by a real module under modules/ (verified against every plugin's own
# class attribute, not guessed at). A plugin whose capability string
# isn't in this table falls back to UNCATEGORIZED rather than a wrong
# guess — a new module always needs an explicit entry here to be
# categorized.
_CAPABILITY_MAP: dict[str, Capability] = {
    # Domain discovery
    "enumerate_domains": Capability.DOMAIN_DISCOVERY,
    # DNS
    "resolve_dns": Capability.DNS,
    "wildcard_dns": Capability.DNS,
    "passive_dns": Capability.DNS,
    # Network discovery
    "asn": Capability.NETWORK_DISCOVERY,
    "port_scan": Capability.NETWORK_DISCOVERY,
    "port_verify": Capability.NETWORK_DISCOVERY,
    # HTTP surface
    "http_probe": Capability.HTTP,
    "http_headers": Capability.HTTP,
    "http_verify": Capability.HTTP,
    "post_http": Capability.HTTP,
    "content_discovery": Capability.HTTP,
    "url_archive": Capability.HTTP,
    "param_fuzz": Capability.HTTP,
    # Technology / WAF-CDN identification
    "technology_intelligence": Capability.TECHNOLOGY,
    "waf_detection": Capability.TECHNOLOGY,
    # TLS
    "tls_posture": Capability.TLS,
    # Cloud
    "cloud_enum": Capability.CLOUD,
    # Visual
    "browser": Capability.VISUAL,
    # Exposure detection
    "vuln_match": Capability.EXPOSURE_DETECTION,
    "leaked_secrets_scanning": Capability.EXPOSURE_DETECTION,
    "sub_takeover": Capability.EXPOSURE_DETECTION,
    # External intelligence
    "typosquat_detection": Capability.EXTERNAL_INTELLIGENCE,
    "registration": Capability.EXTERNAL_INTELLIGENCE,
    "reputation": Capability.EXTERNAL_INTELLIGENCE,
    "email_personnel_osint": Capability.EXTERNAL_INTELLIGENCE,
}


def capability_for(product_capability: str) -> Capability:
    """Never raises, never guesses — an unrecognized string is
    `UNCATEGORIZED`, not a fuzzy/best-effort match."""
    return _CAPABILITY_MAP.get(product_capability, Capability.UNCATEGORIZED)
