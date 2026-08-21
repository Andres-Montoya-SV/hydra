"""Authorized-scope matching for fail-closed target filtering."""

from __future__ import annotations

from pathlib import Path

from core.assets import normalize_domain
from core.domain import parse_hostname


def load_scope_patterns(path: Path) -> list[str]:
    """Load non-empty, non-comment scope lines from a text file."""
    patterns: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line.lower().rstrip("."))
    return patterns


def host_in_scope(host: str, patterns: list[str]) -> bool:
    """True when ``host`` matches an exact entry or ``*.root`` wildcard."""
    domain = normalize_domain(host)
    if not domain:
        return False
    _, _, root = parse_hostname(domain)
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if domain == suffix or domain.endswith("." + suffix):
                return True
            continue
        exact = normalize_domain(pattern)
        if domain == exact or root == exact:
            return True
        # Exact www.example.com entry must also cover example.com's apex
        # only when the pattern itself is that FQDN — already handled by
        # equality. Subdomain of an exact FQDN that is not a wildcard:
        # www.metaversejustice.com matches the exact line.
        if domain.endswith("." + exact):
            return True
    return False


def out_of_scope_targets(targets: list[str], patterns: list[str]) -> list[str]:
    """Return target hostnames that do not match any scope pattern."""
    return [t for t in targets if not host_in_scope(t, patterns)]
