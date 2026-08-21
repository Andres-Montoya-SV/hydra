"""Domain parsing utilities for host normalization."""

from __future__ import annotations

# Common multi-part public suffixes (minimal set — extend as needed)
_MULTI_SUFFIX = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.br",
        "com.mx",
        "co.kr",
    }
)


def parse_hostname(hostname: str) -> tuple[str, str, str]:
    """Return (hostname, subdomain, root_domain)."""
    hostname = hostname.strip().lower().rstrip(".")
    if not hostname:
        return "", "", ""

    parts = hostname.split(".")
    if len(parts) == 1:
        return hostname, "", hostname

    suffix = ".".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    if suffix in _MULTI_SUFFIX and len(parts) >= 3:
        root = ".".join(parts[-3:])
        subdomain = ".".join(parts[:-3])
    elif len(parts) == 2:
        root = hostname
        subdomain = ""
    else:
        root = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

    return hostname, subdomain, root
