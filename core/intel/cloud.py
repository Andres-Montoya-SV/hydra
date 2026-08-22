"""Cloud / shared-tenancy classification for IP addresses."""

from __future__ import annotations

import ipaddress

# Coarse provider ranges. A hit means shared tenancy is the default assumption,
# not dedicated ownership. Keep in sync with core.intelligence.engine ranges.
CLOUD_IP_RANGES: tuple[tuple[str, str], ...] = (
    ("AWS", "3.0.0.0/8"),
    ("AWS", "13.32.0.0/15"),
    ("AWS", "52.0.0.0/8"),
    ("AWS", "54.0.0.0/8"),
    ("Cloudflare", "104.16.0.0/12"),
    ("Cloudflare", "172.64.0.0/13"),
    ("Cloudflare", "188.114.96.0/20"),
    ("GCP", "34.0.0.0/8"),
    ("GCP", "35.184.0.0/13"),
    ("Azure", "20.0.0.0/8"),
    ("Azure", "40.64.0.0/10"),
)


def cloud_provider_for_ip(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, cidr in CLOUD_IP_RANGES:
        try:
            if addr in ipaddress.ip_network(cidr):
                return provider
        except ValueError:
            continue
    return None


def is_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False
