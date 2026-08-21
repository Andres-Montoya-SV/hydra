"""Hydra CLI identity: ASCII banner and one-line plugin ("head") blurbs."""

from __future__ import annotations

HYDRA_BANNER = r"""
      /\      /\      /\
     /  \    /  \    /  \
    /    \  /    \  /    \
   |  ()  \/  ()  \/  ()  |
    \        HYDRA       /
     \ coordinated recon/
      `----------------'
"""

HYDRA_TAGLINE = "Multiple reconnaissance heads, one coordinated brain."

# One-line description of what each plugin "head" does.
HEAD_BLURBS: dict[str, str] = {
    "whois": "domain attribution head",
    "asn_lookup": "network ownership (ASN) head",
    "ctlogs": "certificate-transparency discovery head",
    "subfinder": "passive subdomain enumeration head",
    "assetfinder": "related-hostname discovery head",
    "amass": "deep OSINT enumeration head",
    "anew": "new-entry tracking head",
    "wildcard_check": "wildcard-DNS canary head",
    "dnsx": "DNS resolution head",
    "naabu": "port-scan / tarpit-canary head",
    "port_verify": "service-verification (nmap) head",
    "httpx": "live HTTP probing head",
    "soft404_check": "soft-404 / catch-all detection head",
    "param_fuzz": "hidden-parameter discovery head",
    "cloud_bucket_enum": "cloud-bucket existence head",
    "threat_intel": "host-reputation (URLhaus) head",
    "gau": "archived-URL harvest head",
    "waybackurls": "Wayback Machine URL head",
    "katana": "active crawler head",
    "hakrawler": "lightweight crawler head",
    "unfurl": "URL-component extraction head",
    "nuclei": "template-based vuln scan head",
    "browser_probe": "browser cloaking-detection head",
    "vuln_match": "CVE correlation head",
    "security_headers": "HTTP security-header audit head",
}


def print_banner() -> None:
    """Write the Hydra banner and tagline to stdout."""
    print(HYDRA_BANNER.lstrip("\n"), end="")
    print(f"  {HYDRA_TAGLINE}\n")
