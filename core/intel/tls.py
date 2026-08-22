"""TLS certificate identity helpers. Identity is SHA-256 fingerprint, never SAN slices."""

from __future__ import annotations

from core.assets import normalize_domain
from core.intel.model import normalize_fingerprint


def extract_tls_fingerprint(tls: dict | None) -> str:
    """Extract a 64-char SHA-256 fingerprint from an httpx-style TLS object."""
    if not isinstance(tls, dict):
        return ""
    nested = tls.get("fingerprint_hash")
    if isinstance(nested, dict):
        for key in ("sha256", "SHA256", "sha_256"):
            fp = normalize_fingerprint(str(nested.get(key) or ""))
            if fp:
                return fp
    for key in ("fingerprint_sha256", "sha256", "fingerprint"):
        value = tls.get(key)
        if isinstance(value, str):
            fp = normalize_fingerprint(value)
            if fp:
                return fp
    return ""


def extract_sans(raw: object) -> list[str]:
    """Normalize a SAN list; preserve order, drop empties, keep first of duplicates."""
    values: list[str] = []
    if raw is None:
        return values
    if isinstance(raw, str):
        parts = raw.replace(",", "\n").splitlines()
    elif isinstance(raw, list):
        parts = [str(item) for item in raw]
    else:
        parts = [str(raw)]
    seen: set[str] = set()
    for part in parts:
        raw = part.strip().removeprefix("*.")
        try:
            raw = raw.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            pass
        name = normalize_domain(raw)
        if name and name not in seen:
            seen.add(name)
            values.append(name)
    return values


def extract_certificate_names(raw_names: object) -> list[str]:
    """All names from a CT name_value blob, including off-root SANs."""
    return extract_sans(raw_names)
