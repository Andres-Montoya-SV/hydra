"""Authorized-scope matching for fail-closed target filtering."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from core.assets import normalize_domain
from core.domain import parse_hostname


def load_scope_patterns(path: Path) -> list[str]:
    """Load non-empty, non-comment scope lines from a text file.

    A line may be a positive domain/wildcard pattern (`*.example.com`) or an
    explicit path exclusion prefixed with `!` (`!example.com/*/whistleblowing`)
    — see `split_scope_patterns`. Exclusion lines keep their original path
    case (URL paths are case-sensitive); only the domain part of a positive
    pattern is lowercased, as before.
    """
    patterns: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            patterns.append("!" + line[1:].strip())
        else:
            patterns.append(line.lower().rstrip("."))
    return patterns


def split_scope_patterns(patterns: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split raw scope lines into (positive domain patterns, path exclusions).

    A path exclusion line looks like `!domain/path-glob`, e.g.
    `!bancoplata.mx/*/whistleblowing`. The domain part is matched the same
    way a positive scope entry is (exact host or any subdomain); the path
    part is matched against the URL path by segment (`/`-separated, each
    segment compared with `fnmatch` — see `url_path_excluded`) as a
    **subtree prefix**: the exclusion covers the named path and everything
    beneath it, not merely that exact path string.
    """
    positive: list[str] = []
    exclusions: list[tuple[str, str]] = []
    for pattern in patterns:
        if not pattern.startswith("!"):
            positive.append(pattern)
            continue
        body = pattern[1:].strip()
        domain_part, _, path_part = body.partition("/")
        domain = normalize_domain(domain_part)
        if not domain:
            continue
        path_glob = "/" + path_part if path_part else "/*"
        exclusions.append((domain, path_glob))
    return positive, exclusions


def url_path_excluded(url: str, exclusions: list[tuple[str, str]]) -> bool:
    """True when `url`'s hostname+path falls under an explicit path
    exclusion's subtree — not just an exact string match.

    `!domain/path` excludes `path` **and everything beneath it**:
    `!bancoplata.mx/*/whistleblowing` excludes `/es/whistleblowing`,
    `/es/whistleblowing/reportar`, `/es/whistleblowing/formulario/paso2`,
    and so on — a bug-bounty program almost never marks the landing page
    itself as sensitive, it marks a section, and the actual report
    mechanism usually lives one or more segments deeper. Matching by exact
    string (`fnmatch.fnmatch(path, glob)` alone) would protect only the
    literal landing path and silently leave every subpath — the part that
    actually matters — reachable.

    Matching is by whole path *segment* (split on `/`), each segment
    compared with `fnmatch` (so a `*` in the pattern matches one segment,
    not an arbitrary run of characters): the URL path must have at least as
    many segments as the pattern, and every corresponding leading segment
    must match. A path that merely shares a text *prefix* with a different,
    unrelated segment (`/es/whistleblowing-info` against a pattern ending in
    `whistleblowing`) is a different segment and is never excluded — segment
    equality, not substring containment.

    Only meaningful for a real URL (scheme + path) — a bare hostname or
    `host:port` indicator carries no path to exclude and never matches here,
    same as a path exclusion never applying to non-URL discovery data.
    """
    if not exclusions:
        return False
    text = (url or "").strip()
    if "://" not in text:
        return False
    try:
        parsed = urlparse(text)
    except ValueError:
        return False
    host = normalize_domain(parsed.hostname or "")
    if not host:
        return False
    path_segments = (parsed.path or "/").split("/")
    for domain, path_glob in exclusions:
        if host != domain and not host.endswith("." + domain):
            continue
        glob_segments = path_glob.split("/")
        if len(path_segments) < len(glob_segments):
            continue
        if all(
            fnmatch.fnmatch(actual, pattern)
            for actual, pattern in zip(path_segments, glob_segments, strict=False)
        ):
            return True
    return False


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
