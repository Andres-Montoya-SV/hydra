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


def hostname_matches_pattern(host: str, pattern: str) -> bool:
    """True when `host` matches `pattern` — an exact hostname, or a
    hostname pattern with a `fnmatch` wildcard anywhere in it (e.g.
    `mta*.stripchat.com`, `*-beta.example.com`, `staging-*.example.com`) —
    or is a further subdomain of some name the pattern would match.

    Uses `fnmatch` directly against the whole hostname string, the same
    matching engine `url_path_excluded` already uses per path segment and
    the positive `*.domain` scope patterns already rely on — not a second,
    different comparison mechanism for exclusions. `fnmatch`'s `*` has no
    concept of a label boundary (it matches any run of characters,
    including further dots), which is intentionally on the safe side for
    an *exclusion*: matching a wider set of hostnames only ever excludes
    more, never less, the same conservative principle host_fully_excluded
    already documents for the plain-subdomain case below.

    A pattern with no wildcard character behaves exactly like the
    pre-wildcard exact-or-subdomain check this replaces: `fnmatch` with no
    special characters is a plain string comparison, so `host == pattern`
    is unaffected, and the subdomain walk below reproduces the previous
    `host.endswith("." + domain)` check for that case.
    """
    if not host or not pattern:
        return False
    if fnmatch.fnmatch(host, pattern):
        return True
    labels = host.split(".")
    for i in range(1, len(labels)):
        if fnmatch.fnmatch(".".join(labels[i:]), pattern):
            return True
    return False


def host_fully_excluded(host: str, exclusions: list[tuple[str, str]]) -> bool:
    """True when `host` (or any subdomain of it) falls under a **whole-domain**
    exclusion — a `!domain` SCOPE_FILE line with no path at all (or an
    explicit `!domain/*`, which means the same thing: every path excluded is
    the whole domain excluded). `domain` may itself contain a `fnmatch`
    wildcard (`!mta*.stripchat.com`) — matched via `hostname_matches_pattern`
    above, not a separate mechanism.

    `url_path_excluded` above only ever fires for a real URL (scheme +
    path) — a bare hostname indicator (what DNS resolution, a CT-log SAN
    observation, or a plain `resolved.txt`/`subdomains.txt` line actually
    is) structurally has no path to compare against a path glob, so it
    always fell through as "not excluded" even for a program's explicit
    `!community.linktr.ee` line — the exact real-world case (Linktree
    excludes `community.linktr.ee` from an otherwise-authorized
    `*.linktr.ee`) that surfaced this gap. A domain-only exclusion has no
    such ambiguity: "exclude this domain" means exclude it from every
    collection path, not only the ones that happen to carry a URL.

    A path-*specific* exclusion (`!domain/some/real/path`) never matches
    here — only the `/*` sentinel `split_scope_patterns` produces when no
    path segment was given (or an explicit `/*` was), since a bare hostname
    genuinely has no path to exclude in that case; `bancoplata.mx` itself
    must stay resolvable even though `!bancoplata.mx/*/whistleblowing` is
    excluded.

    Conservative by design, same principle as the subtree rule above: a
    further subdomain of the excluded domain (`sub.community.linktr.ee`) is
    excluded too, not just the exact excluded name — in scope-exclusion
    ambiguity, excluding more is safer than excluding less. The same
    principle now also covers a further subdomain of a name a *wildcard*
    exclusion pattern matches (`sub.mta1.stripchat.com` under
    `!mta*.stripchat.com`), since `hostname_matches_pattern` walks the
    label suffixes for both the exact and the wildcard case alike.
    """
    if not host:
        return False
    for domain, path_glob in exclusions:
        if path_glob != "/*":
            continue
        if hostname_matches_pattern(host, domain):
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
