"""Scope classification and the hard authorization gate for active collection.

Discovery and observation are not authorization. Every DNS/HTTP/port/crawl
probe must call ``allows_active_collection(indicator, scope)`` immediately
before touching the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from core.assets import normalize_domain
from core.domain import parse_hostname
from core.exceptions import ConfigurationError
from core.intel.model import ScopeStatus
from core.scope import host_in_scope, load_scope_patterns
from utils.files import read_lines, write_lines


@dataclass(frozen=True)
class CollectionScope:
    """Authorization context for one run. Fail closed when empty."""

    seed_domains: tuple[str, ...] = ()
    scope_patterns: tuple[str, ...] = ()

    @classmethod
    def from_seeds(
        cls,
        seeds: list[str],
        *,
        patterns: list[str] | None = None,
        scope_file: Path | None = None,
    ) -> CollectionScope:
        normalized = tuple(normalize_domain(s) for s in seeds if normalize_domain(s))
        loaded: list[str] = list(patterns or [])
        if scope_file is not None and scope_file.exists():
            loaded.extend(load_scope_patterns(scope_file))
        return cls(seed_domains=normalized, scope_patterns=tuple(loaded))


def classify_scope(
    hostname: str,
    *,
    seed_domains: list[str],
    scope_patterns: list[str] | None,
) -> ScopeStatus:
    """Classify a hostname relative to seeds and an optional SCOPE_FILE.

    Rules:
    - Seeds supplied by the operator are IN_SCOPE.
    - If SCOPE_FILE patterns exist, they are the authorization list (fail closed).
    - Without SCOPE_FILE, names under a seed's registrable domain are IN_SCOPE.
    - Other registrable domains are OUT_OF_SCOPE (observe, do not probe).
    - Unparseable names are UNKNOWN (no active collection).
    """
    domain = normalize_domain(hostname)
    if not domain:
        return ScopeStatus.UNKNOWN
    if not _hostname_is_collectable(domain):
        return ScopeStatus.UNKNOWN

    seeds = [normalize_domain(s) for s in seed_domains if normalize_domain(s)]
    if domain in seeds:
        return ScopeStatus.IN_SCOPE

    if scope_patterns:
        return (
            ScopeStatus.IN_SCOPE
            if host_in_scope(domain, scope_patterns)
            else ScopeStatus.OUT_OF_SCOPE
        )

    _, _, root = parse_hostname(domain)
    if not root:
        return ScopeStatus.UNKNOWN
    seed_roots = {parse_hostname(s)[2] for s in seeds}
    if root in seed_roots or domain in seed_roots:
        return ScopeStatus.IN_SCOPE
    return ScopeStatus.OUT_OF_SCOPE


def scope_status_allows_collection(status: ScopeStatus) -> bool:
    """UNKNOWN and OUT_OF_SCOPE must not be DNS/HTTP/port probed."""
    return status is ScopeStatus.IN_SCOPE


def _hostname_is_collectable(host: str) -> bool:
    """Reject wildcards, empties, and junk that must never become probe targets."""
    if not host:
        return False
    if any(ch in host for ch in ("*", " ", "\t", "\n", "?", "#")):
        return False
    if host.startswith(".") or host.endswith(".."):
        return False
    if host in {".", "localhost"}:
        return False
    return True


def allows_active_collection(indicator: str, scope: CollectionScope) -> bool:
    """Authoritative gate: True only when this indicator may be actively probed."""
    if scope is None:
        return False
    host = indicator_hostname(indicator)
    if not host or not _hostname_is_collectable(host):
        return False
    status = classify_scope(
        host,
        seed_domains=list(scope.seed_domains),
        scope_patterns=list(scope.scope_patterns) or None,
    )
    return scope_status_allows_collection(status)


def indicator_hostname(raw: str) -> str:
    """Extract a hostname from a host, URL, or host:port indicator."""
    text = (raw or "").strip()
    if not text or text.startswith("#"):
        return ""
    if "://" in text:
        try:
            parsed = urlparse(text)
            return normalize_domain(parsed.hostname or "")
        except ValueError:
            return ""
    host = text.split("/")[0].split("%")[0].strip()
    if host.startswith("[") and "]" in host:
        return host
    if host.count(":") == 1:
        name, _, port = host.rpartition(":")
        if port.isdigit():
            host = name
    return normalize_domain(host)


def filter_authorized_indicators(names: list[str], scope: CollectionScope) -> list[str]:
    """Keep original lines whose hostname is authorized. Preserve order/dedupe."""
    kept: list[str] = []
    seen: set[str] = set()
    for raw in names:
        line = raw.strip()
        if not line or line in seen:
            continue
        if allows_active_collection(line, scope):
            kept.append(line)
            seen.add(line)
    return kept


def authorize_collect_input(
    input_path: Path,
    *,
    scope: CollectionScope,
    dest: Path,
    base_dir: Path,
) -> tuple[Path, list[str], list[str]]:
    """Write ``dest`` with only authorized indicators.

    Returns (dest, kept, dropped). The source file is not modified so
    out-of-scope names remain available as intelligence observations.
    """
    source_lines = read_lines(input_path) if input_path.exists() else []
    kept = filter_authorized_indicators(source_lines, scope)
    dropped = [
        line for line in source_lines if line.strip() and not allows_active_collection(line, scope)
    ]
    write_lines(dest, kept, base_dir=base_dir)
    return dest, kept, dropped


def require_collection_scope(context: object) -> CollectionScope:
    """Fail closed: active collection is refused without an attached scope."""
    scope = getattr(context, "collection_scope", None)
    if scope is None:
        raise ConfigurationError(
            "Active collection refused: CollectionScope is missing (fail closed). "
            "Discovery of an indicator does not imply authorization to probe it."
        )
    return scope


def authorize_plugin_input(context: object, input_path: Path, plugin_name: str) -> Path:
    """Re-check collector input immediately before active use.

    Missing CollectionScope is never a no-op. Discovery is not authorization.
    """
    scope = require_collection_scope(context)
    output_dir = getattr(context, "output_dir", None)
    if output_dir is None:
        raise ConfigurationError(
            f"{plugin_name}: active collection refused — output directory missing"
        )
    dest_name = input_path.name
    if not dest_name.startswith("authorized_"):
        dest_name = f"authorized_{plugin_name}_{input_path.name}"
    dest = Path(output_dir) / dest_name
    authorized, _kept, dropped = authorize_collect_input(
        input_path,
        scope=scope,
        dest=dest,
        base_dir=Path(output_dir),
    )
    if dropped:
        add_warning = getattr(context, "add_warning", None)
        if callable(add_warning):
            add_warning(
                f"{plugin_name}: withheld {len(dropped)} out-of-scope "
                "indicator(s) from active collection"
            )
        metadata = getattr(context, "metadata", None)
        if isinstance(metadata, dict):
            denied = metadata.setdefault("authorization_denied", [])
            if isinstance(denied, list):
                for name in dropped:
                    if name not in denied:
                        denied.append(name)
    return authorized
