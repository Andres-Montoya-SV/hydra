"""Central authorization primitive for every active network action.

Discovery of an indicator is not authorization. Presence of a CollectionScope
object is not authorization. UNKNOWN fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from core.assets import normalize_domain
from core.intel.model import ScopeStatus
from core.intel.scope import (
    CollectionScope,
    _hostname_is_collectable,
    classify_scope,
    indicator_hostname,
    scope_status_allows_collection,
)

# Vendor cloud hostnames are never silently in-scope just because a seed brand
# appears in a label. Active collection requires an explicit cloud policy.
_CLOUD_ENDPOINT_SUFFIXES = (
    ".s3.amazonaws.com",
    ".s3.amazonaws.com.cn",
    ".storage.googleapis.com",
    ".blob.core.windows.net",
    ".r2.cloudflarestorage.com",
)


class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AuthorizationResult:
    decision: AuthorizationDecision
    hostname: str
    operation: str
    reason: str
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN

    @property
    def allowed(self) -> bool:
        return self.decision is AuthorizationDecision.ALLOW


def is_generated_cloud_endpoint(hostname: str) -> bool:
    host = normalize_domain(hostname)
    if not host:
        return False
    return any(host == suffix[1:] or host.endswith(suffix) for suffix in _CLOUD_ENDPOINT_SUFFIXES)


def parse_indicator_hostname(indicator: str) -> tuple[str, str]:
    """Return (hostname, parse_error). Empty hostname means unusable."""
    text = (indicator or "").strip()
    if not text or text.startswith("#"):
        return "", "empty"
    if "://" in text:
        try:
            parsed = urlparse(text)
        except ValueError:
            return "", "malformed_url"
        if not parsed.scheme or not parsed.netloc:
            return "", "malformed_url"
        host = normalize_domain(parsed.hostname or "")
        if not host:
            return "", "malformed_url"
        return host, ""
    host = indicator_hostname(text)
    if not host:
        return "", "unparseable_hostname"
    return host, ""


def authorize_active_indicator(
    indicator: str,
    collection_scope: CollectionScope | None,
    operation: str,
    reason: str,
) -> AuthorizationResult:
    """Authoritative decision for one concrete hostname/URL.

    UNKNOWN and DENY both refuse active collection. Callers must not probe
    unless decision is ALLOW.
    """
    op = (operation or "active_collection").strip() or "active_collection"
    why = (reason or "unspecified").strip() or "unspecified"
    if collection_scope is None:
        return AuthorizationResult(
            AuthorizationDecision.UNKNOWN,
            "",
            op,
            "missing_collection_scope",
        )
    host, error = parse_indicator_hostname(indicator)
    if error or not host:
        return AuthorizationResult(
            AuthorizationDecision.UNKNOWN,
            host,
            op,
            error or "unparseable_hostname",
        )
    if not _hostname_is_collectable(host):
        return AuthorizationResult(
            AuthorizationDecision.UNKNOWN,
            host,
            op,
            "hostname_not_collectable",
        )
    if is_generated_cloud_endpoint(host) and not collection_scope.cloud_collection_allowed:
        if op != "cloud_bucket_enum":
            return AuthorizationResult(
                AuthorizationDecision.DENY,
                host,
                op,
                "cloud_endpoint_requires_explicit_policy",
                ScopeStatus.OUT_OF_SCOPE,
            )
        return AuthorizationResult(
            AuthorizationDecision.DENY,
            host,
            op,
            "cloud_collection_policy_disabled",
            ScopeStatus.OUT_OF_SCOPE,
        )
    status = classify_scope(
        host,
        seed_domains=list(collection_scope.seed_domains),
        scope_patterns=list(collection_scope.scope_patterns) or None,
    )
    if status is ScopeStatus.UNKNOWN:
        return AuthorizationResult(
            AuthorizationDecision.UNKNOWN,
            host,
            op,
            "scope_unknown",
            status,
        )
    if not scope_status_allows_collection(status):
        return AuthorizationResult(
            AuthorizationDecision.DENY,
            host,
            op,
            "out_of_scope",
            status,
        )
    return AuthorizationResult(
        AuthorizationDecision.ALLOW,
        host,
        op,
        why,
        status,
    )


def authorize_collection(
    indicator: str,
    collection_scope: CollectionScope | None,
    *,
    capability: str,
    operation: str = "",
    reason: str = "",
    strict_opsec: bool = False,
    opsec_allowed: bool = True,
) -> AuthorizationResult:
    """Compose scope, capability label, and OPSEC. All four must pass.

    AUTHORIZED = IN_SCOPE AND capability requested AND OPSEC_ALLOWED.
    Budget is enforced by the planner, not this function.
    """
    op = (operation or capability or "active_collection").strip()
    if strict_opsec and not opsec_allowed:
        host, _error = parse_indicator_hostname(indicator)
        return AuthorizationResult(
            AuthorizationDecision.DENY,
            host,
            op,
            "opsec_blocked",
        )
    return authorize_active_indicator(
        indicator,
        collection_scope,
        op,
        reason or capability or "authorize_collection",
    )


def decision_allows_collection(result: AuthorizationResult) -> bool:
    return result.decision is AuthorizationDecision.ALLOW
