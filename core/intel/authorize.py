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
from core.scope import url_path_excluded

# Vendor cloud hostnames are never silently in-scope just because a seed brand
# appears in a label. Active collection requires an explicit cloud policy.
_CLOUD_ENDPOINT_SUFFIXES = (
    ".s3.amazonaws.com",
    ".s3.amazonaws.com.cn",
    ".storage.googleapis.com",
    ".blob.core.windows.net",
    ".r2.cloudflarestorage.com",
)

# `modules/cloud_bucket_enum.py`'s own pre-check calls this function with
# operation="cloud_bucket_enum" (its literal per-request operation label);
# `ScopeEnforcingProxy`'s independent re-check (`core/collection/crawler_proxy.py`)
# passes the plugin's declared `capability` instead ("cloud_enum",
# `CloudBucketEnumPlugin.capability`) — both must be recognized here, or the
# proxy's re-check falls through to ordinary registrable-domain scope
# matching (which a generated bucket hostname can never pass) and denies
# every candidate even when the operator explicitly opted in. This was a
# real bug: cloud_bucket_enum's classifier treats a bare HTTP 403 (exactly
# what the proxy's own denial looks like) as "bucket exists, access denied"
# for GCS/Azure, so the mismatch silently turned every confined run into
# mostly false-positive "existing bucket" results instead of an obvious
# failure.
_CLOUD_BUCKET_ENUM_OPERATIONS = frozenset({"cloud_bucket_enum", "cloud_enum"})


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
    # Explicit path exclusions (`!domain/path-glob` SCOPE_FILE lines) take
    # priority over every other check below, including the cloud-endpoint
    # opt-in and ordinary domain/wildcard matching — a program can authorize
    # `*.bancoplata.mx` broadly while still carving out a specific path as
    # explicitly out of scope. Only ever matches when `indicator` is a full
    # URL (a bare hostname has no path to exclude).
    if collection_scope.path_exclusions and url_path_excluded(
        indicator, list(collection_scope.path_exclusions)
    ):
        return AuthorizationResult(
            AuthorizationDecision.DENY,
            host,
            op,
            "excluded_path_out_of_scope",
            ScopeStatus.OUT_OF_SCOPE,
        )
    if is_generated_cloud_endpoint(host):
        if not collection_scope.cloud_collection_allowed:
            if op not in _CLOUD_BUCKET_ENUM_OPERATIONS:
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
        if op in _CLOUD_BUCKET_ENUM_OPERATIONS:
            # Explicitly opted in via the cloud policy. A generated bucket
            # hostname is never going to share a registrable domain with the
            # seed (that is the entire point of probing it) — falling
            # through to the normal seed-root scope check below would deny
            # every candidate even after the operator explicitly authorized
            # this operation, which is not "fail closed", it is "this
            # feature can never work". ScopeStatus stays OUT_OF_SCOPE (it
            # genuinely is a different registrable domain) — only the
            # collection decision is ALLOW.
            return AuthorizationResult(
                AuthorizationDecision.ALLOW,
                host,
                op,
                why,
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
