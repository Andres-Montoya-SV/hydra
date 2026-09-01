"""CollectionGateway: the structural network boundary for target-directed collection.

Every piece this module leans on already existed and was independently
verified across prior turns of this hardening arc: `AuthorizedCollectionTarget`
(hostname + capability + OPSEC + destination-IP authorization, sealed against
direct construction — see `core/collection/target.py`), `ScopeEnforcingProxy`
(resolve -> validate -> connect-to-the-validated-IP, DNS-rebinding/TOCTOU
closed — see `core/collection/crawler_proxy.py`), and `core/http_probe.py`'s
proxy-aware `http_get`. What did not exist was ONE object a plugin reaches for
that owns the whole sequence, so that the *type* of what a network primitive
accepts — an `AuthorizedCollectionTarget`, never a bare `str` — is what stops
an unauthorized destination, not a convention every call site has to
remember.

    plugin
      |
      v
    CollectionGateway.authorize(raw, capability=...)   # scope + capability +
      |                                                 # OPSEC + destination-IP
      v
    AuthorizedCollectionTarget | None
      |
      v
    CollectionGateway.http_get(target)   # only accepts the sealed type above;
      |                                   # routes through the confinement
      v                                   # proxy this gateway owns
    network (validated destination, audited)

This does not retrofit every plugin — that remains a real, open scope
decision (see `docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md` for which plugins
route through this gateway today vs. still call `core/http_probe.py` or
`allows_active_collection` directly). It demonstrates the pattern at a real
call site (`modules/soft404_check.py`) with a passing, live-verified test
suite, rather than shipping an unused abstraction nobody calls.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from core.collection.audit import append_network_request
from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.collection.target import AuthorizedCollectionTarget
from core.http_probe import http_get as _http_get
from core.intel.scope import CollectionScope
from core.provenance import utc_now_iso
from core.response_diff import ResponseSnapshot


@dataclass
class GatewayAuditEntry:
    """One `CollectionGateway.http_get` call, independent of whatever the
    underlying confinement proxy itself also recorded — this is the
    gateway's own record of what it was *asked* to do and the target
    identity it was asked to do it with."""

    hostname: str
    capability: str
    operation: str
    status_code: int | None
    error: str | None
    observed_at: str = field(default_factory=utc_now_iso)


class CollectionGateway:
    """Owns authorization + confinement + the actual request for one run's
    worth of target-directed collection by a single plugin/capability.

    Usage:

        async with CollectionGateway(scope, capability="http_verify") as gateway:
            target = gateway.authorize(url, operation="soft404_probe")
            if target is None:
                ...  # denied — record why, never request it
                continue
            response = await gateway.http_get(target)

    `authorize()` never touches the network — it is the same fast,
    synchronous decision `AuthorizedCollectionTarget.authorize_verbose()`
    already made. `http_get()` is the only method that does I/O, and it
    physically cannot accept a plain URL string — the parameter type is
    `AuthorizedCollectionTarget`, obtainable only from `authorize()` (or
    another gateway's), which is itself sealed against direct construction
    (see `core/collection/target.py`).
    """

    def __init__(
        self,
        scope: CollectionScope | None,
        *,
        capability: str,
        context: object | None = None,
        upstream_proxy_url: str | None = None,
        extra_headers: dict[str, str] | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.scope = scope
        self.capability = capability
        self.context = context
        self.extra_headers = dict(extra_headers) if extra_headers else {}
        # None means "use core/http_probe.py's own default" — pass
        # Settings.effective_user_agent() to get Hydra's configured UA
        # (including any program-mandated attribution suffix) instead of
        # http_probe's hardcoded "HydraProbe/1.0" placeholder.
        self.user_agent = user_agent
        self._proxy = ScopeEnforcingProxy(
            scope, capability=capability, upstream_proxy_url=upstream_proxy_url
        )
        self.audit: list[GatewayAuditEntry] = []

    async def __aenter__(self) -> CollectionGateway:
        await self._proxy.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._proxy.stop()
        if self.context is not None:
            for record in self._proxy.audit:
                record.collector = self.capability
                append_network_request(self.context, record)

    def authorize(
        self,
        raw: str,
        *,
        operation: str = "",
        reason: str = "",
        strict_opsec: bool = False,
        opsec_allowed: bool = True,
    ) -> AuthorizedCollectionTarget | None:
        """Scope + capability + OPSEC + destination-IP authorization for one
        indicator. Returns `None` on any DENY/UNKNOWN — never raises, never
        partially authorizes. Pure/no I/O beyond the destination-IP
        resolution `AuthorizedCollectionTarget` itself already performs.
        """
        return AuthorizedCollectionTarget.authorize(
            raw,
            self.scope,
            capability=self.capability,
            operation=operation,
            reason=reason,
            strict_opsec=strict_opsec,
            opsec_allowed=opsec_allowed,
        )

    async def http_get(
        self,
        target: AuthorizedCollectionTarget,
        *,
        timeout: int,
        operation: str = "",
    ) -> ResponseSnapshot:
        """GET an already-authorized target through this gateway's
        confinement proxy. The parameter is `AuthorizedCollectionTarget`,
        not `str` — there is no overload that accepts a bare URL, so a
        caller cannot skip `authorize()` by construction, only by
        deliberately reaching past this method into `core/http_probe.py`
        directly (the static guard,
        `tests/test_no_bypass_network_primitives.py`, is what catches that).
        """
        if not isinstance(target, AuthorizedCollectionTarget):
            # Defense in depth beyond the type hint: a caller ignoring
            # static typing (or passing a plain string under `# type:
            # ignore`) still gets a clear, intentional failure here instead
            # of silently requesting an unauthorized destination.
            raise TypeError(
                "CollectionGateway.http_get() requires an AuthorizedCollectionTarget "
                f"(from gateway.authorize()), got {type(target).__name__!r}"
            )
        # core/http_probe.py:http_get is a blocking urllib call.
        kwargs: dict[str, object] = {
            "timeout": timeout,
            "proxy_url": self._proxy.proxy_url,
            "extra_headers": self.extra_headers or None,
        }
        if self.user_agent:
            kwargs["user_agent"] = self.user_agent
        response = await asyncio.to_thread(_http_get, target.raw, **kwargs)
        self.audit.append(
            GatewayAuditEntry(
                hostname=target.hostname,
                capability=self.capability,
                operation=operation or target.capability,
                status_code=response.status_code,
                error=response.error,
            )
        )
        return response

    @property
    def denied(self) -> list[str]:
        """Hostnames the underlying confinement proxy itself refused to
        connect to (e.g. a destination the target's own HTTP client tried to
        reach that was never authorized) — distinct from an `authorize()`
        call returning `None`, which never reaches the proxy at all."""
        return [item.host for item in self._proxy.denied]
