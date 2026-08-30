"""A concrete network target that has already passed collection authorization.

The rest of the codebase mostly passes plain ``str`` between authorization
and network code: a plugin calls ``allows_active_collection(url, scope)``,
gets back a ``bool``, and is trusted to actually check it before making a
request. Nothing stops a bug from skipping that check, or from a network
primitive accepting whatever string a caller hands it regardless of whether
it was ever checked at all.

``AuthorizedCollectionTarget`` is the alternative: a value that can only be
constructed by actually calling ``authorize_collection`` and getting ALLOW.
A network primitive that requires one of these — instead of ``url: str`` —
cannot be handed an unauthorized destination and "forget" to check it,
because there is no public constructor path that skips the check.

**Sealed construction.** A plain ``@dataclass(frozen=True)`` is NOT sealed —
anyone can call ``AuthorizedCollectionTarget(raw="https://evil.example",
hostname="evil.example", ...)`` directly and get an object that looks
identical to a real authorization proof; nothing about `frozen=True` stops
construction, only mutation afterward. This class's public constructor
(``__init__``, and therefore ``dataclasses.replace()``, which always calls
it) unconditionally raises via ``__post_init__``. The only way to obtain an
instance is ``_construct()``, a private classmethod that builds the object
via ``object.__new__`` + direct attribute assignment, bypassing ``__init__``
entirely — called only from ``authorize_verbose()`` below. This is "sealed"
in the sense that matters for this codebase's threat model (a plugin author
cannot accidentally or conventionally fabricate a capability the same way
they'd construct any other dataclass); it is not sealed against a caller who
deliberately imports and calls a leading-underscore private classmethod with
a hand-built field set — Python has no construct for that, and pretending
otherwise would be a false guarantee. The static guard
(``tests/test_no_bypass_network_primitives.py``) and code review are what
catch *that* level of deliberate circumvention.

This does not replace ``authorize_collection``/``allows_active_collection``;
plugins that already call them correctly do not need to change. It exists
for call sites where making the authorization proof part of the type,
rather than a convention every caller must remember to follow, is worth the
extra step. Wired into ``modules/httpx.py``'s redirect-hop resolution and
``core/collection/gateway.py:CollectionGateway`` (the shared entry point for
the plugins retrofitted onto it — see that module for which ones and why the
rest are not yet).
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any
from urllib.parse import urlparse

from core.intel.scope import CollectionScope


@dataclass(frozen=True)
class AuthorizedCollectionTarget:
    """Proof that `raw` was checked by `authorize_collection` and ALLOWed.

    Immutable, and its own public constructor always rejects direct use —
    see the module docstring for exactly what "sealed" means here. The only
    way to obtain one is `AuthorizedCollectionTarget.authorize(...)` /
    `.authorize_verbose(...)` returning non-None.
    """

    raw: str
    hostname: str
    scheme: str
    port: int | None
    capability: str
    reason: str
    scope_identity: tuple[str, ...]
    resolved_ips: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        raise TypeError(
            "AuthorizedCollectionTarget cannot be constructed directly (this "
            "includes dataclasses.replace(), which also calls __init__) — "
            "use AuthorizedCollectionTarget.authorize()/.authorize_verbose()."
        )

    @classmethod
    def _construct(cls, **field_values: Any) -> AuthorizedCollectionTarget:
        """The one path that actually produces an instance: bypasses
        `__init__`/`__post_init__` via `object.__new__` + direct attribute
        assignment. Private — called only from `authorize_verbose` below."""
        obj = object.__new__(cls)
        for f in fields(cls):
            object.__setattr__(obj, f.name, field_values[f.name])
        return obj

    @classmethod
    def authorize(
        cls,
        raw: str,
        scope: CollectionScope | None,
        *,
        capability: str,
        operation: str = "",
        reason: str = "",
        strict_opsec: bool = False,
        opsec_allowed: bool = True,
        validate_destination_ip: bool = True,
    ) -> AuthorizedCollectionTarget | None:
        """Return an authorized target, or None on DENY/UNKNOWN.

        Never raises on a bad indicator or missing scope — those are DENY
        outcomes (None), consistent with the rest of the authorization
        layer's fail-closed contract. See `authorize_verbose` for a variant
        that also reports *why* a DENY happened (scope vs. destination-IP).
        """
        target, _reason = cls.authorize_verbose(
            raw,
            scope,
            capability=capability,
            operation=operation,
            reason=reason,
            strict_opsec=strict_opsec,
            opsec_allowed=opsec_allowed,
            validate_destination_ip=validate_destination_ip,
        )
        return target

    @classmethod
    def authorize_verbose(
        cls,
        raw: str,
        scope: CollectionScope | None,
        *,
        capability: str,
        operation: str = "",
        reason: str = "",
        strict_opsec: bool = False,
        opsec_allowed: bool = True,
        validate_destination_ip: bool = True,
    ) -> tuple[AuthorizedCollectionTarget | None, str]:
        """Same decision as `authorize`, plus a denial reason for callers
        (the network audit trail) that need to distinguish `out_of_scope`
        from `blocked_private_ip`/`dns_resolution_failed` rather than seeing
        a bare `None` either way.

        `validate_destination_ip` (default True) adds an independent second
        gate after the hostname/scope check passes: the hostname is resolved
        and every resolved IP is checked against
        `core/collection/ssrf.py`'s private/loopback/link-local/CGNAT/
        metadata blocklist, unless `scope.allow_private_network_targets` is
        set. This closes the gap where an in-scope *hostname* resolves to an
        address Hydra must never touch by default — hostname authorization
        alone says nothing about the destination IP a connection actually
        reaches. Fails closed on a DNS resolution error, exactly like every
        other check here.
        """
        from core.intel.authorize import authorize_collection

        result = authorize_collection(
            raw,
            scope,
            capability=capability,
            operation=operation,
            reason=reason,
            strict_opsec=strict_opsec,
            opsec_allowed=opsec_allowed,
        )
        if not result.allowed:
            return None, "out_of_scope"
        text = (raw or "").strip()
        has_scheme = "://" in text
        parsed = urlparse(text if has_scheme else f"//{text}")
        resolved_ips: tuple[str, ...] = ()
        if validate_destination_ip and result.hostname:
            from core.collection.ssrf import validate_destination_ips

            allow_private = bool(scope is not None and scope.allow_private_network_targets)
            decision = validate_destination_ips(
                result.hostname, allow_private_network_targets=allow_private
            )
            if not decision.allowed:
                return None, decision.reason
            resolved_ips = decision.resolved_ips
        target = cls._construct(
            raw=raw,
            hostname=result.hostname,
            scheme=parsed.scheme if has_scheme else "",
            port=parsed.port,
            capability=result.operation,
            reason=result.reason,
            scope_identity=tuple(scope.seed_domains) if scope is not None else (),
            resolved_ips=resolved_ips,
        )
        return target, "in_scope"
