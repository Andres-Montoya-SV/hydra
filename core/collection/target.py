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

This does not replace ``authorize_collection``/``allows_active_collection``;
plugins that already call them correctly do not need to change. It exists
for call sites where making the authorization proof part of the type,
rather than a convention every caller must remember to follow, is worth the
extra step. Wired into one concrete call site so far —
``modules/httpx.py``'s redirect-hop resolution (``_fetch_single_hop`` takes
the target object itself, not a URL string). Retrofitting the rest of the
plugins is the still-open ``CollectionGateway`` work, not done here; the
browser guard (``modules/browser_probe.py``) still returns a plain bool,
since Playwright's routing API only needs true/false to decide abort vs.
continue and gains nothing from the richer type.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from core.intel.scope import CollectionScope


@dataclass(frozen=True)
class AuthorizedCollectionTarget:
    """Proof that `raw` was checked by `authorize_collection` and ALLOWed.

    Immutable. The only way to obtain one is `AuthorizedCollectionTarget.authorize(...)`
    returning non-None — there is no constructor that skips the check.
    """

    raw: str
    hostname: str
    scheme: str
    port: int | None
    capability: str
    reason: str
    scope_identity: tuple[str, ...]

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
    ) -> AuthorizedCollectionTarget | None:
        """Return an authorized target, or None on DENY/UNKNOWN.

        Never raises on a bad indicator or missing scope — those are DENY
        outcomes (None), consistent with the rest of the authorization
        layer's fail-closed contract.
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
            return None
        text = (raw or "").strip()
        has_scheme = "://" in text
        parsed = urlparse(text if has_scheme else f"//{text}")
        return cls(
            raw=raw,
            hostname=result.hostname,
            scheme=parsed.scheme if has_scheme else "",
            port=parsed.port,
            capability=result.operation,
            reason=result.reason,
            scope_identity=tuple(scope.seed_domains) if scope is not None else (),
        )
