"""AuthorizedCollectionTarget: the only way to obtain one is passing authorize_collection."""

from __future__ import annotations

from core.collection.target import AuthorizedCollectionTarget
from core.intel.scope import CollectionScope

SEED = "app.example-target-test.internal"
OOS = "evil.example-target-test.internal"


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED])


def test_authorize_returns_none_for_out_of_scope_host() -> None:
    assert (
        AuthorizedCollectionTarget.authorize(f"https://{OOS}/x", _scope(), capability="http_probe")
        is None
    )


def test_authorize_returns_none_for_missing_scope() -> None:
    assert (
        AuthorizedCollectionTarget.authorize(f"https://{SEED}/", None, capability="http_probe")
        is None
    )


def test_authorize_returns_none_for_malformed_indicator() -> None:
    assert (
        AuthorizedCollectionTarget.authorize("not a url", _scope(), capability="http_probe") is None
    )
    assert AuthorizedCollectionTarget.authorize("", _scope(), capability="http_probe") is None


def test_authorize_returns_populated_target_for_in_scope_host() -> None:
    target = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}:8443/path?q=1", _scope(), capability="http_probe"
    )
    assert target is not None
    assert target.hostname == SEED
    assert target.scheme == "https"
    assert target.port == 8443
    assert target.raw == f"https://{SEED}:8443/path?q=1"
    assert target.scope_identity == (SEED,)


def test_authorize_respects_opsec_denial_even_when_in_scope() -> None:
    denied = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/",
        _scope(),
        capability="naabu",
        strict_opsec=True,
        opsec_allowed=False,
    )
    assert denied is None

    allowed = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/",
        _scope(),
        capability="httpx",
        strict_opsec=True,
        opsec_allowed=True,
    )
    assert allowed is not None


def test_target_is_immutable() -> None:
    target = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert target is not None
    try:
        target.hostname = "attacker-controlled.test"  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised, "AuthorizedCollectionTarget must be frozen — mutation must fail"
