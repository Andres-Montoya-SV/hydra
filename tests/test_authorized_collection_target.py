"""AuthorizedCollectionTarget: the only way to obtain one is passing authorize_collection."""

from __future__ import annotations

import copy
import dataclasses
import pickle

import pytest

from core.collection.target import AuthorizedCollectionTarget
from core.intel.scope import CollectionScope

SEED = "app.example-target-test.internal"
OOS = "evil.example-target-test.internal"


@pytest.fixture(autouse=True)
def _fake_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """`SEED`/`OOS` are synthetic `.internal` names that never resolve.

    These tests exercise hostname/scope/OPSEC authorization, not the
    destination-IP SSRF layer (`core/collection/ssrf.py`, tested on its own
    in `tests/test_ssrf_destination_policy.py`) — stub DNS to a fixed
    public-looking address so that orthogonal, real-DNS-dependent check
    doesn't turn every synthetic-domain test here into a DNS-resolution
    test by accident.
    """
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["203.0.113.10"])


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


def test_direct_construction_cannot_forge_a_capability() -> None:
    """The exact attack this class exists to prevent: a plugin author (or a
    malicious plugin) building an `AuthorizedCollectionTarget` by hand for a
    hostname that was never actually checked against `CollectionScope`. A
    plain `@dataclass(frozen=True)` would allow this — `frozen` only blocks
    mutation *after* construction, not construction itself. This must raise,
    not silently produce a usable, forged "authorization"."""
    with pytest.raises(TypeError):
        AuthorizedCollectionTarget(
            raw=f"https://{OOS}/",
            hostname=OOS,
            scheme="https",
            port=None,
            capability="http_probe",
            reason="fabricated",
            scope_identity=(SEED,),
        )


def test_forging_with_every_plausible_field_combination_still_fails() -> None:
    """Not just the empty/malformed case — even a field set that looks
    exactly like a real authorized target's output must be rejected."""
    real = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert real is not None
    forged_fields = dataclasses.asdict(real)
    forged_fields["hostname"] = OOS
    forged_fields["raw"] = f"https://{OOS}/"
    with pytest.raises(TypeError):
        AuthorizedCollectionTarget(**forged_fields)


def test_dataclasses_replace_cannot_forge_a_capability_either() -> None:
    """`dataclasses.replace()` is the classic escape hatch for "frozen"
    dataclasses — it still calls `__init__` under the hood, so a naive seal
    (e.g. a sentinel default value) would leak through unchanged fields.
    This must fail exactly like direct construction."""
    real = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert real is not None
    with pytest.raises(TypeError):
        dataclasses.replace(real, hostname=OOS, raw=f"https://{OOS}/")


def test_copy_and_deepcopy_cannot_retarget_an_authorized_object() -> None:
    """copy/deepcopy of a frozen dataclass produce another instance of the
    same class, but they do not let a caller swap the hostname: the
    resulting object still points at the originally authorized host. A
    caller who then tries to mutate it hits the frozen barrier. This is
    conventional misuse, not a bypass."""
    real = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert real is not None
    cloned = copy.copy(real)
    deep = copy.deepcopy(real)
    assert cloned.hostname == SEED
    assert deep.hostname == SEED
    assert cloned.raw == real.raw
    with pytest.raises(Exception):
        cloned.hostname = OOS  # type: ignore[misc]
    with pytest.raises(Exception):
        deep.raw = f"https://{OOS}/"  # type: ignore[misc]


def test_pickle_roundtrip_is_not_a_forgery_path() -> None:
    """Pickle reconstructs via ``__new__`` + state restore, not ``__init__``.
    That is deliberate same-process (or cross-process) reconstruction of an
    already-authorized value, not a way to mint a new capability for an
    unauthorized host. After unpickle the hostname is still the original
    authorized one; there is no public hook to pickle an OOS hostname into
    an AuthorizedCollectionTarget that authorize() never produced."""
    real = AuthorizedCollectionTarget.authorize(
        f"https://{SEED}/", _scope(), capability="http_probe"
    )
    assert real is not None
    restored = pickle.loads(pickle.dumps(real))
    assert isinstance(restored, AuthorizedCollectionTarget)
    assert restored.hostname == SEED
    assert restored.raw == real.raw
    assert restored.hostname != OOS


def test_object_new_without_authorize_is_not_a_usable_target() -> None:
    """``object.__new__`` can allocate an instance (Python has no way to
    stop that) but the resulting object has no authorized field values —
    CollectionGateway.http_get() would still type-check it as the class,
    which is why this is classified as deliberate same-process code
    execution, outside the plugin threat model. Documented, not claimed
    sealed."""
    raw = object.__new__(AuthorizedCollectionTarget)
    assert not hasattr(raw, "hostname") or getattr(raw, "hostname", None) != OOS
    with pytest.raises(TypeError):
        AuthorizedCollectionTarget(
            raw=f"https://{OOS}/",
            hostname=OOS,
            scheme="https",
            port=None,
            capability="http_probe",
            reason="object_new_forge",
            scope_identity=(SEED,),
        )
