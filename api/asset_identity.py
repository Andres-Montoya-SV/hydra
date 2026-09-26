"""Fase 03 (EASM roadmap, docs/easm/00_consolidation_plan.md): the
cross-run Asset identity and reconciliation logic. Every function in
this module is PURE — no database access, no `datetime.now()`, no
randomness — by explicit requirement of the phase's own prompt
("función pura, testeable con fixtures fijos"). `api/control_db.py`'s
`assets`/`asset_identifiers` tables and the backfill in
`api/asset_backfill.py` are the I/O layer built on top of this.

**Identity key format**: reuses `core.intel.model.entity_id()`'s own
`f"{type.lower()}:{key}"` convention (per the Fase 01 consolidation
plan's decision to ABSORB `core/intel/model.py`'s identity scheme, never
reinvent a second one) for the two asset types it already covers
(`domain`, `url`). `port` and `dns_record` are NOT in
`core.intel.model.EntityType` — the phase 03 prompt explicitly requires
them (`core/assets.py`'s own `Port`/`DnsRecord` sub-entities have no
equivalent there) — so this module defines local, analogous key builders
for those two, following the identical `"type:key"` string shape rather
than a different convention. This is additive (two new asset_type
string values), never a change to `core.intel.model.EntityType` itself.

**The interpretation this module makes explicit, since the phase 03
prompt's Spanish list ("dominio, host, URL, puerto abierto, registro
DNS") is ambiguous between "root registrable domain" and "any discovered
hostname"**: `core/assets.py::Host.domain` is used as a Host's own full,
possibly-subdomained hostname (confirmed by `core/store.py`'s
`UNIQUE(run_id, domain)` on the `hosts` table, and by
`core.intel.model.EntityType.DOMAIN` being used for exactly this same
string in `core/intel/engine.py`'s `ingest_hosts`). This module treats
the prompt's "dominio" and "host" as the SAME concept — one `domain`
asset type per distinct `Host.domain` value — rather than inventing a
separate "root domain vs. specific host" split roadmap phase 03 never
asked for explicitly. If a later phase needs the root-domain-as-its-own-
umbrella-asset concept, that is a new, additive asset type, not a
reinterpretation of this one.

**On never fusing two different real assets on weak evidence (the
phase's own adversarial requirement)**: reconciliation here is decided
SOLELY by an exact match on `(asset_type, identity_key)` — a domain
string, a URL string, or a (host, port, protocol)/(host, record_type,
value) tuple either IS the same value as a previously-seen one, or it
is not; there is no fuzzy/heuristic matching step. A secondary signal
like an IP address is never used as a lookup/merge key for a DIFFERENT
primary asset — it is recorded as an `asset_identifier` attached to
whichever domain asset was actually observed with it
(`identifiers_for_host`), and two different domains that happen to
currently share an IP (a shared CDN, the exact adversarial case the
phase's own tests require) simply each get their own separate `ip`
identifier row pointing at their own, separate `asset_id` — this is
what makes an accidental cross-asset merge structurally impossible
here, not a rule enforced by extra application logic on top of a
fuzzier lookup.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from core.assets import Host, normalize_domain, normalize_http_url
from core.intel.model import EntityType, entity_id

# Additive to core.intel.model.EntityType, never a modification of it —
# see this module's own docstring for why PORT/DNS_RECORD don't belong
# in that enum (core/intel/ has no concept of either as its own entity).
ASSET_TYPE_DOMAIN = EntityType.DOMAIN.value.lower()
ASSET_TYPE_URL = EntityType.URL.value.lower()
ASSET_TYPE_PORT = "port"
ASSET_TYPE_DNS_RECORD = "dns_record"
ASSET_TYPE_CLOUD_STORAGE = "cloud_storage"

# The identifier attached to a domain asset for each IP it was observed
# resolving to — descriptive metadata only, NEVER a reconciliation lookup
# key (see module docstring).
IDENTIFIER_TYPE_IP = "ip"


def domain_identity_key(domain: str) -> str:
    return entity_id(EntityType.DOMAIN, normalize_domain(domain))


def url_identity_key(url: str) -> str:
    return entity_id(EntityType.URL, normalize_http_url(url))


def port_identity_key(*, host: str, port: int, protocol: str) -> str:
    return f"{ASSET_TYPE_PORT}:{normalize_domain(host)}:{port}:{protocol.lower()}"


def dns_record_identity_key(*, host: str, record_type: str, value: str) -> str:
    normalized_value = value.strip().lower().rstrip(".")
    return (
        f"{ASSET_TYPE_DNS_RECORD}:{normalize_domain(host)}:"
        f"{record_type.upper()}:{normalized_value}"
    )


def cloud_storage_identity_key(*, provider: str, resource_name: str) -> str:
    """Stable provider-qualified identity for external cloud storage."""
    normalized_provider = provider.strip().lower()
    normalized_name = resource_name.strip().lower()
    return f"{ASSET_TYPE_CLOUD_STORAGE}:{normalized_provider}:{normalized_name}"


def cloud_storage_observation(record: Mapping[str, object]) -> AssetObservation:
    """Reduce one raw cloud_resources row to the normal reconciliation shape."""
    provider = str(record.get("provider") or "cloud").strip().lower()
    name = str(record.get("resource_name") or record.get("bucket") or "").strip().lower()
    identifiers: list[tuple[str, str]] = []
    url = str(record.get("url") or "").strip()
    if url:
        identifiers.append(("url", url))
    return AssetObservation(
        asset_type=ASSET_TYPE_CLOUD_STORAGE,
        identity_key=cloud_storage_identity_key(provider=provider, resource_name=name),
        identifiers=tuple(identifiers),
    )


@dataclass(frozen=True)
class AssetObservation:
    """One (asset_type, identity_key) pair discovered in a single run,
    plus whatever secondary identifiers (IPs) were observed alongside it
    — the pure, DB-free shape `identities_for_host` reduces a `Host`
    into, and what `reconcile_observation` consumes."""

    asset_type: str
    identity_key: str
    identifiers: tuple[tuple[str, str], ...] = ()  # (identifier_type, identifier_value)


def identities_for_host(host: Host) -> list[AssetObservation]:
    """Every asset this ONE `Host` (one run's observation of one
    hostname, plus its attached ports/DNS records/URLs) implies —
    deliberately NOT including `TlsCertificate`/`Finding`/
    `TechnologyFinding` in Fase 03 (out of the phase's own required
    asset-type list; a later phase can extend this the same additive
    way `port`/`dns_record` were added here, never by changing this
    function's existing return shape for the types it already covers)."""
    observations: list[AssetObservation] = [
        AssetObservation(
            asset_type=ASSET_TYPE_DOMAIN,
            identity_key=domain_identity_key(host.domain),
            identifiers=tuple((IDENTIFIER_TYPE_IP, ip) for ip in host.ips),
        )
    ]
    for port in host.ports:
        observations.append(
            AssetObservation(
                asset_type=ASSET_TYPE_PORT,
                identity_key=port_identity_key(
                    host=port.host, port=port.port, protocol=port.protocol
                ),
            )
        )
    for record in host.dns_records:
        observations.append(
            AssetObservation(
                asset_type=ASSET_TYPE_DNS_RECORD,
                identity_key=dns_record_identity_key(
                    host=record.host, record_type=record.record_type, value=record.value
                ),
            )
        )
    for url in host.urls:
        observations.append(
            AssetObservation(asset_type=ASSET_TYPE_URL, identity_key=url_identity_key(url.url))
        )
    return observations


@dataclass(frozen=True)
class ExistingAsset:
    """The minimal, DB-free shape of an already-persisted `assets` row
    that `reconcile_observation` needs to decide "same asset" vs "new
    asset" — never a live `ControlDB` handle, keeping this function
    pure."""

    asset_id: str
    asset_type: str
    identity_key: str


@dataclass(frozen=True)
class ReconciliationDecision:
    """What `reconcile_observation` decided for ONE `AssetObservation`:
    reuse `asset_id` (an existing asset, `is_new=False`) or mint a new
    one (`is_new=True`) — the caller (the I/O layer) is responsible for
    actually persisting this decision (an INSERT for a new asset, an
    `UPDATE ... SET last_seen_at` for an existing one, plus any
    `identifiers` rows)."""

    asset_id: str
    asset_type: str
    identity_key: str
    is_new: bool
    identifiers: tuple[tuple[str, str], ...]


def reconcile_observation(
    *,
    observation: AssetObservation,
    existing_by_identity_key: dict[str, ExistingAsset],
    new_asset_id: Callable[[], str],
) -> ReconciliationDecision:
    """The single reconciliation rule, stated plainly: look up
    `observation.identity_key` in `existing_by_identity_key` (already
    scoped to one organization and one asset_type by the caller — this
    function itself never filters by organization_id, so a caller that
    accidentally passed a cross-organization dict would be the bug, not
    this function; `reconcile_host_observations` below is the one real
    caller and always builds this dict correctly-scoped). An exact match
    means "the same real-world asset, seen again" (this is what makes an
    asset that disappeared for a run and reappeared later reconcile to
    the SAME row, never a duplicate — the lookup dict is built from ALL
    assets ever recorded for this organization/type, not just the
    immediately preceding run). No match means a genuinely new asset —
    `new_asset_id()` mints its id; callers pass a deterministic factory
    in tests (e.g. a fixed sequence) to keep this whole call
    deterministic end to end, and a real random generator
    (`secrets.token_hex`) in production, where determinism doesn't
    matter but a genuinely unpredictable id does."""
    existing = existing_by_identity_key.get(observation.identity_key)
    if existing is not None:
        return ReconciliationDecision(
            asset_id=existing.asset_id,
            asset_type=existing.asset_type,
            identity_key=existing.identity_key,
            is_new=False,
            identifiers=observation.identifiers,
        )
    return ReconciliationDecision(
        asset_id=new_asset_id(),
        asset_type=observation.asset_type,
        identity_key=observation.identity_key,
        is_new=True,
        identifiers=observation.identifiers,
    )


def reconcile_host_observations(
    *,
    host: Host,
    existing_by_identity_key: dict[str, ExistingAsset],
    new_asset_id: Callable[[], str],
) -> list[ReconciliationDecision]:
    """Convenience wrapper: `identities_for_host` then
    `reconcile_observation` for each — the shape `api/asset_backfill.py`
    actually calls per `Host` row it reads back from one run."""
    return [
        reconcile_observation(
            observation=observation,
            existing_by_identity_key=existing_by_identity_key,
            new_asset_id=new_asset_id,
        )
        for observation in identities_for_host(host)
    ]
