# Hydra architecture

Hydra is an evidence-driven infrastructure intelligence engine. SQLite is the
source of truth. The in-memory graph is a derived view. Host remains the
reporting projection.

This document describes the system **as implemented**. `docs/ARCHITECTURE_CURRENT.md`
is the runtime checklist (bounds, CLI, schema, collect vs observe).

---

## Control flow

```
indicator (CLI seed)
  → collectors (subprocess-isolated plugins)
  → artifacts
  → parsers → Host (reporting view)
  → IntelEngine
       entities / observations / evidence / relationships
       scope-aware indicator queue
  → optional bounded follow-up (depth ≤ MAX_DISCOVERY_DEPTH)
  → correlation (named signals, not magic integers)
  → SQLite persist
  → query CLI / reports / field-level diff
```

Collection is no longer assumed to happen once. Follow-up is explicit, bounded,
and refused for `OUT_OF_SCOPE` / `UNKNOWN`.

---

## Entity model

Independently addressable entities (stable IDs):

| Type | ID |
|---|---|
| Domain | `domain:{normalized}` |
| IPAddress | `ip_address:{addr}` |
| Certificate | `certificate:{sha256}` |
| ASN | `asn:{asn}` |
| Nameserver | `nameserver:{fqdn}` |
| URL / HTTPService / Technology | keyed by URL or name |

Certificate identity is the leaf SHA-256 fingerprint. It does **not** depend on
sorted SANs, the first N SANs, or hostname. CT records without a fingerprint
use `crtsh:{id}` or `serial:{issuer,serial}` as a provisional key and are
merged onto the fingerprint entity when the SAN set matches a later TLS
observation.

`Host` is not deleted. It is a reporting view over collected domains: IPs,
certificates, HTTP services, technologies, observations, and relationships.

---

## Observation model

Every observation records what, where, when, how, and scope status.

`virusinspector.top` observed as a SAN on `certificate:ABC` (source
`certificate_transparency` / `tls`) is not collapsed into "subfinder found a
host". Provenance types stay distinct.

---

## Relationship and evidence model

Relationships are first-class SQLite rows:

- `PRESENTS_CERTIFICATE` (VERY_HIGH — leaf fingerprint)
- `SAN_CONTAINS` (VERY_HIGH)
- `RESOLVES_TO`
- `SHARES_CERTIFICATE` (HIGH only for identified certs with modest SAN
  diversity; decays to MEDIUM/LOW as SAN / eTLD+1 cardinality grows;
  unidentified certificates do not create this edge)
- `SHARES_IPV4` / `SHARES_IPV6` (MEDIUM on cloud tenancy, HIGH otherwise)
- `SHARES_NAMESERVER` / `SHARES_ASN` (MEDIUM)
- `SHARES_FAVICON` / `SHARES_BODY_HASH` (MEDIUM unless an independent
  second signal corroborates the pair)
- `SHARES_TLS_CHARACTERISTICS` (LOW)

Each row has `confidence` (named band), `strength` (named reason),
`evidence_id`, `first_seen`, `last_seen`. Evidence answers why the edge exists.

Hydra does **not** create actor, owner, threat-actor, or campaign entities.

---

## Scope model

| Status | Active collection |
|---|---|
| `IN_SCOPE` | Allowed (still subject to bounds) |
| `OUT_OF_SCOPE` | Forbidden — observation only |
| `UNKNOWN` | Forbidden |

Seeds are in scope. With `SCOPE_FILE`, that file is authorization. Without it,
only names under a seed's registrable domain are in scope. Off-root certificate
SANs are recorded as `OUT_OF_SCOPE` / `NOT_ALLOWED` and are not DNS-resolved or
HTTP-probed.

Discovery ≠ authorization.

---

## Indicator lifecycle

```
OBSERVED → (optional) RELATED → scope check
  IN_SCOPE + depth ≤ max → ELIGIBLE_FOR_COLLECTION → COLLECTED
  else → NOT_ALLOWED / NOT_COLLECTED
```

The queue deduplicates, stores parent, reason (`CERTIFICATE_SAN`,
`DNS_RESOLUTION`, `SEED`, …), depth, and evidence.

---

## Collection lifecycle and bounds

Configurable (conservative defaults):

- `MAX_DISCOVERY_DEPTH` (default 1)
- `MAX_FOLLOWUP_INDICATORS` (50)
- `MAX_HTTP_PROBES` / `MAX_DNS_PROBES`
- `MAX_RUNTIME`
- `MAX_ENTITIES` / `MAX_RELATIONSHIPS`
- `ENABLE_FOLLOWUP_COLLECTION`

Depth 0 is the original target. Depth 1 is a direct CT/TLS/DNS discovery.
There is no unbounded recursion.

---

## Correlation semantics

Same leaf certificate fingerprint is strong infrastructure evidence
(`VERY_HIGH`/`HIGH`). A shared Google Cloud IP (`34.0.0.0/8`, including
`34.75.127.116`) is `shared_cloud_tenancy` at `MEDIUM`. It is not treated as
dedicated ownership and does not become "same actor".

---

## Historical model

`core/diff.py` compares the current run to the most recent **finished** run
whose target set overlaps. It does not use `others[0]`.

Field changes include IP/IPv4/IPv6, certificate fingerprint, SAN add/remove,
validity, ports, HTTP status/title, technologies, favicon/body hash, ASN, and
nameservers.

---

## Query CLI

These read `output/recon.db` and do not rescan:

```
python app.py investigate DOMAIN
python app.py investigate --entity DOMAIN
python app.py graph DOMAIN
python app.py relationships DOMAIN
python app.py evidence DOMAIN
python app.py evidence RELATIONSHIP_ID
python app.py certificates DOMAIN
python app.py indicators DOMAIN
python app.py diff DOMAIN
python app.py diff RUN_A RUN_B
```

`investigate` includes `explanations` (fingerprint, SAN cardinality, tenancy,
named confidence, `active_collection`). Graph is a neighborhood view over
`intel_entities` / `intel_relationships`, not `graph_*` tables.

---

## Graph

Derived from SQLite. Certificate nodes use `certificate:{sha256}`. Edges carry
relationship type, named confidence, evidence id, first_seen, last_seen.

---

## Risk

Surface risk (`core/intelligence/risk.py`) answers "what deserves attention?"
(auth endpoints, weak TLS, findings).

Correlation answers "what is technically related?" Shared certificate count may
be attached as an explainable Host note. Shared cloud IP is labeled tenancy,
not criticality.

Attribution is never generated.

---

## Extension model

Plugins remain subprocess-isolated. They may attach
`PluginResult.data["intel"]` as a `StructuredEmission`:

```python
produces: ["Domain", "Certificate"]
domains / ip_addresses / certificates
relationships: [{relationship_type, source_entity, target_entity, ...}]
followups: [{kind, reason}]
```

Artifact files and parsers still work. A collector does not need a new parser
class to land structured entities, but runner stage placement and a settings
flag are still required for a new external tool.

---

## Security model

Unchanged controls: no `shell=True`, output caps, path confinement,
`STRICT_OPSEC`, scope fail-closed on seeds, wildcard/tarpit/soft-404, certifi
HTTPS, hostile parser input. Scope is now also enforced per indicator.
