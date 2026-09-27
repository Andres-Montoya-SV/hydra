# EASM Fase 12 — Certificate Intelligence + RDAP

## Purpose

Two enrichment capabilities, built together because they share the same
"registration/certificate data is evidence, never ownership proof"
discipline: (1) classifying what actually changed when a domain's TLS
certificate is renewed, replaced, or gains/loses a SAN; (2) RDAP
enrichment of an already-known domain's registration metadata.

## Certificates: why no new "Certificate" asset type was built

The phase's own instruction is explicit: build a first-class Certificate
entity only "si el modelo actual no basta" (if the current model isn't
already enough). It already was:

- `core/intel/engine.py` already emits `PRESENTS_CERTIFICATE`,
  `SAN_CONTAINS`, and (via `core/intel/correlate.py`'s confidence
  banding) `SHARES_CERTIFICATE` relationships from real `Host.tls`
  captures.
- `api/relationship_backfill.py` (Fase 07) already persists **every**
  `intel_relationships` row into the EASM relationship graph regardless
  of type — these certificate relationships were already flowing into
  the durable, organization-scoped graph before this phase touched
  anything.
- A shared certificate across domains is therefore already visible as a
  `SHARES_CERTIFICATE` relationship — never as asset ownership — with
  zero new code.

A dedicated `certificates` table would also have broken Fase 03's "one
asset, one host" assumption the moment a certificate is shared across
domains (`host_for_asset` has no single answer for "which domain does
this certificate belong to").

**What was genuinely missing**: per-domain change classification — did
this domain's certificate get renewed, replaced by a different
issuer/subject, or gain/lose a SAN. That's what this phase adds:

- `api/observation_identity.py::OBSERVATION_TYPE_CERTIFICATE_PRESENT` —
  a new observation type attached to the DOMAIN asset (same treatment
  Fase 06 already gave `technology_detected`/`security_header_present`),
  carrying the certificate's full shape (fingerprint, subject, issuer,
  validity window, SANs) as one canonical string in the evidence
  `detail` (`api/certificate_events.py::certificate_snapshot_detail`).
- `api/certificate_events.py::classify_certificate_transition()` — pure,
  deterministic classifier: `CERTIFICATE_FIRST_SEEN`, `RENEWED` (same
  subject/issuer, new fingerprint), `CHANGED` (different subject or
  issuer — potentially a compromise or reissue under new ownership),
  `SAN_ADDED`, `SAN_REMOVED`. Can return multiple events for one
  transition (a renewal that also drops a SAN is both `RENEWED` and
  `SAN_REMOVED`, reported as two separately citable facts).
- `certificate_events` table + `api/certificate_backfill.py` — walks
  each domain's certificate-observation history in chronological order
  and records the classified transitions. `UNIQUE(asset_id, run_id,
  event_type, reason)` makes replaying the backfill idempotent.
- `OBSERVATION_TYPE_DOMAIN_REGISTRATION_INFO` also added for
  `Host.registrar`/`registration_created_at`/`registration_expires_at`
  (WHOIS-sourced) — a real gap: this data was already captured on `Host`
  but never flowed into the Evidence/Observation model before this
  phase.

**Observation time vs. validity time**: a certificate's own
`not_before`/`not_after` are carried as opaque strings, never confused
with `Observation.observed_at`/`Evidence.first_seen_at` — the phase's
own explicit requirement.

## RDAP

- `core/collection/rdap_client.py::fetch_rdap_domain()` — SSRF-hardened
  HTTP(S) client, same discipline as `core/collection/whois_client.py`'s
  own TCP referral-chain handling: every hop's destination IP is
  validated via `core/collection/ssrf.py` before connecting (never the
  organization's own `CollectionScope`/`allow_private_network_targets`
  path — RDAP always targets third-party registry infrastructure, exactly
  like WHOIS's own hops), bounded to 3 hops, 2 MiB response cap,
  configurable timeout. Connects to the pre-validated IP while keeping
  the correct TLS SNI/Host header (`_PinnedHTTPSConnection`), closing the
  DNS-rebind gap between the SSRF check and the actual connection.
- Bootstraps through `https://rdap.org/domain/<domain>` — the same "one
  hardcoded, trusted, well-known entry point" pattern
  `modules/ctlogs.py` already uses for `crt.sh`. `rdap.org` typically
  redirects to the authoritative RIR/registry server, whose IP is
  validated like any other hop.
- `core/parsers/rdap.py::parse_rdap_domain_response()` — pure, minimal
  parser: registrar name, registration date, expiration date. Never
  extracts anything from a `registrant` entity (only `registrar`-role
  entities are read) — registration/entity data is evidence, never
  ownership proof, enforced here by simply never reading the fields that
  could imply it.
- `api/rdap_lookup.py::lookup_rdap_for_domain()` — feeds the result
  through Fase 10's `ingest_external_observation_batch` exactly like
  Fase 11's importers did. **Only ever enriches an already-known domain
  asset** — if the looked-up domain isn't already a real `assets` row,
  nothing is recorded (no candidate is created from an RDAP result; RDAP
  is an enrichment capability, never a discovery one in this cut).

## Adversarial tests

- `CT SAN != authorized target` — already proven by Fase 06's own
  existing adversarial test
  (`tests/test_candidate_assets.py::
  TestCandidateNeverFeedsActiveScanningWithoutPromotion`), whose default
  fixture (`_seed_candidate`, `reason="shared certificate SAN"`,
  `CollectReason.CERTIFICATE_SAN`) already exercises exactly a
  CT-discovered certificate-SAN candidate through the real correlation
  pipeline. No new test needed — re-verified it still passes.
- `RDAP result != authorized target` —
  `tests/test_rdap_lookup.py::TestRdapEnrichesOnlyAlreadyKnownAssets::
  test_a_domain_not_already_known_is_never_created_as_an_asset_or_candidate`.
- Sibling SANs never create ownership — the same Fase 06 mechanism;
  `SHARES_CERTIFICATE`/`SAN_CONTAINS` are relationships, never asset
  creation.
- Renewal vs. change classification —
  `tests/test_certificate_events.py`.
- RDAP redirect/size limits, malformed responses —
  `tests/test_rdap_client.py`.
- SSRF hop validation refuses a private-IP redirect target before any
  socket opens — `tests/test_rdap_client.py::TestFetchOneSsrfValidation`.

## Non-goals

- No RDAP for IP networks or ASNs — domain RDAP only in this cut (the
  phase's own three RDAP object types share no bootstrap/query shape;
  domain is the concrete, tested capability delivered here, following
  the same "defer, document, don't half-build" discipline Fase 11 used
  for IVRE).
- No candidate creation from RDAP responses (no new nameserver/related-
  entity discovery signal in this cut).
- No `certificates` table / Certificate asset type (see above).
