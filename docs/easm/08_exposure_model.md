# EASM Fase 08 — Exposure Model

Hydra treats a run-scoped Finding as evidence that a detector reported a
condition and an Exposure as the durable, cross-run identity of that condition
on one durable Asset.

Deterministic identity remains:

```text
organization
+ asset
+ detector source
+ detector template/rule
+ normalized endpoint/location
```

Informational findings are excluded. Backfill reads persisted Findings, filters
invalidated hosts and requires an existing durable Asset. It performs no
network collection and changes no scope authorization.

## Lifecycle

The durable lifecycle supports:

```text
OPEN -> RESOLVED -> REOPENED
```

Every observation/resolution/reopening is retained in `exposure_history`.
Every supporting run-scoped Finding is retained through
`exposure_evidence`.

Replaying old evidence is idempotent and can never reopen a resolved exposure.
Only genuinely later evidence can reopen the same Exposure id.

## Provider outcome evidence

Fase 09 now gives Hydra unambiguous provider outcomes. Fase 08 hardening stores
those results durably in `provider_run_outcomes` after each successfully
completed API scan:

- success_with_results
- success_no_results
- partial
- blocked_by_scope
- skipped
- unavailable
- failed

This ledger is operational evidence, not an automatic remediation signal.

A provider succeeding at run level does NOT prove that every individual asset
and every detector rule received exhaustive coverage. Hydra therefore still
refuses to auto-resolve an Exposure merely because the next run lacks the
Finding.

Future automatic resolution must require explicit asset/rule-scoped successful
coverage. Until then, stale-open is preferable to a false-resolved exposure.

## API surface

Fase 08 now exposes tenant-scoped product endpoints:

```text
GET  /organizations/{organization_id}/exposures
GET  /organizations/{organization_id}/exposures/{exposure_id}
GET  /organizations/{organization_id}/exposures/{exposure_id}/evidence
GET  /organizations/{organization_id}/exposures/{exposure_id}/history
POST /organizations/{organization_id}/exposures/{exposure_id}/resolve
```

List requests are bounded and filterable by status, severity and asset id.
All reads require organization membership. Manual resolution requires the owner
role. Foreign tenant ids deliberately return 404 so guessed ids do not disclose
resource existence.

## Security invariants

```text
Finding != Exposure
missing Finding != remediation
provider success != per-asset coverage
provider failure != clean
blocked_by_scope != clean
partial != clean
Exposure != authorization
Exposure != ownership
manual resolution requires organization owner
foreign tenant exposure ids are non-enumerable
```

## Still intentionally deferred

- automatic exposure resolution until asset/rule-scoped detector coverage is
  mechanically provable
- retention-safe copying of source Finding payloads beyond the durable lineage
  currently stored
- richer workflow states such as accepted-risk/suppressed, which should be
  introduced together with audit policy rather than as untracked status strings
- monitoring notifications directly from Exposure transitions; that belongs to
  the monitoring migration phase so there is only one significance/outbox path
