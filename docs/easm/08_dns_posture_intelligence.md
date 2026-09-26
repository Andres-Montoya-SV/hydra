# EASM Fase 08 — DNS Posture Intelligence

## Decision

Hydra already has DNS posture classification in
`core.validation.engine.annotate_dns_record()`. It tags normalized DNS
records with deterministic facts such as:

- `spf`
- `weak-spf`
- `dmarc`
- `monitoring-only-dmarc`
- `certificate-authority-policy`
- `mail-surface`
- `service-discovery`
- `takeover-watch`
- `domain-verification`

Fase 08 does **not** add another DNS scanner or another risk model.

Instead, these existing tags become durable `dns_posture_tag`
Observations attached to the exact DNS-record asset that produced them.

```text
dnsx
  ↓
DnsRecord
  ↓
annotate_dns_record()
  ↓
security_tags[]
  ↓
dns_posture_tag Observation
  ↓
Evidence
  ↓
Fase 05 change digest/history
```

This means a posture transition can be represented cross-run using the
existing temporal engine, for example:

```text
v=spf1 ~all
   ↓
v=spf1 +all

or

DMARC p=none
   ↓
DMARC p=reject
```

when those records are part of the collected DNS evidence.

## Semantics

```text
DNS posture observation != vulnerability
missing CAA != vulnerability
MX present != vulnerability
takeover-watch != confirmed takeover
weak-spf != proven spoofing
```

Only the existing validation layer decides which deterministic labels apply;
this phase merely makes those facts persistent and historical.

## Network behavior

No additional network requests are introduced. Fase 08 operates on
`DnsRecord.security_tags` already derived from dnsx output.

## Why this shape

The DNS record remains the asset identity. A posture label is an observation
about that record, not a new asset type and not an Exposure. This keeps the
Fase-03/Fase-04 identity model intact and lets Fase 05 detect changes without a
parallel DNS-posture table.


## Provider boundary

Fase 08 is provider-agnostic. Today the tags originate from dnsx-normalized
`DnsRecord` objects, but a future DNS provider may contribute the same
canonical record/tag shape without changing the temporal observation model.
The provider discovers evidence; Hydra owns the posture semantics.
