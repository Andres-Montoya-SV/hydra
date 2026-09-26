# EASM Fase 09 — Cloud Asset Identity Foundation

## Problem fixed

Hydra already has an explicitly-authorized `cloud_bucket_enum` collector,
but its legacy parser represents a discovered storage bucket as
`Host(domain=bucket_name)`. That shape is useful for backward-compatible
finding/report plumbing, but it is not a correct EASM identity model: a cloud
storage resource is not a DNS domain.

Fase 09 introduces a canonical path alongside that legacy compatibility path.

## Run-scoped raw model

Authorized cloud discoveries are persisted in `core/store.py::cloud_resources`
with:

- provider
- resource type
- resource name
- provider URL
- classification
- existence/listability state
- status/body hash
- raw artifact
- confidence

This table is run-scoped raw evidence, just like the existing Host-shaped raw
tables. It does not replace the collector artifact.

## Cross-run identity

The control-plane asset is:

```text
asset_type = cloud_storage
identity_key = cloud_storage:<provider>:<resource_name>
```

Provider qualification is required. The same label in S3 and GCS is two
different assets.

The provider itself is deliberately **not** stored as an
`asset_identifier`: identifiers are organization-unique, so a shared value
such as `cloud_provider=s3` would incorrectly collide across every S3 asset.
The provider belongs in the primary identity key.

A provider URL may be stored as a secondary identifier because it identifies
that concrete resource.

## Temporal semantics

Each run creates a neutral `cloud_storage_observed` observation whose evidence
contains the provider classification and listability state.

Therefore:

```text
s3/example-assets : exists_private
          ↓
s3/example-assets : public_listable
```

is one persistent asset with changed evidence/history, never two assets.

## Authorization boundary

This phase adds **zero new cloud requests**. Collection authorization remains
owned by the existing `CloudBucketEnumPlugin` + `CollectionGateway` path and
its explicit `CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED` opt-in.

```text
cloud asset identity != authorization
resource exists != ownership proof
public listable != automatic compromise
provider URL != domain asset
```

## Compatibility

The legacy `CloudBucketEnumParser` finding path remains temporarily for report
compatibility. EASM identity/backfill no longer depends on treating the bucket
label as a Host. A later cleanup phase can remove that compatibility projection
once reports/API consumers read `cloud_storage` assets directly.
