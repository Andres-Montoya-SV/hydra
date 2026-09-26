# Exposure integration review

Deterministic identity: organization + asset + detector source/template + normalized
endpoint. Informational findings are excluded. Backfill reads persisted Findings,
filters invalidated hosts and requires an existing durable Asset. It performs no
network collection and changes no scope authorization.

Each observation preserves account/run/finding lineage. `exposure_history` records
observed, resolved and reopened events with detector/reason and timestamps.
Replaying the same input is idempotent and cannot reopen a resolved exposure.
Only a genuinely later observation can reopen it; resolution details remain in
history and on the row. Missing findings are NOT proof of remediation: a failed or
skipped detector must never mark a risk resolved. Resolution therefore remains
explicit until successful detector coverage is recorded.

Regression fixture: five runs -> one exposure, five evidence rows; resolve ->
replay all five -> still resolved; sixth later observation -> same row reopened,
seven history entries. Foreign account/run evidence and missing detector rules
are rejected at the persistence boundary.

This is foundation work, not completion of the entire exposure roadmap: the
live monitoring integration, API authorization surface, retention-safe evidence
copy and in-progress workflow remain separate pending work. Existing report
pipelines are not silently redirected to this model.
