# Visual Asset Intelligence

Visual Asset Intelligence extends Hydra's existing, already-confined
`browser_probe`. It does not introduce a second browser engine or a second
asset database.

## Why browser_probe, not gowitness

Hydra already has a Playwright/WebKit collector that is:

- opt-in
- routed through ScopeEnforcingProxy
- guarded per request and WebSocket
- covered by live confinement tests
- compatible with researcher attribution headers

Adding another screenshot engine would duplicate network/security policy before
adding meaningful EASM capability.

## Captured data

For each successfully rendered HTTP service Hydra can retain:

- rendered page title
- final browser URL
- redirect chain
- rendered HTML SHA-256
- bounded viewport screenshot
- screenshot SHA-256
- relative HTML artifact path
- relative screenshot artifact path

HTML and screenshots are owner-only artifacts. Paths stored in SQLite are
relative to the run directory; analyst-local absolute paths are never embedded
in shared output.

## Bounded screenshot policy

Screenshots intentionally use the configured mobile viewport rather than
`full_page=True`. A hostile page can create effectively unbounded document
height, making a full-page screenshot an avoidable memory/disk amplification
vector.

## Persistence

Visual metadata normalizes into the existing `HttpService` model:

```text
browser_probe
    ↓
HttpService
    ├── title
    ├── body_hash              (rendered HTML SHA-256)
    ├── response_fingerprint   (screenshot SHA-256)
    └── screenshot_path
```

The `http_services` SQLite table now persists `screenshot_path`, including a
migration for existing databases.

If httpx already created the canonical service URL, browser metadata enriches
that service instead of creating a duplicate or being discarded.

## Change semantics

The hashes are neutral per-run observations. This change deliberately does NOT
feed screenshot/rendered-HTML hashes directly into Fase 05's generic asset
change digest.

Dynamic timestamps, rotating banners, ads, counters, personalization, and
other harmless rendering differences can alter a pixel/hash every run. A later
visual-history layer can apply normalization/perceptual thresholds before
emitting a `VISUAL_CONTENT_CHANGED` event.

Therefore:

```text
visual difference != compromise
visual difference != defacement
visual observation != exposure
visual observation != authorization
```

Cloaking detection remains its own existing finding and retains its existing
manual-verification language.
