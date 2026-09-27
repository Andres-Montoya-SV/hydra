# EASM Fase 17 — Capability Architecture

## Purpose

With every intelligence capability built (Fases 06-16), Hydra should
read as "an EASM platform with stable capabilities implemented by
replaceable providers," not "a collection of 33 separate tools." This
phase adds the taxonomy, policy, and metadata layer that makes that true
— on top of Fase 09's existing provider contract, never a rewrite of it.

## 1. Capability taxonomy

`core/capabilities.py::Capability` — a stable, closed enum (Domain
Discovery, DNS, Network Discovery, HTTP, Technology, Visual, TLS, Cloud,
Exposure Detection, External Intelligence, Import, Uncategorized).
`capability_for()` maps each plugin's EXISTING `ReconPlugin.capability`
free-text string (already set by all 33 modules) onto one category —
additive metadata, not a new per-plugin field. A test
(`test_every_real_plugin_capability_string_is_categorized_or_documented_uncategorized`)
asserts every real plugin's string resolves to a real category except
one explicitly accepted exception (`anew`'s `"dedupe"` — a processing
utility, not a product capability).

## 2. Migration to Fase 09's contract

**Nothing to migrate.** Verified directly: every one of the 33 modules
under `modules/` already sets `capability`, `produces`, and the other
Fase 09 contract fields — `provider_kind`/`supported_asset_types` are
left at their inherited defaults for most, which `core/provider_contract.py`
was explicitly designed to derive safely (its own docstring: "Existing
plugins need not all override these during Fase 09"). The taxonomy in
(1) is a read-only projection on top of what's already declared — no
plugin file needed to change.

## 3. Replaceability

Already true by construction, verified rather than rebuilt: nothing in
`core/provider_contract.py` or the new `Capability` taxonomy names a
specific tool as load-bearing — `provider_descriptor()` only ever reads
a plugin's own declared metadata. Swapping WhatWeb for a different
technology-detection provider changes zero lines outside that one
module and its registration.

## 4. Capability policy + compatibility layer

`core/capability_policy.py::capability_enabled()` — a pure function
answering "is this capability currently enabled," built entirely from
EXISTING per-tool flags (`Settings.enable_<tool>`, ~30 of them, all left
completely unchanged) plus one new, purely additive lever:
`disabled_capabilities: frozenset[Capability]`, which can only turn a
capability OFF, never on — "una política nunca autoriza," made literal:
this function cannot grant anything past what individual providers'
existing `is_enabled()` already allows.

**Deliberately not wired into `config/settings.py` or into each of the
33 `is_enabled()` overrides in this cut.** Reasoning: `is_enabled()` is
an abstract method each plugin implements individually — wiring a new
policy layer into all 33 would be a much larger, riskier change than
this phase's own scope justifies for a first pass, and `Settings` is a
heavily-relied-on, already thoroughly-tested file this phase's own
"no reescribir salvo necesario" discipline argues against touching
broadly. `capability_enabled()`/`providers_for_capability()` are fully
correct, tested, and usable today by any caller that already has a
`Settings`-backed plugin list (the `heads` CLI is exactly that caller,
see (9)) — surfacing `disabled_capabilities` through a config file or
CLI flag is a small, separate, low-risk follow-up, not a reason to block
this layer's own correctness.

## 5. Cost/intensity metadata

`core/provider_contract.py::ProviderIntensity` (PASSIVE,
ACTIVE_STANDARD, ACTIVE_HIGH_VOLUME, THIRD_PARTY_API, LLM_BACKED) — a
new field on `ProviderDescriptor`, classified per real tool (e.g.
`subfinder`/`amass` are PASSIVE despite being discovery providers;
`naabu`/`ffuf`/`param_fuzz`/`cloud_bucket_enum` are ACTIVE_HIGH_VOLUME;
`ctlogs`/`whois`/`github_secrets`/etc. are THIRD_PARTY_API). No
LLM-backed provider exists today — the enum value exists for when one
does. No billing engine, per the phase's own "sin motor de facturación."

## 6. Provider selection

**Scoped down, with reasoning.** Full primary/enrichment/fallback/
verification selection with cadence and "last successful observation"
triggers is genuinely greenfield (confirmed: `core/runner.py` gates
purely on `is_enabled()`/`is_runnable()` today, no scheduling concept
exists anywhere under `core/`) — and cadence/scheduling is explicitly
`api/monitoring_worker.py`'s own domain (Speed 1/Speed 2), which Fase 18
(Monitoring Integration, the very next phase) connects to the new EASM
model without rewriting. Building a parallel scheduling concept here
would risk exactly the kind of second, competing system the roadmap's
own reuse-first invariant warns against. What this phase DOES ship:
`core.capability_policy.providers_for_capability()` — the "which
providers serve this capability" half of selection, usable by Fase 18's
own scheduling work without this phase needing to guess at cadence
policy it doesn't own.

## 7. Multi-provider deduplication

Substantially already addressed: Fase 14's technology name normalization
collapses "nginx" (httpx) and "Nginx" (WhatWeb) into one canonical fact
before evidence is even recorded; Fase 10's precedence system already
answers "which of several corroborating sources should a caller trust."
This phase adds one more piece specifically for confidence (see 8) —
no separate cross-provider fact-merging engine was built, since Fase
04's own evidence model already keeps one row per (asset, source,
detail) and Fase 14 already normalizes the content that matters most for
collisions.

## 8. Confidence composition with source independence

`core/confidence_composition.py::compose_confidence()` — new, pure,
deterministic. Groups sources known to read the same underlying signal
(httpx/WhatWeb/security-headers all parse the same HTTP response) into
one cluster (only the best confidence in a cluster counts); genuinely
independent clusters combine via a documented noisy-OR formula, never a
trained/opaque model. Deliberately does NOT replace
`core/confidence.py::update_host_confidence`'s existing `max()`-based
aggregation — that function is already tested and relied on broadly;
this is a new, additive capability for callers (a future risk score,
Fase 21) that need independence-aware composition, not a rewrite of
already-working, security-relevant code.

## 9. CLI: `heads` shows capability and status

`app.py::cmd_heads` — existing `Head`/`Active`/`Opt-in`/`Role` columns
unchanged; added `Capability` (from (1)) and `Status`
(`disabled`/`runnable`/`not runnable`, from the existing
`ToolManager.is_runnable()`, not a new health-check mechanism).

## 10. Redundancy audit

Reviewed every tool against "what unique signal does this add, and could
Hydra already get it another way":

- **No near-zero-contribution tool was found.** Each of the 33 has a
  distinct real function: three domain enumerators (amass, assetfinder,
  subfinder) is the closest thing to overlap, but each uses different
  passive sources and their union is the point (a single one would miss
  real subdomains the others catch — this is the intentional
  multi-source discovery pattern the codebase already documents, not
  redundancy).
- **WhatWeb** was already evaluated in an earlier phase (Fase 14's own
  audit) as adding real signal beyond httpx's `-tech-detect` (plugin-
  based fingerprints httpx doesn't have) — kept, with its confidence
  normalized rather than trusted blindly (Fase 14).
- **gau / waybackurls**: both query URL archives, with different
  backends (Wayback Machine + AlienVault OTX + Common Crawl vs. Wayback
  Machine alone) — kept, since `gau`'s broader source set is a
  genuinely different result, not a duplicate call to the same API.
- No tool is recommended for removal in this pass. If a future phase's
  own usage data shows one contributing nothing in practice, that
  decision belongs to whoever owns that data, with the migration-impact
  documentation the roadmap itself requires before removing anything.

## Non-goals

- No wiring of `capability_policy` into `config/settings.py` or into
  each plugin's `is_enabled()` (see 4).
- No cadence/scheduling engine (see 6) — Fase 18's own concern.
- No rewrite of `core/confidence.py`'s existing aggregation (see 8).
- No tool removed (see 10).
