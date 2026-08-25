# Hydra readiness report

**Date:** 2026-08-24  
**Repository:** this workspace (`Andres-Montoya-SV/hydra`)  
**Method:** forensic runtime audit (`docs/ARCHITECTURE_AUDIT.md`), control-loop refactor, then a second adversarial review that treated the new code as untrusted.  
**Test proof used:** 356 pytest cases, including `PipelineRunner.run()` and `app.main()` with stubbed collectors. Tests that copy finished artifacts and call `finalize` were not counted as proof of the loop.

**Verdict: READY FOR CONTROLLED BETA**

This is not `READY`. Residual tool-level fetches, browser subresources, and crawler-internal navigation are still not fully bound by `authorize_collection`. It is also not `NOT READY`: the production path is collect → intelligence → authorize → follow-up sidecars → union → evidence → hypothesis → collection attempts → SQLite → explanation.

**Post-audit hardening (same day):** P0 fail-open paths (`scope is None → allow`) in browser_probe, threat_intel, vuln_match, dnsx output, and runner alive rebuild were inverted to DENY. `Hypothesis` and `CollectionAttempt` are persisted. CI `black --check` is clean. See `docs/ARCHITECTURE.md`.

---

## 1. Architecture before

Forensic baseline: `docs/ARCHITECTURE_AUDIT.md`.

```
python app.py run -d <target>
    → PipelineRunner.run
    → plugins write canonical artifacts (dnsx overwrites resolved.txt, httpx overwrites alive.txt)
    → _maybe_collect_followups (fresh IntelEngine)
    → follow-up could clobber seed alive.txt / resolved.txt
    → _finalize_to_store: HostRegistry + IntelligenceEngine clusters + IntelEngine snapshot
    → SQLite + reports
```

Intelligence ran after reconnaissance. Presence of a `CollectionScope` object was treated as a gate. `COLLECTED` could be assigned when an indicator was merely claimed. Seed dnsx resolved the CT-merged `subdomains.txt`, so in-scope CT SANs never became follow-up work. Host graph assigned independent HIGH CDN/ASN confidence. Plugin reason strings such as `CERTIFICATE_SAN` could be trusted without evidence rows.

## 2. Architecture after

```
seed / indicator
    ↓
authorize_active_indicator (ALLOW | DENY | UNKNOWN; UNKNOWN fail-closed)
    ↓
bounded collection (seed DNS from enum+seeds, not the full CT merge)
    ↓
normalized entity + observation + provenance
    ↓
evidence → relationship (intel graph is correlation truth)
    ↓
hypothesis / indicator (DISCOVERED → ELIGIBLE → IN_FLIGHT → COLLECTED|FAILED)
    ↓
authorize again
    ↓
follow-up collection into sidecars
    ↓
authorized deterministic union → canonical artifacts
    ↓
intelligence ingest → SQLite (including indicator lifecycle)
    ↓
CLI / HTML / Markdown / JSON via serialize_relationship()
```

`Host` remains the attack-surface projection. Intel entities, observations, evidence, and relationships are the intelligence source of truth. Host graph CDN/ASN edges are `LOW`. Pairwise SHARES_IP / SHARES_ASN / SHARES_FAVICON / SHARES_BODY_HASH are not `HIGH` without independent corroboration.

## 3. Files changed

New:

- `core/intel/authorize.py` — central authorization primitive
- `core/intel/artifacts.py` — seed snapshots, pass-numbered sidecars, authorized union, `authorized_alive.txt`
- `core/intel/serialize.py` — canonical relationship objects
- `docs/ARCHITECTURE_AUDIT.md`
- `tests/test_asi_loop_e2e.py`
- `tests/test_adversarial_matrix.py`
- `tests/test_cli_acceptance.py`

Modified (principal):

- `core/runner.py` — seed DNS split, follow-up sidecars, union, indicator persist, `COLLECTED` only on artifact success
- `core/intel/followup.py` — evidence-backed reasons, wildcard policy, central authorize
- `core/intel/queue.py` — DISCOVERED / ELIGIBLE / IN_FLIGHT / COLLECTED / FAILED / NOT_ALLOWED / REJECTED
- `core/intel/engine.py`, `scope.py`, `bounds.py`, `model.py`, `cli.py`, `correlate.py`
- `core/store.py`, `core/diff.py`, `core/reporter.py`, `core/intelligence/graph.py`
- `config/settings.py`
- Plugins: `_base.py`, `whois.py`, `gau.py`, `waybackurls.py`, `katana.py`, `nuclei.py`, `port_verify.py`
- `README.md`

Preserved: structured argv subprocess (no `shell=True`), path confinement, output caps, SQLite+WAL+FK, `STRICT_OPSEC`, fingerprint-first certificates, OOS observation, no Neo4j, no actor/owner entities.

## 4. Database / schema changes

SQLite remains `output/recon.db`. Foreign keys stay enabled.

`intel_indicators` gained durable lifecycle columns (migrated if missing):

- `authorization_status`
- `created_at`, `claimed_at`, `completed_at`
- `failure_reason`
- `collector`

New tables (`CREATE TABLE IF NOT EXISTS` on connect; existing DBs migrate safely):

- `intel_hypotheses` — relationship-derived collection hypotheses (not authorization)
- `intel_collection_attempts` — per-capability SUCCESS/FAILED (DNS vs HTTP)

`persist_registry` reads prior indicator rows **before** `clear_run_data`. Leftover `IN_FLIGHT` becomes `FAILED` (`interrupted_in_flight`). Finalize never invents `COLLECTED`. Mid-run `upsert_intel_indicators` / `upsert_intel_attempts` record queue and attempt state. A later follow-up pass **merges** attempts; it does not wipe the first pass.

## 5. New invariants

| ID | Rule | Enforcement |
|---|---|---|
| I1 | No active collection without a concrete authorized indicator | `authorize_active_indicator`; plugins re-gate inputs; missing scope fails closed |
| I2 | Observation ≠ collection | OOS names persist as entities/observations with `NOT_ALLOWED`; not written to canonical alive/resolved |
| I3 | `COLLECTED` only after success | Queue transitions; follow-up success = hostname present in sidecar artifacts |
| I4 | No relationship without evidence | `_relate` requires evidence; serializer includes `evidence_id` |
| I5 | Confidence belongs to the relationship | Shared IP/ASN/CDN/favicon/body-hash alone are not HIGH |
| I6 | Host is a projection | Intel relationships are authoritative; Host CDN/ASN graph edges are LOW |
| I7 | Follow-up must not clobber seed artifacts | Seed snapshots + sidecars + atomic union |
| I8 | Reasons are not evidence | Planner verifies certificate entity + SAN observation + `SAN_CONTAINS` |
| I9 | Cloud endpoints need explicit policy | Generated `*.s3.amazonaws.com` / GCS / Azure / R2 denied unless cloud collection is enabled **and** still in scope |
| I10 | Certificate identity is fingerprint-first | Same SAN set + different SHA-256 → two certificates |

## 6. New tests

Proof tests (count):

- `tests/test_asi_loop_e2e.py` — `PipelineRunner.run()` seed → CT → seed DNS → seed HTTP → intel → authorized follow-up DNS/HTTP → union → SQLite → CLI/HTML/MD/JSON. Fails if follow-up is skipped. OOS `malicious-or-unrelated.example.net` is observed, never active-collected.
- `tests/test_cli_acceptance.py` — `app.main()` argv: `run --no-ui -d virusbarrier.xyz` then `investigate`, `relationships`, `evidence`, `diff`. Class-level collector stubs only. Asserts follow-up DNS/HTTP ran.
- `tests/test_adversarial_matrix.py` — authorization fail-closed, cloud policy, spoofed `CERTIFICATE_SAN` / `SHARED_CERTIFICATE`, 10k SAN truncation, cert fingerprints, poisoned alive/subdomains, missing scope, empty+crash follow-up preserves seed, dedicated shared IP not HIGH, interrupted `IN_FLIGHT` → `FAILED`.
- Updated `tests/test_followup_loop.py`, `tests/test_followup_artifacts.py`, `tests/test_intel_diff.py`.

Existing coverage still used: redirect OOS (`test_redirect_safety.py`), virusbarrier production path (`test_pipeline_runner_e2e.py`), correlation (`test_correlation_correctness.py`).

Adversarial matrix mapping (user 1–35): covered in this suite or by the named existing files. Weakest remaining cells: live httpx timeout at the binary (simulated as collector exception, because `_run_single_plugin` swallows raises), katana in-page crawl internals, browser subresource fetches.

## 7. Runtime E2E trace (what tests actually execute)

Stubbed at plugin `run()` / class methods. Not stubbed: `app.main` → `cmd_run` → `PipelineRunner.run` → scope → seed DNS input construction → intel ingest → planner → authorize → sidecar write → union → `AssetStore` → `cmd_investigate` / `cmd_relationships` / `cmd_evidence`.

Expected fixture behavior (ASI loop):

| Indicator | Observed | Authorized | Active-collected | Canonical artifacts |
|---|---|---|---|---|
| `seed.example.com` | yes | ALLOW | COLLECTED | `resolved.txt`, `alive.txt` |
| `www.seed.example.com` | yes (CT SAN) | ALLOW | COLLECTED via follow-up | union into canonical |
| `malicious-or-unrelated.example.net` | yes | DENY / NOT_ALLOWED | never | absent from resolved/alive; present in intel observations |

CLI acceptance uses `virusbarrier.xyz` + in-scope `www.virusbarrier.xyz` and OOS `virusinspector.top` with the same rules.

## 8. Scope enforcement matrix

| Collector | Input hostname source | Authorization | Output as future target |
|---|---|---|---|
| whois | target roots | `authorize_active_indicator` per root | nameservers observed, not auto-probed |
| subfinder/amass/assetfinder | operator seeds | seed is operator-supplied | names observed into `subdomains.txt` |
| ctlogs | seeds → crt.sh | passive | SANs observed; seed dnsx does **not** resolve the full merge |
| dnsx | `authorized_dns_targets.txt` then follow-up list | `authorize_plugin_input` + plugin re-check | resolved hosts re-filtered |
| httpx | authorized resolved | input gated; final URL classified | OOS landing **not** added to alive; still fetched once by httpx `-follow-redirects` |
| naabu | authorized resolved | `_authorized_input` | ports |
| port_verify | naabu list | `_authorized_input` (no longer trusts naabu blindly) | verified ports |
| katana / nuclei | prefer `authorized_alive.txt` | `_authorized_input` | tool-internal crawl remains a residual |
| hakrawler | `_alive_urls()` | require scope + filter | same |
| gau / waybackurls | seeds | per-seed `authorize_active_indicator` | archive URLs not used as crawler input by default |
| threat_intel | httpx hosts | skip unauthorized hosts | none |
| browser_probe | httpx URLs | start URL + document navigations gated | **subresources not gated** |
| cloud_bucket_enum | derived FQDNs | explicit cloud policy + still not silent in-scope | URLs |
| asn_lookup | IPs from authorized DNS | IP not a hostname; contacts Team Cymru | ASN entities |
| wildcard_check | roots | `allows_active_collection` on roots | diagnostic + collection policy |

Missing `CollectionScope` on an active plugin fails closed (`ConfigurationError`). A scope object with an OOS hostname returns `DENY`.

## 9. Follow-up lifecycle

```
DISCOVERED → ELIGIBLE → IN_FLIGHT → COLLECTED
                              ↘ FAILED
OUT_OF_SCOPE → NOT_ALLOWED
spoofed/invalid → REJECTED
```

Planner order: normalize → already-collected → **authorize** → evidence (for `CERTIFICATE_SAN` / `SHARED_CERTIFICATE`) → wildcard policy.

Sidecars: `resolved_followup_<pass>.txt`, `dnsx_records_followup_<pass>.jsonl`, `alive_followup_<pass>.txt`, `httpx_followup_<pass>.json`. Canonical files are an authorized union of seed + sidecars. Empty result, crash, or timeout-as-exception leaves seed snapshots intact. Duplicate claim returns nothing new (`eligible_followups`). Second pass uses a new suffix and still unions against seed.

`context.alive_urls` is not the union source of truth. The artifact store is.

## 10. Evidence model

Every intel relationship stores `evidence_id` with FK to `intel_evidence`. Evidence carries source artifact, collector, observation id, reason, metadata, `observed_at`.

Certificate follow-up is valid only when:

1. certificate entity exists (fingerprint identity)
2. SAN observation exists and references that certificate (`observed_as=certificate_san`)
3. `SAN_CONTAINS` relationship exists with an evidence id

A plugin cannot mint `CERTIFICATE_SAN` by writing a reason string. Emissions are forced to `CollectReason.PLUGIN`.

Truncation (`san_limit`, `relationship_limit`, `entity_limit`) sets `truncated=true` and records a reason. Seeds keep priority. No dummy FK rows.

## 11. Relationship model

Canonical object (`serialize_relationship()`):

`relationship_id`, `source_entity`, `target_entity`, `relationship_type`, `confidence_band`, `strength`, `evidence_id`, `evidence_type`, `certificate_fingerprint`, `certificate_serial`, `shared_ip`, `san_cardinality`, `source_artifact`, `source_plugin`, `run_id`, `explanation`

Stable IDs include enough identity that `domain A SHARES_CERTIFICATE fingerprint X` does not collide with fingerprint Y.

Pairwise SHARES_* cliques are hub-only above `max_relationships_per_signal` (capped via `bounded_pairs`). Prefer `CERTIFICATE --SAN_CONTAINS--> domain` over a 200-domain clique.

## 12. Historical diff behavior

`diff_runs` now reports:

- hosts / HTTP URLs / host field changes (IP, cert fingerprint, SANs, HTTP, tech, …)
- relationships appeared / disappeared / changed
- `CONFIDENCE_INCREASED` / `CONFIDENCE_DECREASED` / `EVIDENCE_CHANGED`
- entities, observations, evidence appeared / disappeared
- indicator discovered / collected / failed / status changed
- certificate appeared / disappeared (rotation)

## 13. Reporter consistency

CLI `relationships`, HTML, Markdown, and `assets.json` `intelligence.relationships` all call `serialize_relationship()`. The ASI loop test checks CLI ids against JSON and that HTML/Markdown mention the same relationship types.

Host graph remains a visualization. It must not independently assign HIGH shared CDN/ASN. Intel CLI is the story operators should trust.

## 14. Performance bounds

`DiscoveryBounds` / settings: `MAX_DISCOVERY_DEPTH`, `MAX_FOLLOWUP_INDICATORS`, `MAX_FOLLOWUP_PER_SOURCE` (`max_domains_per_source` / `max_followups_per_relationship`), `MAX_DNS_PROBES`, `MAX_HTTP_PROBES`, `MAX_ENTITIES`, `MAX_RELATIONSHIPS`, `MAX_RUNTIME`, `MAX_SANS_PER_CERTIFICATE` (`max_ct_names_per_certificate`), `MAX_CERTIFICATES`, `MAX_IP_ENTITIES`, `MAX_URL_ENTITIES`, `MAX_TECHNOLOGY_ENTITIES`, `MAX_RELATIONSHIPS_PER_SIGNAL`.

A 10,000-SAN certificate is truncated and cannot consume the whole entity budget. Tests cover this.

## 15. Security review (second pass)

Searched: `shell=True` (none; comment only), `subprocess` (structured argv in `utils/subprocess.py`), `os.system` (none), `urllib` (ctlogs, threat_intel, vuln_match, cloud/param/soft404), `socket` / `open_connection` (asn_lookup → whois.cymru.com), Playwright (browser_probe), redirects (httpx `-follow-redirects`), `alive.txt` / `resolved.txt` / follow-up, output paths (confined).

| Path | Hostname contacted | Obtained from | Authorized? | Attacker influence | Bypass? |
|---|---|---|---|---|---|
| dnsx/httpx/naabu | input list | artifacts | yes, re-gated | poisoned files dropped | no, if scope attached |
| httpx redirect | **final Location, once** | HTTP response | classified after fetch | target can redirect OOS | **residual fetch**; not added to alive |
| katana/nuclei | authorized_alive | Hydra view | input yes | in-page links inside tool | **residual internal crawl** |
| browser_probe | start URL + documents | httpx | document yes | page loads CDN | **subresources residual** |
| ctlogs | crt.sh | seed | passive | none beyond seed | observe-only |
| threat_intel | urlhaus | authorized hosts | skip OOS | none | fail closed on host |
| gau/waybackurls | archive APIs | seeds | per-seed | none | seeds only |
| whois | whois servers | target roots | per-root authorize | none | OOS roots skipped |
| asn_lookup | whois.cymru.com / DNS | resolved IPs | IPs from authorized DNS | none | Team Cymru always contacted for those IPs |
| cloud_bucket_enum | derived cloud FQDNs | brand permute | policy required | plugin output | denied without policy |

Plugin provenance cannot forge `CERTIFICATE_SAN`. Scope cannot be bypassed by “I have a CollectionScope instance.” `STRICT_OPSEC` still blocks unverified tools.

## 16. Remaining known limitations

1. httpx still **follows** out-of-scope redirects at the binary. Hydra withholds the landing from the active alive set and records an observation. Eliminating the fetch would require stopping at the first hop or a Hydra-owned HTTP client.
2. Playwright subresources (CDN, JS, fonts) are not hostname-authorized.
3. katana/nuclei may request URLs they discover internally before Hydra sees them. Inputs are authorized; outputs that become later targets must be re-authorized, but the tool’s own crawl is not a Hydra loop.
4. Without `SCOPE_FILE`, names under a seed’s registrable domain are `IN_SCOPE`. Operators who need a tight program scope must set `SCOPE_FILE`.
5. If subfinder/amass/assetfinder artifacts are missing, seed DNS falls back to `subdomains.txt` (which may include CT names). The ASI loop depends on `subfinder.txt` existing so follow-up remains a real second collect.
6. `_run_single_plugin` swallows collector exceptions; follow-up crash handling keys off missing/empty sidecars.
7. Host risk scoring remains a separate numeric system from relationship confidence bands.
8. No live internet run against production `virusbarrier.xyz` is claimed as proof. Proof is the stubbed production CLI/runner path.
9. `datetime.utcnow()` deprecation warnings remain; behavior is unchanged.
10. Pairwise SHARES_CERTIFICATE still exists for small SAN sets; large sets stay hub-only.

---

## Scores

| Axis | Score | Why not 10 |
|---|---|---|
| Collection | 8/10 | Seed/follow-up split and union work; httpx still fetches OOS redirects once |
| Authorization | 8/10 | Central primitive, fail-closed; tool-internal and subresource I/O remain |
| Intelligence | 8/10 | Control loop is in `PipelineRunner`; not a post-hoc sidecar |
| Evidence | 8/10 | Relationships require evidence; planner verifies cert SANs |
| Correlation | 8/10 | One intel truth; Host graph is a lowered projection, not deleted |
| Follow-up | 8/10 | Sidecars + union + bounds; not an unrestricted crawler |
| Persistence | 8/10 | SQLite + FK + durable indicator lifecycle + interrupted IN_FLIGHT |
| History | 8/10 | Entities/observations/evidence/relationships/indicators/cert rotation |
| Reporting | 8/10 | Shared serializer; Host HTML still also shows risk/clusters |
| OPSEC | 9/10 | STRICT_OPSEC, no shell=True, path confinement preserved |

## Verdict

**READY FOR CONTROLLED BETA**

Use on authorized targets with `SCOPE_FILE` set, follow-up enabled, and optional crawlers/browser probe treated as higher-risk heads. Do not treat a green pytest run that bypasses `PipelineRunner` as production proof. The proof that matters is the runtime path above.
