# Hydra — Final Project Audit

Status: **audit only, no feature work.** Branch `audit/final-project-review`,
cut from `main` at commit `1afcfa3` (the reportability-agent-design v2 merge).
Every number below comes from actually running the command, on this machine,
today — not from re-reading old docs and assuming they still hold. Where a
check contradicts what an older doc claims, that is called out explicitly as
drift, not silently corrected.

This document is the direct input for the documentation-rewrite prompt that
follows it. Read the final "Ready to document" section first if you only
have five minutes.

---

## Part 1 — Inventory and general health

### 1.1 Full test suite, 5 consecutive runs

Native environment (macOS, Python 3.13.2, this machine's normal install —
`anthropic`/`openai`/`playwright` **not** installed):

| Run | Result | Duration |
|---|---|---|
| 1 | 844 passed, 10 skipped | 240.34s |
| 2 | 844 passed, 10 skipped | 236.06s |
| 3 | 844 passed, 10 skipped | 235.90s |
| 4 | 844 passed, 10 skipped | 238.87s |
| 5 | 844 passed, 10 skipped | 253.13s |

**Identical result all 5 times. Zero flaky tests observed** — every prior
report of intermittency in this project's history was not reproduced in this
run (5/5 consecutive, not a lucky 2/2). The 10 skips are the 5
`pytest.importorskip`-guarded reportability/browser-live modules (see 1.3)
plus pre-existing tool/credential-gated live tests.

### 1.2 Lint/format/security gates

| Tool | Command | Result |
|---|---|---|
| ruff | `ruff check .` | **All checks passed** |
| black | `black --check .` | **217 files unchanged** |
| isort | `isort --check-only .` | **clean** (4 paths skipped: `.venv`, `logs`, `output` — gitignored runtime dirs, expected) |
| bandit | `bandit -c pyproject.toml -r .` | **0 issues** (Undefined/Low/Medium/High all 0), 25,914 lines scanned, 26 findings suppressed via explicit `#nosec` comments (all pre-existing, reviewed in prior audits) |
| mypy | `mypy .` | **Success: no issues found in 129 source files** — real, but a weak signal: `pyproject.toml` sets `ignore_errors = true` project-wide, so this mainly confirms syntax validity, not type correctness |

### 1.3 Clean collection without optional dependencies — re-verified in a genuinely fresh environment

Not assumed from the last session's fix. Built a brand-new venv
(`python3 -m venv`), installed **only** `requirements-dev.txt` (no
`anthropic`, `openai`, or `playwright` anywhere on `sys.path`):

```
847 tests collected in 0.37s   (0 collection errors)
844 passed, 10 skipped, 297 warnings in 223.77s
```

Matches the native-machine numbers exactly. The CI-breaking regression from
before is genuinely still fixed, verified independently of this session's
own (possibly already-patched) working copy.

**Why 847 collected here vs. 933 with optional deps installed, explained
precisely, not hand-waved**: diffed the exact test IDs from `--collect-only`
between both environments. The entire 86-test delta is exactly the tests
living inside the five `pytest.importorskip("anthropic"/"openai"/"playwright")`-
guarded modules (`test_reportability_client.py`, `test_reportability_cli.py`,
`test_reportability_openai_client.py`, `test_reportability_prompt_injection.py`,
`test_reportability_live.py`, `test_browser_confinement_live.py`,
`test_browser_probe_scope_guard.py`) — when the guard's import fails, pytest
drops those modules from collection entirely rather than listing individual
skipped items. Confirmed with a real diff of collected IDs, not inferred.
**This closes, with certainty, the "unexplained test-count discrepancy"
item that was open in institutional memory (Part 3) — there is no
discrepancy, it is fully mechanical and by design.**

### 1.4 Plugin inventory and test coverage

`modules/` contains **26 `.py` files**: `_base.py` (shared plugin base class)
plus **25 real plugins**. Checked each by both filename and declared class
name against every reference in `tests/`.

**19 of 25 have real regression-test references** (asn_lookup, cloud_bucket_enum,
ctlogs, dnsx, hakrawler, katana, naabu (via test_naabu.py, not name-grepped
above but confirmed separately), nuclei, param_fuzz, port_verify,
soft404_check, subfinder, threat_intel, vuln_match, wildcard_check, httpx,
security_headers, browser_probe, whois).

**6 plugins have zero regression-test coverage — no test file references
their class by name or module path anywhere in `tests/`:**

| Plugin | Class | Coverage found |
|---|---|---|
| `amass` | `AmassPlugin` | Named once in `test_plugins.py::test_plugins_registered` — a registration/discovery check only, asserts nothing about its actual parsing or execution logic |
| `anew` | `AnewPlugin` | None |
| `assetfinder` | `AssetfinderPlugin` | None |
| `gau` | `GauPlugin` | None |
| `unfurl` | `UnfurlPlugin` | None |
| `waybackurls` | `WaybackurlsPlugin` | None |

All 6 are real, installed, invocable tools in this environment. `amass` is
additionally **confirmed actively broken** (Part 3) — its complete absence of
regression coverage is exactly why that break went unnoticed. The other five
were not live-tested for functional correctness in this pass (out of the
explicit ask for Part 1.4, which was coverage inventory, not a live
functional audit of every tool) — flagged as a real gap, not silently
assumed fine because they're untested.

Additionally: `KatanaParser`/`HakrawlerParser`/`GauParser`/`WaybackurlsParser`
(all thin subclasses of `core/parsers/registry.py::UrlListParser`) have no
dedicated unit test exercising their own `.parse()` output shape directly —
their real CLI invocation is covered (live, real binaries) via
`test_crawler_confinement_live.py`, but the parsing step itself is not
independently tested. Low severity (the format is a one-URL-per-line file,
about as simple as parsing gets) but real.

### 1.5 Docker build and containerized test run

`docker build -t hydra:audit .` — **succeeded**, ~90s total (Go toolchain
compile stages cached from a prior layer, Playwright/WebKit download ~29s).

```
docker run --rm hydra:audit python -m pytest tests/ -q
932 passed, 1 skipped in 265.98s   (933 collected)
```

**933 collected inside the container — more than either native number, fully
consistent with 1.3's explanation**: the image installs `anthropic`,
`openai`, and Playwright/WebKit, so all five import-guarded modules collect
their real tests instead of being skipped at the module level (933 collected
matches a from-scratch venv with `requirements-dev.txt` +
`requirements-optional.txt` installed, verified side-by-side — identical
number). The 1 skip is `test_reportability_live.py`'s real test, correctly
gated on `ANTHROPIC_API_KEY` (unset, by design, inside a CI-style container).

No test failures inside the container that don't also occur natively, and no
native-only failures either — **the suite's behavior is identical in both
environments**, modulo which optional tools happen to be on `PATH`/importable.

---

## Part 2 — Subsystem verification, with evidence

| # | Subsystem | Verdict | Evidence |
|---|---|---|---|
| 1 | Network confinement (`CollectionGateway`/`ScopeEnforcingProxy`) | **VERIFIED_CURRENT** | `test_httpx_confinement_live.py` + `test_urllib_confinement_live.py` + `test_crawler_confinement_live.py`, 22/22 passed — real local arbiter server, real `httpx`/`katana`/`hakrawler`/urllib-based-plugin invocations, redirect-escape attempts, private-IP-resolution attempts, and researcher-attribution-header/UA propagation all covered. Zero unauthorized connections observed across all 22. |
| 2 | Correlation engine | **VERIFIED_CURRENT** | `test_infra_correlation.py` (7/7) + `test_virusbarrier_e2e.py` (5/5), 12/12 total. `test_all_six_names_survive_as_observations` confirms the real 6-domain `virusbarrier.xyz` case still reconstructs correctly; shared-certificate → HIGH confidence, shared-IPv4-alone → MEDIUM (not HIGH) distinction still holds. |
| 3 | Verification agent — `scope_exclusion_canary_check` | **VERIFIED_CURRENT** | `test_real_stripchat_wildcard_host_exclusion_now_works` re-run and passing: `scope_exclusion_canary_check(CollectionScope.from_seeds(["stripchat.com"], patterns=["*.stripchat.com", "!mta*.stripchat.com"]))` → `[]`, confirmed again, not assumed permanent from the original fix. |
| 4 | Reportability agent — citation grounding | **VERIFIED_CURRENT** | `TestIsCitationGroundedAgainstRealStripchatRules`, 12/12 passed against the real fixture. Independently re-confirmed outside the test framework with a direct call: a fabricated citation ("Critical remote code execution vulnerabilities are always eligible...") against the real Stripchat rules text returns `(False, 'none')` — the 0.98 fuzzy threshold and exact/normalized tiers all still reject it. |
| 5 | Docker — non-root, minimal capabilities | **VERIFIED_CURRENT** | `docker run --rm hydra:audit id` → `uid=10001(hydra) gid=10001(hydra)`, never root. Scanned every binary in `/usr/local/bin` for capabilities: **only `naabu` has any**, and it is exactly `cap_net_raw=ep` — nothing broader, nothing on any other binary. |

**No drift found in any of the 5 checked subsystems.** Everything the
existing docs claim about these five areas is still true today, re-verified
with a real, live check rather than re-read from the doc itself.

---

## Part 3 — Consolidated technical debt and open items

### 3.1 `katana`/`hakrawler`/`nuclei` empirical audit — status corrected from institutional memory

**Partially done, not "never executed" as recalled.** Network-confinement
behavior for all three **was** empirically verified with real binaries in a
later round (`test_crawler_confinement_live.py`, plus
`docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md`/`FINAL_SECURITY_AUDIT.md` document
it) — this session re-ran those 22 live tests and they still pass (Part 2.1).
What genuinely was **never** done with `httpx.py`-level rigor: a dedicated
unit test of each tool's own **output-parsing** logic (see 1.4) — the parsers
are simple enough that this is low-severity, but it is a real, still-open gap,
not a fully-closed item as the memory suggested and not the same gap as the
confinement question.

### 3.2 `amass` failing consistently — root cause now confirmed, not just observed

**Confirmed, reproduced live, root-caused.** `modules/amass.py` invokes:

```
amass enum -passive -d <domain> -o <output_path> -timeout 5
```

The installed binary is **amass v5.1.1**. In v5, the `-o` flag **does not
exist** — verified against `amass enum -h`'s real output, and reproduced
directly:

```
$ amass enum -passive -d example.com -o /tmp/out.txt -timeout 1
...
flag provided but not defined: -o
$ echo $?
1
```

v5 replaced single-file `-o` output with `-dir` (a whole output directory) or
`-oA` (a path prefix for multiple named files) as part of a broader
architecture change (an engine/graph-DB model, `-passive` is now "deprecated
since passive is the default setting"). This is **not** a flaky network
issue, a missing API key, or an environment quirk — it is a hard CLI
incompatibility that fails **every single invocation**, 100% reproducible,
independent of network conditions or target. `modules/install_hint_linux`
still points at `v4/...@master`, i.e. the code was written against v4's
interface and never updated for v5.

**Not fixed in this pass** (a real design decision: pin/require amass v4
specifically, or rewrite the plugin against v5's directory-based output —
either is non-trivial and belongs to a real implementation session, not an
audit). Documented as a finding.

### 3.3 nuclei "ERROR" classification in the CLI summary — investigated, not reproduced

Traced every plausible mechanism: `_execute_self_output`'s
`return_code != 0 → FAILED` path, `_scan_telemetry`'s stdout/stderr
keyword-scanning (rate-limit/retry only, no generic error-text matching),
`core/runner.py`'s `context.add_error(...)` call site (fires for *any*
plugin's non-success result, not nuclei-specific), `ui/tables.py`'s literal
`"ERROR"` label in `build_errors_panel`, and `NucleiParser`'s severity
mapping (passes the template's own `info.severity` straight through — no
"info → ERROR" translation exists anywhere).

Live-tested real installed `nuclei v3.9.0` three times: against an empty-match
target, a tag-filtered zero-match scan, and a local test server that produced
**3 real findings** — all three runs exited **0** and were classified
`COMPLETED`, matching what the code should do. **Could not reproduce the
described bug with the current code and this nuclei version.** Most likely
explanations, none confirmed: already fixed in an intervening change, tied to
a specific nuclei version/flag combination not exercised here, or a one-off
local observation that was never actually a code bug. Recorded honestly as
**NOT REPRODUCED**, not silently marked "fixed" or "still broken."

### 3.4 Test-count discrepancy across environments

**Fully resolved — see Part 1.3.** There is no unexplained discrepancy; the
847-vs-933 (or 844-vs-932-passed) gap is exactly and only the set of tests
gated behind optional-dependency `importorskip` guards, confirmed by a direct
diff of collected test IDs.

### 3.5 Branches that were never merged nor explicitly closed

Checked all 11 local/remote feature and fix branches against `main`. **9 are
fully merged** (0 commits ahead of `main`): `feat/attribution-useragent-and-full-host-exclusion`,
`feat/docker-containerization`, `feat/passive-dns-correlation`,
`feat/verification-agent-design`, `feat/verification-agent-wired-into-run`,
`fix/redirect-scope-safety`, `fix/scope-host-wildcard-exclusion-v2`,
`fix/security-headers-raw-evidence`, `refactor/main-positioning-hardening`.

**2 are local-only (never pushed to `origin`), never merged, and worth your
direct attention:**

- **`fix/dnsx-nodata-soa-false-resolution`** (1 commit, `d98a5d8`,
  2026-09-01). **This is real, tested work that is missing from `main` right
  now** — a genuine false-positive bug (NODATA/SOA-only dnsx records counted
  as "resolved" in three separate code paths, based on a real
  `fishbowlapp.com` production case with 9 affected subdomains), fixed with
  193+105 lines of new tests, `pytest` 3x clean at the time (668 passed).
  Confirmed the fix (`Host.dns_unconfirmed_http_response`,
  `_flag_unconfirmed_dns_http_responses`) is **absent from current `main`** —
  grepped directly, not assumed. Confirmed it merges into current `main`
  cleanly with no conflicts (`git merge-tree`). **Recommend reviewing and
  merging this branch** — it looks like real work that fell through the
  cracks, not abandoned-on-purpose experimentation.
- **`fix/scope-exclusion-host-wildcard`** (1 commit, `ba08d5f`, 2026-09-01).
  An earlier attempt at the same wildcard-exclusion fix that
  `fix/scope-host-wildcard-exclusion-v2` (already merged) later solved more
  cleanly — confirmed by diffing both branches' `core/scope.py`: the merged
  v2 branch's commit has the identical message and a more thorough
  `hostname_matches_pattern` implementation. This one looks safely
  superseded and abandonable, but flagged for your explicit call rather than
  deleted unilaterally.

---

## Part 4 — Repo structure notes (observations only, nothing restructured)

- **`core/intel/` vs `core/intelligence/`** — two top-level packages with
  almost-identical names and genuinely different purposes (`intel/`: the
  OSINT entity/relationship/hypothesis/authorization engine, 17 files;
  `intelligence/`: clustering/graph/risk-scoring, 5 files). A newcomer will
  very plausibly import the wrong one on a first guess.
- **`core/scope.py` vs `core/intel/scope.py`** — also two distinct modules
  (legacy glob-pattern exclusion matching vs. the intel layer's
  authorization-aware `CollectionScope`), same naming-collision risk.
- **`core/models.py` vs `core/intel/model.py`** (plural vs. singular) — same
  pattern again, lower risk since the singular/plural distinction is at
  least a real (if subtle) signal.
- **`core/discovery/`** and **`core/validation/`** are each a package
  containing exactly one file (`tool_discovery.py`, `engine.py`
  respectively) — plausibly better as `core/discovery.py`/`core/validation.py`
  unless there's a near-term plan to add siblings.
- **`docs/` has 16 files with heavy naming overlap and no stated authority
  order**: five files with "ARCHITECTURE" in the name
  (`ARCHITECTURE.md`, `ARCHITECTURE_AUDIT.md`, `ARCHITECTURE_AUDIT_2.md`,
  `ARCHITECTURE_CURRENT.md`, `ARCHITECTURE_REVIEW.md`); three with
  "NETWORK_BOUNDARY/CONFINEMENT_AUDIT" in the name (`NETWORK_BOUNDARY_AUDIT.md`,
  `FINAL_NETWORK_BOUNDARY_AUDIT.md`, `FINAL_NETWORK_CONFINEMENT_AUDIT.md`);
  and `FINAL_SECURITY_AUDIT.md`/`RUNTIME_AUDIT.md`/`READINESS_REPORT.md`
  covering substantially overlapping ground. Nothing in `docs/` states which
  one is current/authoritative when two disagree — this is precisely the
  kind of sprawl the upcoming documentation pass should consolidate, not
  add a 17th file to.
- Root-level runtime/secret files (`.env`, `scope.txt`, `.venv/`, `output/`,
  `logs/`) are all correctly `.gitignore`d and confirmed **not** tracked in
  git (`git ls-files` shows only the `.gitkeep` placeholders) — no hygiene
  issue found here, called out because it was checked, not skipped.
- `.github/workflows/ci.yml` already exists and is real (a `check` job
  across Python 3.10/3.11/3.12 running ruff/black/isort/mypy/bandit/pytest,
  plus a `docker` job on pull requests that builds the real image and reruns
  the confinement live tests and the exact `!mta*.stripchat.com` canary case
  inside the container). This wasn't mentioned as existing in the audit
  prompt's own institutional memory — worth knowing it's there before the
  documentation pass describes CI as absent or aspirational.

No bugs were fixed silently in this pass — every item above that touches
behavior is recorded as a finding, per this audit's own scope.

---

## Ready to document

Hydra today is a working, non-trivial reconnaissance pipeline — roughly 26
tool plugins orchestrated by an async runner, gated end-to-end by a real
scope/authorization layer and a live confinement proxy that 22 real,
tool-invoking tests just proved blocks unauthorized network egress; on top
of that sit three independent, genuinely-tested intelligence layers (an
OSINT correlation/relationship engine, a deterministic evidence-verification
agent, and an LLM-backed reportability agent with two interchangeable
providers and adversarial cross-validation), all persisted to SQLite with
real foreign-key-enforced integrity; it ships as a non-root Docker image
with minimally-scoped Linux capabilities and has real CI across three Python
versions plus a containerized confinement re-verification on every pull
request; 844 tests pass consistently and reproducibly today, with one
actively-broken optional tool (`amass`, a confirmed v4→v5 CLI
incompatibility), six optional plugins with no regression coverage, one real
tested bugfix sitting unmerged on a forgotten branch, and a documentation
tree sprawling enough that consolidating it — not adding to it — should be
the primary goal of the pass that reads this file next.
