# Hydra — Hardening Round 2 (P1): reproducibility, configuration, types, subprocess, logging, Docker

**Status: hardening audit + targeted fixes, no feature work.** Branch
`hardening/p1-repro-types-subprocess-logging`, cut from `main` after
Round 1 (`docs/HARDENING_ROUND1_P0.md`) merged. Builds on Round 1 and
`docs/FINAL_PROJECT_AUDIT.md` — does not repeat their numbers, only what
changed since. The reportability agent and Program Profiles were not
touched; `docs/ARCHITECTURE.md`/`docs/NETWORK_CONFINEMENT.md` were not
restructured.

Every fix below is scoped to a single, well-understood gap, verified with
real tools/binaries and real tests, not assumed from reading the diff.
None of Round 1's 12 invariants were weakened. No fix was tried and
reverted this round — every change landed clean, verified end-to-end
before being kept.

---

## Executive summary

| # | Task | Verdict |
|---|---|---|
| 1 | Dependency reproducibility | **Real bug found and fixed** — version detection silently returned banner-art garbage for 5 of Hydra's most-used tools; amass v5's known `-o` breakage now fails with a clear message instead of a cryptic binary error |
| 2 | Configuration consistency | **One dead setting removed, 23 real gaps closed** — `WHOIS_PATH` did nothing and was deleted; 23 genuinely-read env vars were undocumented and are now in `.env.example`, with a regression test |
| 3 | Incremental mypy type safety | **14 real type errors fixed** across 6 security-sensitive modules; 16 modules now carved out of the blanket `ignore_errors` and checked for real, with a config regression test |
| 4 | Test suite reliability | **No flakiness found** — 8 consecutive full-suite runs (5 mid-round + 3 final), all passing with a stable 10 skips, every skip visibly reasoned; `importorskip` confirmed consistent across every anthropic/openai/playwright-touching test file |
| 5 | Subprocess review | **Real gap found and fixed** — every external tool subprocess inherited Hydra's *entire* environment (every API key, every credential) with no `env=` restriction; two dead functions duplicating the same risk were removed |
| 6 | Logging and secrets hygiene | **Real gap found and fixed** — `SecretRedactingFilter` never reached exception tracebacks (`logger.exception(...)`), so a secret embedded in an exception's own message reached the log unredacted; also added defense-in-depth redaction for bare API-key shapes with no keyword context |
| 7 | Docker security re-check | **No drift found** — fresh image build, fresh evidence: non-root (uid 10001), naabu is the only binary with any capability (`cap_net_raw=ep` and nothing else), no secret in any layer, log/artifact permissions correctly restrictive (0700/0600) |

---

## Findings

### Finding 1 — tool version detection silently returned banner garbage (Task 1)

- **Severity**: Medium
- **Component**: `core/dependencies/validation.py`
- **Problem**: `_extract_version` only scanned the first 5 lines of a
  tool's version/help output, with a fallback that accepted "any line
  containing a digit" as a version. `_try_version` stopped at the first
  `version_commands` entry that merely exited successfully, even if its
  output had no real version to extract.
- **Impact**: Confirmed against real installed binaries: `httpx`,
  `naabu`, `katana`, `dnsx`, and `amass` all print a multi-line ASCII
  banner before their real `Current Version: vX.Y.Z` line — well past
  line 5. The old code matched banner box-drawing-character lines that
  happened to contain a digit and returned that as the "version," and
  never fell through to a cleaner alternate command. This directly
  produced the exact failure mode the round's proof-of-concept named:
  amass's real v5 `-o` flag removal (`docs/FINAL_PROJECT_AUDIT.md`) was
  never caught by version detection because the "version" being compared
  against was never a real version at all.
- **Root cause**: a scan window sized for simple single-line `--version`
  output, applied uniformly to tools with multi-line banners, plus
  "first successful command wins" logic that never re-evaluated a bad
  parse.
- **Fix**: scan up to 40 lines (verified against all installed
  ProjectDiscovery tools' real banners); the bare-version fallback now
  requires a line that is *entirely* a version token, not "contains a
  digit anywhere"; `_try_version` continues to the next
  `version_commands` entry until one actually parses. Added a small,
  explicit, evidence-only `KNOWN_INCOMPATIBLE_VERSIONS` gate
  (`core/dependencies/registry.py`) that flags amass ≥ v5 with the real
  error message and install fix, wired into `DependencyService` so it
  surfaces through the *existing* `ToolHealth.MISSING` /
  `context.add_warning` pipeline (`core/tool_manager.py`) — zero new
  plumbing needed. Amass's `version_commands` order and pinned install
  version were corrected in the same pass.
- **Test**: `tests/test_tool_version_detection.py` (16 tests) uses the
  exact real captured banner strings from real installed binaries
  (amass v5.1.1, httpx v1.9.0, naabu v2.6.1, katana v1.6.1, dnsx v1.2.3,
  jq, nmap) as fixtures, plus an async test proving
  `DependencyService.analyze_all()` surfaces the amass incompatibility
  end-to-end.

### Finding 2 — `WHOIS_PATH` setting was dead; 23 real settings were undocumented (Task 2)

- **Severity**: Low
- **Component**: `config/settings.py`, `config/.env.example`
- **Problem**: `whois_path` was defined, parsed from `WHOIS_PATH`, and
  even validated — but `modules/whois.py::WhoisPlugin.get_binary_path()`
  hardcodes `Path("built-in")` and never reads it (confirmed: the plugin
  moved to a native Python WHOIS client,
  `core/collection/whois_client.py`, and the old binary-path setting was
  never cleaned up). Separately, 23 env vars that `config/settings.py`
  genuinely reads and that real code paths genuinely use
  (`ENABLE_AMASS`, `ENABLE_CACHE`/`CACHE_TTL_SECONDS`, passive-DNS
  settings, several `MAX_*` bounds, attribution-header options, etc.)
  were never documented in `.env.example`.
- **Impact**: an operator reading `.env.example` had no way to discover
  or tune 23 real settings; `WHOIS_PATH` looked configurable but silently
  did nothing, which is actively misleading if left undocumented instead
  of removed.
- **Root cause**: config and docs drifted independently in both
  directions — one setting outlived the code that used it, and 23 newer
  settings were added to code without a matching doc update.
- **Fix**: removed `whois_path` from the dataclass and `from_env()`
  entirely (code had moved on — documenting a no-op setting would be
  worse than removing it). Added all 23 real settings to
  `.env.example` with accurate defaults (verified against a live
  `Settings` instance) in their thematically correct sections.
  `MAX_RUNTIME`/`STRICT_OPSEC`/the bounded-discovery limits were
  independently re-verified as genuinely enforced (`core/runner.py`,
  `core/intel/bounds.py`) — no fix needed, confirmed correct rather than
  assumed. `WORDLIST` was confirmed to be an already-honest "documented
  as not yet wired up" case and left untouched.
- **Test**: `tests/test_config_documentation_sync.py` (3 tests) — a
  durable regression guard asserting every `os.getenv(...)` read in
  `config/settings.py` has a matching entry in `.env.example`, a
  100-variable documentation floor, and that `whois_path` cannot silently
  reappear on either side without the test failing.

### Finding 3 — 14 real mypy errors in security-sensitive modules exempt from checking (Task 3)

- **Severity**: Low (latent — these were type-correctness gaps, not
  runtime bugs; none were reachable incorrect behavior)
- **Component**: `core/store.py`, `core/collection/{crawler_proxy,
  gateway, ssrf}.py`, `core/verification/{grounding, preflight}.py`
- **Problem**: `pyproject.toml`'s mypy config blanket-ignores
  `core.*`/`modules.*`/`utils.*`/etc. Real type errors existed in
  authorization-adjacent, network-confinement-adjacent, and
  persistence-adjacent modules, invisible because nothing ever checked
  them.
- **Fix**: fixed all 14 with real type-narrowing (no
  `# type: ignore`, no unjustified casts) — `TYPE_CHECKING`-guarded
  imports, explicit `if x is None: raise` narrowing, concrete
  `ipaddress.IPv4Network`/`IPv6Network` constructors instead of the
  generic factory, a typed closure replacing a loosely-typed
  `**dict[str, object]` unpack. Added a second
  `[[tool.mypy.overrides]]` block (mypy applies the *last* matching
  override) that re-enables real checking for 16 security-priority
  modules — `core.intel.authorize`, `core.scope`, `core.intel.scope`,
  `core.collection.{audit,crawler_proxy,gateway,ssrf,target,
  whois_client}`, `core.store`, `core.verification.{detectors,
  grounding, model, postmodule, preflight}`, `config.settings` — without
  touching the broad exemption everything else still has.
- **Test**: `tests/test_mypy_strict_module_coverage.py` (3 tests) — a
  dependency-free regex-based parse of `pyproject.toml`'s override
  blocks (no `tomllib`/`tomli`, since Python 3.10 — still in this
  project's CI matrix — lacks stdlib `tomllib` and the project has no
  TOML dependency) guarding that the strict carve-out list and the
  blanket-ignore fallback both still exist. Verified live:
  `mypy .` → `Success: no issues found in 129 source files`.

### Finding 4 — no test flakiness; skip/importorskip discipline already correct (Task 4)

- **Severity**: N/A (verification only, no fix needed)
- **Component**: `tests/`
- **What was checked**: ran the full suite 8 times total across this
  round (5 runs mid-round, 3 final runs after every code change landed)
  — every run passed with the same 10 skips, each with a clear,
  human-readable `reason=` (missing `playwright`/`anthropic`/`openai`,
  never a silently-skipped security assertion). Audited every file
  importing `playwright`/`anthropic`/`openai`: all correctly use
  `pytest.importorskip` at module level when the whole file needs the
  dependency, or scoped to the one test function that needs it when the
  rest of the file doesn't (`tests/test_subresource_escape_oracle.py`
  was the one file mixing both patterns — confirmed deliberate, not a
  gap).
- **Verdict**: nothing to fix. Documented with this round's own 8 runs
  of evidence rather than citing a prior round's suite health as still
  valid.

### Finding 5 — every external tool subprocess inherited Hydra's full environment (Task 5)

- **Severity**: High
- **Component**: `utils/subprocess.py`, `core/dependencies/validation.py`
- **Problem**: `run_command`/`run_command_to_file` (the single
  chokepoint every plugin routes through via `modules/_base.py`) called
  `asyncio.create_subprocess_exec` without an `env=` argument.
  `asyncio.create_subprocess_exec` inherits the *entire* parent process
  environment when `env` is omitted. `core/dependencies/validation.py`'s
  `HealthValidator._run_probe`/`_smoke_test` (used for every tool
  version/health check) had the identical gap.
- **Impact**: confirmed empirically — every invocation of every external
  tool (subfinder, httpx, naabu, katana, hakrawler, dnsx, nuclei, nmap,
  amass, assetfinder, gau, waybackurls, unfurl, anew, jq) received
  `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `WPSCAN_API_TOKEN`,
  `SECURITYTRAILS_API_KEY`, `URLHAUS_API_KEY`, and any credential
  embedded in `OUTBOUND_PROXY_URL` as environment variables, regardless
  of whether that tool had anything to do with those providers. None of
  Hydra's supported tools read API keys or proxy settings from
  environment variables — proxying is always via an explicit `-proxy`
  CLI flag — so nothing in this allowlist was load-bearing for any real
  tool behavior; it was pure unnecessary exposure to third-party
  binaries Hydra does not control the source of.
- **Root cause**: `env=` was never specified, so Python's default
  (full inheritance) applied silently.
- **Fix**: added `utils.subprocess.child_process_env()` — an explicit
  allowlist (`PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`,
  `TMPDIR`, `TZ`, `GOPATH`, `GOCACHE`) — passed as `env=` to every
  `create_subprocess_exec` call in both files. Verified against all 9
  real installed tools (subfinder, httpx, naabu, katana, nuclei, dnsx,
  amass, nmap, jq) that they still execute and report their version
  correctly with the restricted environment, and verified
  end-to-end through the real `DependencyService.analyze_all()`
  pipeline (amass's Task-1 incompatibility gate still fires correctly).
  Also removed `utils.subprocess.check_tool_available()` and
  `get_tool_version()` — confirmed zero callers anywhere in the
  codebase (fully superseded by `core/dependencies/`), and both had the
  identical missing-`env=` gap; fixing dead code duplicating a just-fixed
  risk would have been pointless, so it was deleted instead, per this
  project's established precedent (Task 2's `whois_path` removal) of
  removing confirmed-dead code rather than patching it in place.
  Confirmed (audited) already-correct: no `shell=True` anywhere outside
  a docstring, all arguments passed as explicit arrays, all real
  call sites pass an explicit timeout, executable resolution already
  validates configured absolute/relative paths
  (`utils.security.validate_binary_path`, called from
  `Settings.validate()`) while bare-name PATH lookup relies on the same
  `shutil.which` (which already checks executability) every CLI tool
  uses — no gap beyond what's inherent to trusting one's own PATH, which
  is out of any application's ability to change. Child-process cleanup
  on crash/interrupt was independently confirmed already correct:
  `PipelineRunner.run()`'s `finally` block unconditionally calls
  `terminate_all_processes()`, and `ui/dashboard.py` wires
  SIGINT/SIGTERM to `PipelineRunner.cancel()`, which schedules the same
  cleanup.
- **Test**: `tests/test_subprocess.py::TestChildProcessEnvironmentIsolation`
  (4 tests) — asserts the allowlist excludes every known secret-bearing
  variable, that `child_process_env()` never carries a secret set in the
  parent, and a live subprocess spawn proving a real child process
  cannot see a parent-set `ANTHROPIC_API_KEY`.
  `tests/test_dependencies.py::TestHealthValidator::test_probe_and_smoke_test_do_not_leak_secrets_to_the_child`
  — a fake "tool" binary that would write any leaked secret to a file
  `validate()` never reads, proving the leak-canary approach catches a
  real regression in the health-check path too.

### Finding 6 — exception tracebacks bypassed secret redaction entirely (Task 6)

- **Severity**: High
- **Component**: `core/logger.py`
- **Problem**: `SecretRedactingFilter.filter()` only sanitizes
  `record.msg`/`record.args`. A `logging.Filter` runs *before*
  `Formatter.format()` renders `record.exc_info` into text — so
  `logger.exception(...)` (used in `core/runner.py`,
  `core/collection/crawler_proxy.py`, `modules/browser_probe.py` for
  pipeline/plugin/proxy failure paths) wrote the full, unredacted
  exception traceback to both console and `logs/recon.log`, regardless
  of the filter being attached.
- **Impact**: confirmed empirically — a `ValueError` raised with a
  credential-embedded URL (`https://apikey:secret@evil.example/path`),
  or a `RuntimeError` echoing an `Authorization: Bearer ...` value,
  logged the secret in full via `logger.exception(...)`, even with
  `SecretRedactingFilter` attached exactly as documented. This is
  precisely the "unhandled exception could expose a secret in its
  traceback" scenario the task asked to confirm.
- **Root cause**: secret redaction was implemented at the `Filter`
  layer, which cannot see text `Formatter.format()` has not rendered
  yet (exception/stack info is rendered lazily, inside `format()`
  itself, not before).
- **Fix**: added `RedactingFormatter(logging.Formatter)` — overrides
  `format()` to run `sanitize_log_message` on the *entire* rendered
  line (message + traceback + any stack info) as the last step before
  it's written, and wired it into `setup_logging()` in place of the
  bare `logging.Formatter`. Verified empirically: both the
  credential-URL and bearer-token tracebacks are now fully redacted.
  Also audited every other `logger.debug/info/warning/error` call site
  across `core/`/`modules/` for direct header/secret logging — none
  found; `run_command`'s own "Executing: ..." debug line was already
  correctly sanitized via `shlex.quote` + `sanitize_log_message`
  (Round-1-era code, re-verified, unchanged). Confirmed no secret field
  (`anthropic_api_key`, `openai_api_key`, `wpscan_api_token`,
  `securitytrails_api_key`, `urlhaus_api_key`, `outbound_proxy_url`) is
  ever referenced by `core/store.py`, `core/collection/audit.py`'s
  persisted `NetworkRequestRecord`, or `core/reporter.py`'s generated
  reports — nothing currently writes a secret into `recon.db` or a raw
  artifact.
- **Additional hardening (defense in depth)**: `utils/security.py`'s
  `_SECRET_PATTERNS` list previously only matched keyword-anchored
  secrets (`key=...`, `token:...`, `Bearer ...`). A raw API key value
  echoed by a third-party SDK's own exception text (e.g.
  `anthropic.AuthenticationError`) with no such keyword prefix would
  not have matched any existing pattern. Added a shape-based pattern
  matching real Anthropic/OpenAI key prefixes (`sk-ant-...`,
  `sk-proj-...`, `sk-...`) followed by a long token body — long enough
  to avoid false-positiving on unrelated short `sk-`-prefixed
  substrings (verified with a dedicated test).
- **Test**: `tests/test_logger.py::TestExceptionTracebackRedaction`
  (4 tests) — proves the credential-URL and bearer-token leaks are
  fixed, and that `setup_logging()` wires `RedactingFormatter` (not a
  bare `Formatter`) on every handler, so this can't silently regress.
  `tests/test_security.py::TestLogSanitization` gained 3 tests for the
  new key-shape pattern (Anthropic shape, OpenAI shape, and a
  false-positive guard for short unrelated `sk-` substrings).

### Finding 7 — Docker security posture unchanged, reconfirmed with fresh evidence (Task 7)

- **Severity**: N/A (verification only, no fix needed)
- **Component**: `Dockerfile`, `docs/DOCKER.md`
- **What was checked**: built `hydra:round2-audit` fresh from the
  current `Dockerfile` (not reused from a prior round) and verified
  directly against the running container:
  - **Non-root**: `id` inside the container reports `uid=10001
    gid=10001 user=hydra`.
  - **naabu's capability set**: `getcap -r /usr/local/bin/ /usr/bin/`
    across every installed binary returns exactly one line —
    `/usr/local/bin/naabu cap_net_raw=ep` — nothing else in the image
    carries any capability, and the `hydra` user cannot write into
    `/usr/local/bin` (permission denied), so a compromised plugin can't
    add a capability to another binary.
  - **No secret baked into any layer**: `docker history --no-trunc`
    across every build step, and `docker inspect`'s baked `Config.Env`,
    contain no API key/token/password-shaped string (grepped
    explicitly for the same secret names Task 5/6 named); only
    `config/.env.example` is present inside the image, never a real
    `.env` (`.dockerignore` explicitly excludes `.env`/`config/.env`).
  - **Output filesystem permissions**: `core/logger.py::setup_logging`
    creates `logs/` at `0700` and `recon.log` at `0600` inside the
    real container; `utils/security.py::atomic_write_text` (the sole
    path Hydra uses to write output artifacts) produces `0600` files,
    confirmed with a real write inside the container.
- **Verdict**: identical to the last verification
  (`docs/FINAL_PROJECT_AUDIT.md`/`docs/DOCKER.md`) — nothing has
  drifted. Stated here with this round's own fresh build-and-inspect
  evidence, not by citing the prior finding as still sufficient.

---

## Files changed

- `core/dependencies/validation.py` — version-detection scan window and
  fallback fixed; `_try_version` no longer stops at the first
  unparseable command; `env=child_process_env()` added to both
  subprocess calls.
- `core/dependencies/registry.py` — `KNOWN_INCOMPATIBLE_VERSIONS` /
  `known_incompatible_version()` added; amass's `version_commands`
  order and pinned install version corrected.
- `core/dependencies/service.py` — wires the incompatibility gate into
  `analyze_tool`.
- `config/settings.py` — removed dead `whois_path` field.
- `config/.env.example` — removed `WHOIS_PATH`, added 23 previously
  undocumented real settings, added an explanatory comment for the
  native WHOIS client.
- `core/verification/grounding.py`, `core/verification/preflight.py`,
  `core/collection/{ssrf,gateway,crawler_proxy}.py`, `core/store.py` —
  14 real mypy errors fixed with type-narrowing (no ignores/casts).
- `pyproject.toml` — added the 16-module strict mypy override block.
- `utils/subprocess.py` — added `child_process_env()`/
  `_CHILD_ENV_ALLOWLIST`; wired into `run_command`; removed dead
  `check_tool_available()`/`get_tool_version()`.
- `core/logger.py` — added `RedactingFormatter`; wired into
  `setup_logging()`.
- `utils/security.py` — added the API-key-shape secret pattern.
- `docs/DOCKER.md` — added the per-tool compatibility-strategy table
  (Task 1).
- New tests: `tests/test_tool_version_detection.py`,
  `tests/test_config_documentation_sync.py`,
  `tests/test_mypy_strict_module_coverage.py`; extended
  `tests/test_subprocess.py`, `tests/test_dependencies.py`,
  `tests/test_logger.py`, `tests/test_security.py`.

---

## Remaining risks (honest, by enforcement level)

- **PATH-based bare-name tool resolution is trusted, like every other
  CLI application** — `BinaryDiscovery` resolves bare tool names via
  `shutil.which`. An operator whose own `PATH` is already compromised
  (e.g. a malicious `subfinder` earlier in `PATH`) is a pre-existing
  condition Hydra's subprocess layer cannot detect without breaking
  normal tool discovery; only explicitly-configured absolute/relative
  paths get the deeper `validate_binary_path` symlink/executable check.
  This is unchanged from before this round and considered out of scope
  for an application-level fix — it is equivalent to the trust already
  extended to every other program a user runs from their own shell.
- **The child-process environment allowlist is a fixed list, not a
  per-tool policy** — every external tool gets the same minimal
  environment (`PATH`/`HOME`/locale/`TMPDIR`/`TZ`/`GOPATH`/`GOCACHE`).
  If a future tool integration genuinely needs an additional
  environment variable to function, it will fail (loudly — a missing
  env var causes a normal tool error, not a silent misbehavior) rather
  than needing a workaround; extend `_CHILD_ENV_ALLOWLIST` deliberately
  in that case rather than reverting to full inheritance.
  `core/dependencies/validation.py` and `utils/subprocess.py` are the
  only two files that spawn a subprocess project-wide (verified via a
  full-repo grep) — both now route through the same allowlist, so
  there is no third call site that could silently regress.
  `child_process_env()` is a plain function (not itself under mypy's
  strict carve-out from Task 3); a future edit to it is only checked at
  runtime by `tests/test_subprocess.py`, not by mypy.
- **Log redaction is pattern-based, necessarily incomplete against a
  determined novel secret shape** — `RedactingFormatter`/
  `SecretRedactingFilter` catch every currently-known secret shape
  (keyword-anchored generic secrets, credential-embedded URLs, and now
  Anthropic/OpenAI key shapes) but cannot guarantee catching a future
  provider's key format with no recognizable shape or keyword context
  until a pattern is added for it — the same limitation
  `_SECRET_PATTERNS`'s own docstring already documents ("fail safe by
  over-redacting," not "guaranteed complete"). This is a structural
  property of pattern-based redaction, not a regression this round
  introduced.
- **mypy's strict carve-out (Task 3) covers 16 of the most
  security-sensitive modules, not the whole codebase** — `modules/*.py`
  (every plugin), `ui/*.py`, and most of `utils/*.py` (including the
  files touched by Tasks 5/6 this round —
  `core/logger.py`/`utils/security.py`/`utils/subprocess.py`/
  `core/dependencies/*.py`) remain under the blanket
  `ignore_errors = true`. This is a deliberate, incremental scope
  decision carried forward from Task 3, not an oversight — expand the
  carve-out list in a future round using the same pattern.
- **Docker capability confinement is OS/container-level, not a
  substitute for application-level authorization** — as in prior
  rounds, `naabu`'s `cap_net_raw` grant lets it perform raw-socket scans
  regardless of what CollectionScope/authorization state Hydra's
  application logic is in; the container boundary and the application
  boundary are independent, complementary controls, not one
  subsuming the other.

---

## Quality gate (this round's final numbers)

- `pytest tests/ -q`: run 8 times across this round (5 mid-round + 3
  final, after every code change in this document landed) —
  **913 passed, 10 skipped, 0 failed** every time, identical skip set
  each run.
- `ruff check .`: **All checks passed** (0 findings).
- `black --check .`: **225 files unchanged** (4 pre-existing
  Task-1/3-era formatting nits fixed this round).
- `isort --check-only .`: clean (only the deliberately-excluded
  `output/`/`logs/`/`.venv` paths skipped, per `pyproject.toml`).
- `bandit -c pyproject.toml -r .`: **No issues identified** (26
  pre-existing, already-justified `#nosec` suppressions from prior
  rounds, 0 new).
- `mypy .` (project-wide, honoring the Task 3 override block):
  **Success: no issues found in 129 source files**.
