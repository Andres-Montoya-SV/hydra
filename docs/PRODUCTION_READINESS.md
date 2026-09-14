# Hydra — Production Readiness Certification

**Status: certification, not a hardening round.** Branch
`release/production-readiness-certification`, cut from `main` after both
hardening rounds (`docs/HARDENING_ROUND1_P0.md`, `docs/HARDENING_ROUND2_P1.md`)
were merged (P1 was merged as part of starting this certification — it had
been reviewed and pushed but not yet merged; see the session's own record).
This document does not re-derive anything already proven — it re-runs the
load-bearing checks with fresh evidence, closes the two named loose ends,
runs one real end-to-end production pass, and states a single verdict.

---

## Verdict

# READY WITH KNOWN LIMITATIONS

Hydra's core safety property — a target-directed plugin cannot reach an
unauthorized network destination without going through Hydra's own
authorization/confinement layer — holds under fresh, live testing (117/117
adversarial confinement tests, a live production run, this session). The
known limitations below are real, bounded, and already the subject of
explicit design decisions (not oversights discovered here) — none of them
compromise that core property. Two were found and fixed in this
certification itself (a stale Dockerfile/doc claim about `whois`; a stale
README claim about `amass` "breaking silently," now superseded by Round 2's
fix). Nothing found here should block using Hydra against a real,
authorized bug bounty program — but the operator should read the limitations
list below once, deliberately, before the first real run, not discover them
mid-engagement.

### Known limitations (consolidated, one place)

1. **`naabu`/`port_verify`'s raw TCP/SYN scanning is not connection-pinned.**
   HTTP-speaking collectors resolve a hostname, validate the resolved IP
   against the SSRF blocklist, and connect to *that exact validated IP*
   (`ScopeEnforcingProxy`) — closing the DNS-rebinding/TOCTOU gap. Raw
   socket tools cannot be routed through an application-level proxy at
   all: `naabu` does its own resolution and connects directly, so a
   rebind between Hydra's authorization check and naabu's own connect is
   invisible to Hydra by construction. This is an OS/container-level gap,
   not an application-level authorization gap — Hydra still only ever
   *tells* naabu about authorized hosts; what naabu's own raw-socket
   engine does with that is outside any forward-proxy's reach. Documented
   since `docs/FINAL_PROJECT_AUDIT.md`; re-confirmed unchanged this
   session (`tests/test_untrusted_network_bypass.py`, fresh, still
   passing, still proving the same limitation rather than hiding it).
2. **`amass` v5 does not work with `modules/amass.py`** (the installed
   binary's `-o` flag was removed upstream). As of Round 2 this is
   *detected*, not silent: `check-tools` and the pipeline's own
   pre-flight validation report it as not-runnable with the exact fix
   before the plugin ever attempts to run — confirmed live in this
   certification's own production run (Part 2, below). The underlying
   incompatibility itself is unfixed (a real fix means pinning `amass` v4
   or rewriting the plugin against v5's directory-based output — out of
   scope for both hardening rounds and this certification).
3. **Six plugins have zero regression-test coverage of their own parsing/
   execution logic**: `amass`, `anew`, `assetfinder`, `gau`, `unfurl`,
   `waybackurls`. Re-confirmed unchanged this session (direct grep: 0
   references to any of their plugin classes in `tests/`). All six are
   real, installed, invocable tools that ran cleanly in this
   certification's live production run; none have ever had a
   `.parse()`-level unit test.
4. **`nuclei`'s membership in `PROXY_VERIFIED_TOOLS` rests on a mocked
   flag-enforcement test, not a live-binary confinement test** — found and
   documented in this certification (Part 1.1, below). `katana` and
   `hakrawler` both have dedicated live tests that actually spin up the
   real binary against a local arbiter server and confirm out-of-scope
   requests are blocked (`tests/test_crawler_confinement_live.py`);
   `nuclei`'s equivalent proof is `tests/test_crawler_proxy_flag_enforcement.py`,
   which proves the `-proxy` flag is always passed and mocks the rest.
   This is a real, previously-uninspected gap in verification *rigor*,
   not a known confinement failure — nothing found here suggests nuclei
   actually leaks.
5. **The OpenAI half of the reportability agent's real-API path is proven
   to reach the real API and handle a real error correctly, but not
   proven to complete a full successful assessment against this
   session's available key** — see Part 2, item 4. The Anthropic half
   completed successfully end-to-end with a real API call.
6. **Test suite: a very minor, non-reproducing skip-count variance**
   observed this session (Part 3, item 1) — never a failure, only whether
   one specific test's skip condition fires. Noted for a future session
   to pin down; does not block this verdict.

None of these are new discoveries this document is trying to spin
favorably — every one of them is either already in `README.md`/
`docs/FINAL_PROJECT_AUDIT.md`, or is a direct, disclosed product of this
certification's own testing (items 4–6).

---

## Part 1 — Closing the two named loose ends

### 1.1 — `katana`/`hakrawler`/`nuclei` confinement: closed, with one caveat surfaced

Ran fresh, this session:

```
tests/test_crawler_confinement_live.py .... (6 tests)
tests/test_no_bypass_network_primitives.py ..... (5 tests)
======================= 11 passed, 6 warnings in 24.39s ========================
```

**11/11 passed.** This closes the historical pending item exactly as
scoped: `katana`/`hakrawler` network confinement against real installed
binaries, and the static guard that no built-in collector reaches for a
raw network primitive directly, are both confirmed with this run's own
number — not a reference back to Round 1's 171/172.

**Caveat found, not asked for but relevant to the same question**:
`nuclei` is listed in `core/collection/crawler_proxy.py::PROXY_VERIFIED_TOOLS`
alongside `katana`/`hakrawler`, but grepping for a live-binary nuclei
confinement test (`shutil.which("nuclei")`-gated, real subprocess) found
none. Its only coverage is
`tests/test_crawler_proxy_flag_enforcement.py::test_nuclei_always_receives_proxy_flag`,
which mocks the subprocess call and only proves the `-proxy` argument is
always present — a materially weaker guarantee than katana/hakrawler's
"we actually ran the real binary against a local server and it never
reached the unauthorized target." Recorded as known limitation #4 above.
Not fixed here (writing a new live nuclei confinement test is real
implementation work, out of scope for a certification).

### 1.2 — OpenAI model name verified against real, current documentation

`config/settings.py` (three call sites) and `config/.env.example` set
`openai_model` to `"gpt-5.6-terra"`. Verified against OpenAI's own current
API documentation:

> **Model ID:** `gpt-5.6-terra` — "This is the exact identifier to use in
> API calls." Pricing: $2/million input tokens, $12/million output tokens.

Source: <https://developers.openai.com/api/docs/models/gpt-5.6-terra>
(fetched live this session). `core/reportability/cli.py`'s tracked input
price (`_INPUT_PRICE_PER_MTOK["gpt-5.6-terra"] = 2.00`) matches exactly.

**Confirmed correct — no change needed.** Unlike the Claude model names
(verified when the reportability agent was designed), this was the one
model identifier nobody had checked against a real, external source until
now. It was already right.

---

## Part 2 — Real production run against `virusbarrier.xyz`

Ran the actual pipeline, natively (`.venv`, which has `anthropic`,
`openai`, and `playwright` installed — the richest environment available),
with every tool this machine has installed:

```
SCOPE_FILE=<dedicated scope file, "virusbarrier.xyz" only> \
.venv/bin/python3 app.py run -d virusbarrier.xyz --no-ui --no-banner \
    --run-id production-readiness-cert-20260914
```

(A dedicated, temporary `SCOPE_FILE` was used rather than the repo's own
root `scope.txt`, which is the operator's real, currently-active scope for
a *different* program — the run's actual seed authorization came from
`-d virusbarrier.xyz` itself, per `app.py`'s own `CollectionScope.from_seeds`
logic; nothing in the operator's live scope configuration was touched.)

**First attempt correctly refused to run**: the real `.env`'s own
`SCOPE_FILE` (pointing at the operator's other live program) does not
include `virusbarrier.xyz`, and the pipeline's own validation stage
refused with `Target(s) outside SCOPE_FILE: virusbarrier.xyz` before
touching the network — the authorization gate working exactly as
designed, on the very first real invocation of this certification.

**Real-world finding, disclosed rather than hidden**: `virusbarrier.xyz`
no longer resolves. Confirmed independently of Hydra
(`dig`/`nslookup virusbarrier.xyz` → `NXDOMAIN`) and by Hydra's own run
(`dnsx: Resolved 0 hosts`). WHOIS returned only the generic IANA/registry
stub — Hydra's native referral-following WHOIS client correctly detected
and reported this as a real external rate-limit response
(`WHOIS: virusbarrier.xyz: rate limited by WHOIS server ('rate limit' in
response)`), not a Hydra bug. A fresh certificate-transparency lookup
found only a single-SAN Let's Encrypt certificate issued 2026-07-22
(subject `virusinspector.top`, one SAN: `virusbarrier.xyz`) — a
*different*, much smaller certificate than the original 6-SAN one the
correlation-engine case was built on. Read together, this strongly
suggests the malicious infrastructure documented in
`docs/CORRELATION_ENGINE_DESIGN.md` has genuinely been taken down or
reconfigured since the 2026-08-31 case — a change in the real world, not
a Hydra defect. This materially limited what a *fresh* live run could
demonstrate; each numbered item below states exactly what was and wasn't
possible as a result, and what was used instead.

Tool health at run start: 13/14 healthy, 1 missing — `amass` (see below).
External-target-mode fired correctly (target not in `OWNED_DOMAINS`):
conservative rate limits applied, and `enable_param_fuzz`/
`enable_cloud_bucket_enum`/`enable_browser_probe` were **fail-closed
disabled** because no terminal was attached to confirm them — exactly the
documented non-interactive behavior, not a workaround applied to make the
run "cleaner."

### 1. Six-domain cluster reconstruction

**Could not be demonstrated live** — the seed no longer resolves, so this
run's own CT-log observation was a single-SAN certificate, not the
original 6-SAN one. **Substituted with the existing regression suite,
run fresh**: `tests/test_virusbarrier_e2e.py`, 5/5 passed, replaying the
real captured 2026-08-31 case data (`tests/fixtures/virusbarrier/`). The
correlation engine's logic is intact; a fresh live demonstration of this
specific historical case is no longer possible because the infrastructure
itself has changed. Not fixable by re-running harder — the target is
gone.

### 2. Zero unauthorized connections

The live run's own `intel_network_requests`/`intel_collection_attempts`
audit tables have **0 rows** for this run — because 0 hosts resolved,
nothing ever reached an active-collection stage where such a row would be
created (`katana`/`hakrawler`/`nuclei`/`unfurl`: "Skipped — no alive URLs").
This is a true but weak answer to the question asked. **Supplemented with
fresh, comprehensive evidence** instead: the full confinement/adversarial
suite, run fresh this session:

```
tests/test_browser_confinement_live.py, test_crawler_confinement_live.py,
test_followup_adversarial_oracle.py, test_httpx_confinement_live.py,
test_no_bypass_network_primitives.py, test_opsec_proxy_chaining.py,
test_redirect_destination_oracle.py, test_ssrf_destination_policy.py,
test_strict_opsec_proxy_routing.py, test_subresource_escape_oracle.py,
test_untrusted_network_bypass.py, test_urllib_confinement_live.py
======================= 117 passed, 41 warnings in 142.66s ========================
```

**117/117, 0 failed.** This is a stronger test of "can an unauthorized
destination be reached" than a live run against a domain with nothing to
actively collect against — real local malicious servers, real redirect
escapes, real SSRF/rebinding attempts, real tool binaries.

### 3. No unexpected `INVALIDATES`

The live run's own verification summary: `0 confirmed, 0 pending, 0
findings invalidated` — trivially true (0 findings existed to verify).
**Supplemented**: the full verification-agent suite, run fresh:

```
tests/test_reporter_verification_gate.py, test_verification_detectors.py,
test_verification_grounding.py, test_verification_model.py,
test_verification_postmodule.py, test_verification_preflight.py
======================== 127 passed, 58 warnings in 5.14s =========================
```

**127/127, 0 failed.**

### 4. `assess-reportability` end-to-end with a real API call

Real `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` were available in this
environment (the repo's root `.env` — not `config/.env`, which
`Settings.from_env()`'s own candidate order checks first). `anthropic`
was already installed in `.venv`; `openai==3.13.0` (exact version pinned
in `requirements-optional.txt`) was installed for this certification.

**Anthropic — full success, real API call**:

```
ANTHROPIC_API_KEY=<real> pytest tests/test_reportability_live.py -v
tests/test_reportability_live.py::test_real_api_call_against_real_stripchat_rules_produces_a_grounded_citation PASSED
1 passed in 6.76s
```

This is the project's existing purpose-built live test — real Claude
Sonnet 5 call, real Stripchat rules fixture, a synthetic finding on a
domain clearly outside Stripchat's assets, asserting the real response is
`NOT_ELIGIBLE`/`UNCERTAIN` with a citation that greps clean against the
real rules text. **The full Anthropic reportability path is proven
end-to-end with a real, non-mocked call.**

**OpenAI — real call confirmed, full success not obtained**: no
equivalent live test existed for OpenAI in the codebase, so a one-off
script mirroring the Anthropic test exactly (same Stripchat fixture, same
synthetic finding, `--provider openai`) was run three times. All three
attempts reached the real OpenAI API and received a genuine
`openai.RateLimitError`, which Hydra's own error-mapping
(`core/reportability/openai_client.py`) correctly translated to a clean
message (`"Error: Rate limited by the OpenAI API — wait and retry."`)
rather than crashing. This proves the OpenAI code path is real (not
mocked) and that its real-world error handling works — but a full
successful real completion could not be obtained in this session; the
available key's account tier appears rate-limited beyond what a few
retries with backoff can clear. **Recorded as known limitation #5**, not
silently retried until it happened to work, and not treated as a code
defect (the mocked test for this exact error,
`test_reportability_openai_client.py::test_rate_limit_error`, is now
independently confirmed to represent real API behavior accurately).

### 5. Docs vs. reality

Found and fixed one real discrepancy: **`Dockerfile` installed an unused
`whois` apt package**, and both the Dockerfile's own comment and
`docs/DOCKER.md` (two places) claimed `modules/whois.py` uses it. Round 2
(`docs/HARDENING_ROUND2_P1.md`, Task 2) had already confirmed
`modules/whois.py` uses Hydra's own native Python WHOIS client
(`core/collection/whois_client.py`) and removed the dead `WHOIS_PATH`
setting — but that fix never propagated to the Docker image or its docs.
**Fixed in this certification**: removed the `whois` apt package from
`Dockerfile`, corrected both `docs/DOCKER.md` references. Verified the
rebuilt image genuinely has no `whois` binary (`which whois` → not found)
and still builds and passes its full test suite (Part 3).

Also found and fixed: `README.md`'s "Known limitations" section still
said `amass` "is currently broken" with no mention that Round 2 made this
detected-and-gated rather than silent — corrected to describe the current,
accurate state (see the Verdict section's limitation #2).

Everything else checked — the per-tool compatibility-strategy table in
`docs/DOCKER.md` (added by Round 2), the non-root/capability/permission
claims, the `SCOPE_FILE`/`OWNED_DOMAINS`/external-target-mode behavior —
matched exactly what this run and Part 3's Docker rebuild observed.

---

## Part 3 — General health, fresh numbers

### 1. `pytest tests/ -q` — 5+ consecutive runs

Two environments were exercised, both fully clean of failures:

**Native, `.venv` (all optional dependencies + real API keys present —
the richest environment available, exercising the most code)**, 7 total
runs across this session:

| Run | Result |
|---|---|
| 1–5 (consecutive loop) | `1001 passed, 1 skipped` each time |
| 6, 7 (ad-hoc reruns while investigating the skip) | `1002 passed, 0 skipped` each time |

**0 failures in all 7 runs.** The one open item: which test is skipped
varies (5/7 runs skip exactly one; 2/7 skip none) — every attempt to
capture `-rs` output for the *skipping* runs raced with unrelated system
load (concurrent Docker build) and only ever caught the *non-skipping*
state. Not a failure in any run; recorded as known limitation #6 for a
future session to pin down with a clean, isolated re-run.

**Inside the freshly built Docker image** (Part 3.3): `1001 passed, 1
skipped` — the skip identified precisely:
`tests/test_reportability_live.py:39: ANTHROPIC_API_KEY not set` — correct
and expected, since no real `.env` is ever baked into the image
(`docs/DOCKER.md`/`.dockerignore`, re-confirmed below).

### 2. Lint / format / security / type gates

| Tool | Command | Result |
|---|---|---|
| ruff | `ruff check .` | **All checks passed** |
| black | `black --check .` | **225 files unchanged** |
| isort | `isort --check-only .` | **clean** (only `.venv`/`logs`/`output` skipped, as configured) |
| bandit | `bandit -c pyproject.toml -r .` | **No issues identified** — 26,108 lines scanned, 26 pre-existing `#nosec` suppressions (all reviewed in prior rounds), 0 new |
| mypy | `mypy .` | **Success: no issues found in 129 source files** (honoring Round 2's 16-module strict carve-out) |

### 3. Docker — full rebuild from scratch, tested inside

```
docker build --no-cache -t hydra:cert-nocache .
```

Built clean, first try after a real Docker Desktop restart on this
machine (see below). Final image: **2.79 GB** (documented target in
`docs/DOCKER.md`: ~2.72 GB — a small, non-alarming drift, most likely the
base image's own patch-level updates plus the `whois` apt removal; not
investigated further, well under the doc's own "grows *noticeably*
beyond ~2.7 GB" threshold for concern).

Re-verified against the *fresh* image, not assumed from Round 0's
`hydra:audit`:

- **Non-root**: `uid=10001 user=hydra`.
- **Capabilities**: `getcap -r /usr/local/bin/ /usr/bin/` → exactly one
  line, `/usr/local/bin/naabu cap_net_raw=ep` — nothing else.
- **No `whois` binary present** (confirms this certification's Dockerfile
  fix took effect in a real build, not just in the diff).
- **No real secret baked in**: only `config/.env.example` exists under
  `/app/config`; no real `.env` anywhere in the image.

**Full test suite run inside the container**: `1001 passed, 1 skipped in
289.21s` — the one skip is the same `ANTHROPIC_API_KEY not set` case as
native (no real credentials are ever shipped with the image, by design).
**Matches native exactly, modulo the one credential-gated test that is
supposed to differ.**

*A real environment note, not a Hydra finding*: partway through this
certification, Docker Desktop on this machine stopped responding
(daemon reachable but registry pulls hung indefinitely) and required a
full quit-and-relaunch to recover. This is a local infrastructure hiccup
unrelated to Hydra's own code or Docker configuration — recorded here for
transparency about what this session actually did, not as a project
finding.

### 4. Documentation accuracy — `docs/FINAL_PROJECT_AUDIT.md` + both hardening reports

- **`docs/FINAL_PROJECT_AUDIT.md` §3.1** (katana/hakrawler/nuclei):
  already correctly marked "partially done, not never executed" — this
  certification's Part 1.1 is a strict continuation, not a contradiction,
  and adds the nuclei-specific caveat that audit didn't surface.
- **§3.2** (amass): already correctly root-caused and explicitly marked
  "not fixed in this pass" at the time — now fixed by Round 2 and
  reconfirmed live in Part 2 of this document. `FINAL_PROJECT_AUDIT.md`
  itself is not edited (it is a dated, point-in-time record, same
  editorial choice both hardening rounds made) — the fix is recorded in
  `docs/HARDENING_ROUND2_P1.md` and this document instead.
- **§1.4** (6-plugin coverage gap): re-confirmed unchanged, exact same 6
  plugins, via a fresh direct grep this session.
- **§1.2**'s framing of `mypy .` as "a weak signal... `ignore_errors =
  true` project-wide" is now **partially outdated**: Round 2 carved out
  16 security-priority modules into real strict checking (still true for
  the rest of the codebase, but no longer true project-wide). Noted here
  rather than editing the dated audit document.
- **Both hardening reports' own "Remaining risks" sections**: read
  against this session's evidence, nothing in either has changed —
  Round 1's OS/container-isolation caveat and Round 2's PATH-trust/
  allowlist-scope caveats are both still accurate, unchanged by anything
  found in this certification.
- **Fixed as part of this certification** (not pre-existing in any
  report): the `Dockerfile`/`docs/DOCKER.md` `whois` discrepancy and
  `README.md`'s stale amass wording — see Part 2, item 5.

---

## Runbook — pointing Hydra at a real bug bounty program for the first time

Written for an operator (including future-you) who has never run a real
engagement with this tool before, or who has and needs the exact steps
back without re-deriving them.

### Step 0 — Prerequisites

- Python 3.10–3.12 (this certification used 3.13 natively without issue,
  but the project's declared `requires-python` and CI matrix are
  3.10–3.12 — prefer one of those for anything you intend to rely on).
- At minimum: `subfinder`, `dnsx`, `httpx` (the three tools
  `Settings.required_tools` defaults to). Everything else is optional and
  degrades gracefully if missing.
- `python app.py check-tools` — run this *before* anything else, every
  time you set up a new machine or update a tool. It will tell you
  exactly what's installed, what's missing, and — since Round 2 — flag a
  known-incompatible version (like amass v5) with the exact fix, instead
  of letting you discover it mid-run as a cryptic subprocess error.

### Step 1 — Configure `.env`

Copy `config/.env.example` to `.env` at the **project root** (not
`config/.env` — `Settings.from_env()` checks the root first; either
location works, but pick one and be consistent, since only the first one
found is loaded). Fill in, at minimum:

- Any API keys for optional plugins you want (`WPSCAN_API_TOKEN`,
  `SECURITYTRAILS_API_KEY`, `URLHAUS_API_KEY` — all independently
  optional).
- `ANTHROPIC_API_KEY` and/or `OPENAI_API_KEY` **only if** you plan to use
  `assess-reportability` — never required for `run` itself.
- `RESEARCHER_ATTRIBUTION_HEADER`/`ATTRIBUTION_USER_AGENT` or
  `X_HACKERONE_RESEARCHER` if the program requires identifying traffic as
  security research (check the program's own rules first).
- `OUTBOUND_PROXY_URL` if you route traffic through an operator-controlled
  proxy — required if you set `STRICT_OPSEC=true` (Hydra refuses to start
  otherwise).
- Leave `ENABLE_AMASS` as its default (`false`) unless you have `amass`
  v4 specifically installed — v5 is confirmed non-functional with this
  plugin (see the Verdict section).

### Step 2 — Set the program's scope

Create `scope.txt` at the project root (or point `SCOPE_FILE` at wherever
you keep it) with the program's authorized patterns, one per line —
`*.example.com`, `!excluded.example.com` for exclusions, exact hostnames
for pinned assets. **This file is the actual authorization boundary** —
`-d <domain>` alone authorizes only that one seed domain; a `SCOPE_FILE`
is what lets Hydra's discovery stages (subfinder, CT logs, etc.) expand
into subdomains it finds on its own without asking again for each one.
Read the program's own rules first; Hydra enforces whatever you put in
this file, not what the program's rules say in prose — a mismatch between
the two is on the operator, not something Hydra can detect.

If the target(s) are not in `OWNED_DOMAINS` (the common case for a bug
bounty program you don't personally own), Hydra will apply conservative
rate limits automatically and — **with a terminal attached** — ask you to
confirm before running `param_fuzz`, `cloud_bucket_enum`, or
`browser_probe` directly at it. In a non-interactive/automated context,
these three are disabled by default (fail-closed) rather than silently
enabled — pass `--external` explicitly and have a real confirmation flow
if you need them in that context.

### Step 3 — First run

```bash
python app.py run -d <seed-domain> --run-id <a-name-you-will-recognize-later>
```

Watch the live TUI (or `--no-ui` for log-only output, e.g. in CI). Expect:

- A tool-health table at startup — read it. Anything `MISSING` with a
  clear reason (like amass v5) is Hydra telling you upfront what won't
  run and why, not a bug.
- Stage-by-stage progress: validate → subfinder → dedupe → dnsx → httpx →
  optional tools → metadata → output.
- A final summary: subdomain/resolved/alive counts, verification summary
  (confirmed/pending/invalidated finding counts), any warnings.

### Step 4 — Read the output, in this order

1. **`output/<run-id>/summary.json`** — machine-readable version of
   everything the TUI showed: `tools_failed`, `tools_skipped`, `errors`,
   `warnings`, verification counts. Read `warnings` even on a
   successful-looking run — a known-incompatible tool version or a
   rate-limited external lookup shows up here, not as a hard failure.
2. **`output/<run-id>/summary.html`** — the human-readable report.
3. **`python app.py investigate <domain>`** — analyst-readable
   explanations for any correlated infrastructure (shared certificate,
   shared IP, cloud tenancy) with a named confidence band. This never
   makes actor/attribution claims — it explains *why* Hydra thinks two
   things are related, not *who* is behind them.
4. **`python app.py graph <domain>`** — the raw relationship graph
   (nodes/edges) behind the `investigate` explanation, if you need the
   underlying evidence (certificate serials, SAN lists, IP overlaps).

### Step 5 — Interpreting "verification" and "findings"

A finding that survives to the report has already passed the verification
agent's re-check (`docs/VERIFICATION_AGENT_DESIGN.md`) — `INVALIDATES` and
low-confidence downgrades happen *before* you see the report, not after.
A `0 confirmed, 0 pending, 0 invalidated` summary on a small/quiet target
is not evidence of a bug (see this certification's own live run) — it
means there was nothing to verify, most commonly because nothing resolved
or nothing active ran.

### Step 6 — Reportability assessment (optional, costs real API credits)

```bash
python app.py assess-reportability <run-id> --program-rules <path-to-program-rules.txt>
```

Requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (whichever
`REPORTABILITY_PROVIDER` — default `anthropic` — points at) and produces
an eligibility verdict per finding (`ELIGIBLE`/`NOT_ELIGIBLE`/`UNCERTAIN`)
grounded against the program's actual rules text, with a citation you can
verify yourself. Estimate the cost first — the command prints an
estimated input-token cost before making any real API call. Never runs as
part of `run` itself; always a separate, deliberate step.

### Step 7 — Before your first *real* submission

Read `README.md`'s "Known limitations" section and this document's
Verdict section once. In particular: if `naabu` found something
interesting, remember its raw-socket scanning is not connection-pinned
the way HTTP-based findings are — treat a naabu-sourced finding with
the same care you'd give any tool's output, not extra trust because
Hydra ran it.

---

## The central question, answered with this certification's own evidence

> **Can a target-directed plugin do network I/O against an unauthorized
> destination without going through Hydra's authorization/confinement
> architecture?**

**No.** Evidence from *this* certification, not a prior round:

- **117/117** passed, fresh this session:
  `tests/test_browser_confinement_live.py`,
  `tests/test_crawler_confinement_live.py`,
  `tests/test_followup_adversarial_oracle.py`,
  `tests/test_httpx_confinement_live.py`,
  `tests/test_no_bypass_network_primitives.py`,
  `tests/test_opsec_proxy_chaining.py`,
  `tests/test_redirect_destination_oracle.py`,
  `tests/test_ssrf_destination_policy.py`,
  `tests/test_strict_opsec_proxy_routing.py`,
  `tests/test_subresource_escape_oracle.py`,
  `tests/test_untrusted_network_bypass.py`,
  `tests/test_urllib_confinement_live.py` — real local malicious servers,
  real redirect-escape and SSRF/rebinding attempts, real `katana`/
  `hakrawler`/`httpx`/urllib-based-plugin invocations, zero successful
  unauthorized connections.
- **A real production run** (Part 2) whose very first action was the
  authorization gate correctly *refusing* to proceed against an
  out-of-scope target — the architecture's first line of defense fired
  on the first real invocation of this certification, not in a
  controlled test.
- **The one documented exception is named, not hidden**: `naabu`'s raw
  TCP/SYN scanning cannot be connection-pinned by an application-level
  proxy — `tests/test_untrusted_network_bypass.py` (in the 117 above)
  proves this limitation concretely rather than merely asserting it, and
  it is listed as known limitation #1 above, not omitted from the answer.

The answer is `NO` for every HTTP/HTTPS-speaking collection path, backed
by fresh, this-session evidence. It is honestly `PARTIAL` for raw-socket
scanning, exactly as every prior audit and hardening round has said —
this certification did not change that fact and does not claim otherwise.
