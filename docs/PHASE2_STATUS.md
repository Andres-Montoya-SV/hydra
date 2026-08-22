# Phase 2 Refactor Status

## Implemented

| Component | Path | Status |
|-----------|------|--------|
| Platform detection | `core/platform.py` | Done |
| Tool discovery | `core/discovery/tool_discovery.py` | Done |
| Dependency report | `ui/dependency_report.py` | Done |
| Canonical Host model | `core/assets.py` | Done |
| SQLite store | `core/store.py` | Done |
| Validation engine | `core/validation/engine.py` | Done |
| Confidence scoring | `core/confidence.py` | Done |
| Risk engine | `core/intelligence/risk.py` | Done |
| Clustering | `core/intelligence/clustering.py` | Done |
| Historical diff | `core/diff.py` | Done |
| Normalizer | `core/normalizer.py` | Done |

## Critical Fixes Applied

- Tool discovery replaces naive `-h` check
- Missing optional tools are skipped (not executed)
- Non-zero exit codes = failure
- DNS unresolved hosts excluded from httpx
- Naabu mass-port warnings + LOW confidence
- 50MB subprocess stdout cap
- Partial reports in `finally` block
- Exit code 1 on any error

---

## Phase 3+ — Intelligence Engine, Rebrand, OPSEC (this milestone)

Everything below builds on Phase 2's canonical model and SQLite store without
replacing them — the file-centric plugin execution and reporting pipeline
from Phase 1/2 are preserved and extended.

### Rebrand

- Application renamed to **Hydra** (second rebrand; previously Cooper) across
  the CLI (`app.py` `prog`), TUI title (`ui/dashboard.py`), report headers
  (`core/reporter.py`), and docs. `python app.py heads` lists every plugin.

### Intelligence Engine

| Component | Path | Status |
|-----------|------|--------|
| Host profiling / categorization | `core/intelligence/profile.py` | Done |
| Infrastructure graph (ASN/CDN/provider/tech/cert edges) | `core/intelligence/graph.py` | Done |
| Intelligence pipeline orchestration | `core/intelligence/engine.py` | Done |
| Per-tool → canonical `Host` parsers | `core/parsers/registry.py`, `core/parsers/crawlers.py` | Done |
| Interactive HTML reports (dark mode, search, risk filter, sortable tables) | `core/reporter.py` | Done |
| `check-opsec` diagnostics + report renderer | `core/opsec_check.py`, `ui/opsec_report.py` | Done |

### New Infrastructure Intelligence Plugins ("Block B")

| Plugin | Purpose | External dependency | Enabled by default |
|--------|---------|---------------------|---------------------|
| `modules/whois.py` | Domain registration data | system `whois` client | Yes |
| `modules/asn_lookup.py` | ASN/IP ownership via Team Cymru bulk WHOIS | None (raw TCP socket) | Yes |
| `modules/ctlogs.py` | Certificate Transparency subdomain discovery via crt.sh | None (stdlib `urllib`) | Yes |
| `modules/port_verify.py` | `nmap -sV` re-verification of naabu findings (fixes false positives) | `nmap` | Yes, if `naabu` also enabled |
| `modules/threat_intel.py` | URLhaus host reputation | None (stdlib `urllib`); requires `URLHAUS_API_KEY` | No — opt-in |
| `modules/browser_probe.py` | WebKit cloaking detection (compares httpx vs. real browser navigation) | Playwright (`requirements-optional.txt`) | No — opt-in, active/intrusive |

Each plugin follows the existing pattern: a `BaseToolPlugin` subclass, a
dedicated `ToolParser` merging results into the canonical `Host`, explicit
wiring in `core/runner.py`'s stage order, and settings in
`config/settings.py` / `config/.env.example`.

### Fail-Closed Operational Security (`STRICT_OPSEC`)

- `STRICT_OPSEC=true` requires `OUTBOUND_PROXY_URL`; the pipeline refuses to
  start otherwise (`ConfigurationError` in `core/runner.py`).
- Blocks direct-network plugins (`dnsx`, `naabu`, `port_verify`, `whois`,
  `asn_lookup`, `katana`, `hakrawler`, `gau`, `waybackurls`, `nuclei`); routes
  `httpx`, `ctlogs`, `threat_intel`, and `browser_probe` through the proxy.
- Suppresses researcher/custom headers, uses a generic User-Agent.
- Local artifact hygiene: owner-only directory/DB permissions, provenance
  stores filenames only (not absolute paths), plugin `raw_artifact` fields
  store run-relative paths (never the analyst home directory), log redaction
  of proxy credentials and home directory paths.
- `python app.py check-opsec` — pre-flight diagnostic (proxy reachability,
  functional proxy test, httpx argument inspection, blocked-plugin list).

### Bug Audit (3-agent parallel audit across `modules/`, `core/`, and
`config`/`security`/CLI/`reporting`)

24 confirmed bugs fixed, including: DNS resolution failures silently treated
as success (`dnsx.py`), plugin status permanently stuck at `RUNNING`
(`unfurl.py`), a cache key that ignored `STRICT_OPSEC`/proxy mode (letting a
strict run silently reuse direct-probe results), `_finalize_to_store` +
report generation running twice on every successful run, provenance dedup
being a no-op due to a volatile timestamp field, `HostProfile` fields dropped
on every DB round-trip, duplicate infrastructure-graph edges, an
`atomic_write_text` temp-filename collision that could silently destroy an
unrelated file, and case-sensitive/unbounded home-directory log redaction.

### Port Scan Reliability Hardening (post-milestone bug reports)

Real-world runs against shared-hosting targets (DreamHost) surfaced several
port/WHOIS reliability issues, each closed with a regression test:

- **WHOIS IANA-vs-registrar date bug**: for gTLDs whose whois response is a
  referral chain (e.g. `.xyz`), the parser now anchors on the LAST
  `Domain Name:` block (`modules/whois.py::_authoritative_block`) instead of
  the first date-like fields in the blob, which previously picked up the
  TLD's own IANA delegation date instead of the domain's registration date.
- **WHOIS full-hostname bug**: `whois.py` now reduces every target to its
  registrable root domain via `core.domain.parse_hostname()` before querying
  (deduplicated), instead of passing a subdomain straight to the `whois`
  registry, which always returned `No match for domain`.
- **Naabu single-pass noise**: shared-hosting anti-scan middleboxes complete
  TCP handshakes for a different random sample of ports on every single
  `naabu` pass. `naabu.py` now re-probes exactly the first pass's open ports
  a second time (`NAABU_CONFIRM_OPEN_PORTS`) and keeps only the intersection.
- **Missing raw nmap evidence**: `port_verify.py` now writes the full
  `nmap -sV` stdout/stderr per host to `port_verify_raw/<host>.txt` (mirroring
  `whois_raw.txt`) and references it via a `raw_artifact` field in
  `port_verify.jsonl`, so parsing can be audited against ground truth.
- **Tarpit/portspoof detection**: some targets don't just add noise — they
  fabricate "open" TCP handshakes for literally every port (confirmed live
  against `www.metaversejustice.com`: 4/4 arbitrary high ports with no
  possible real service all returned "open" under `nmap -sV`, and every
  reported service was an unconfirmed `?` guess). `naabu.py` now probes a
  handful of randomly-chosen high ports (20000-60000, re-randomized every
  run) against each host **before** the real scan; if
  `NAABU_TARPIT_OPEN_THRESHOLD` (default 2) or more come back "open", the
  host is flagged `Host.tarpit_suspected` in `core/assets.py`, the real
  naabu/nmap scan is skipped for that host, and `core/confidence.py` /
  `core/intelligence/risk.py` exclude that host's port data from
  confidence/risk scoring entirely (raw naabu/port_verify observations are
  still preserved in `assets.json` for audit). `core/parsers/registry.py`'s
  `TarpitCheckParser` attaches an informational `tarpit-detected` finding,
  and reports (`summary.json`, `summary.md`, `summary.html`) surface an
  explicit "⚠ Tarpit/Portspoof Suspected" warning instead of listing
  individual ports as findings for that host.
- **"Don't trust blindly" layer (wildcard DNS + soft-404 + cloaking)**:
  - `modules/wildcard_check.py` — before trusting passive subdomain enum,
    resolves 2–3 random improbable canaries via dnsx; hits produce
    `wildcard-dns-detected` (info Finding) and demote confidence for
    passively-only children under that root.
  - `modules/soft404_check.py` — after httpx, probes a random nonexistent
    path; HTTP 200 + root-like body → `soft-404-detected` (info Finding).
  - `modules/browser_probe.py` — opt-in Playwright WebKit mobile probe;
    final-domain mismatch vs httpx → `cloaking-detected` (medium Finding)
    plus rendered HTML under `browser_probe_raw/`.

---

## Hydra milestone (rebrand v2, privacy, CI, intel heads)

### Rebrand (second)

- Application renamed **Cooper → Hydra** (`app.py` prog/`--version`, TUI title,
  report headers, docs, `pyproject.toml` name, User-Agent defaults).
- ASCII hydra banner on every CLI invocation; `python app.py heads` lists
  every plugin as a named head.
- `LICENSE` (MIT) and `AUTHORIZED_USE.md` consolidate authorization warnings.

### Artifact path privacy

- `raw_artifact` in JSONL is always relative to the run output directory
  (`utils.security.relative_output_path`). Absolute analyst paths are not
  persisted in shareable reports. Provenance still stores filenames only.

### CI/CD

- `.github/workflows/ci.yml` — Python 3.10–3.12 matrix: ruff, black, isort,
  mypy, bandit, pytest.

### OPSEC

- `check_dns_leak()` (informational: local OS resolver vs proxy).
- Aggregated `summarize_checks()` line on `check-opsec`.
- `STRICT_OPSEC` scan gate (`enforce_opsec_gate`) fail-closed on any `fail`.

### New heads

| Plugin | Purpose | Default |
|--------|---------|---------|
| `vuln_match` | OSV.dev CVE correlation; WPScan opt-in via `WPSCAN_API_TOKEN` | On |
| `security_headers` | Missing HSTS/CSP/XFO/… findings + `security_headers_score` | On |

### Scope and webhooks

- `SCOPE_FILE` / `scope.example.txt` — fail-closed if configured and target
  is out of scope. `scope.txt` is gitignored.
- `WEBHOOK_URL` — Slack/Discord `text`/`content` payload on `diff.json`
  changes; silent no-op when unset.

### TLS / CA bundle (certifi)

Stdlib HTTPS (OSV.dev, crt.sh, WPScan, URLhaus, OPSEC echo, webhooks) always
uses `utils.network.default_ssl_context()` with `certifi.where()` as `cafile`.
This avoids macOS virtualenvs whose default trust store cannot verify public
CAs even when `curl` (Anaconda/system bundle) succeeds. `certifi` is a pinned
runtime dependency. If verification still fails, the exception/raw artifact
states that it may be real MITM/interception, not a local Python CA-store
issue. Target-host recon probes (`core.http_probe.insecure_ssl_context`) are
unchanged — they still skip TLS verify to match httpx's alive-host posture.

### HTML reports

- Executive summary (template, no LLM), per-`template_id` glossary, and
  collapsible raw evidence from relative artifacts.

## Remaining

See `docs/ARCHITECTURE_REVIEW.md` for the original problem register — most
Critical/High items are now resolved. Open items: resume-from-checkpoint,
config profiles, massdns integration, standalone `diff`/`export` CLI
subcommands.

