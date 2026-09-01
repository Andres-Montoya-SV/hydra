# Hydra — scope-aware reconnaissance with evidence-backed intelligence

[![CI](https://github.com/Andres-Montoya-SV/hydra/actions/workflows/ci.yml/badge.svg)](https://github.com/Andres-Montoya-SV/hydra/actions/workflows/ci.yml)

Hydra is a **scope-aware reconnaissance pipeline with an evidence-backed intelligence control loop**. When follow-up collection is enabled, the production path is:

collect → intelligence → authorize → bounded follow-up → evidence → relationship → SQLite → explanation

That loop is what Hydra means by Attack Surface Intelligence. Intelligence is not a post-scan sidecar: `PipelineRunner` ingests artifacts, plans indicators, re-authorizes them, and only then runs follow-up DNS/HTTP. Out-of-scope names may be **observed**. They are never actively collected unless `authorize_active_indicator` returns `ALLOW`.

Works on **macOS**, **Ubuntu**, **Debian**, and **Kali Linux**.

**Authorization:** only scan systems you own or have explicit written permission to test. See [AUTHORIZED_USE.md](AUTHORIZED_USE.md). Licensed under [MIT](LICENSE).

---

## Features

- **Plugin architecture** — each recon tool is an isolated subprocess module. New tools still need a settings flag, a `modules/` file, and (if they write a novel artifact) a parser; they may also emit structured entities via `PluginResult.data["intel"]`
- **Mandatory pipeline** — subfinder → CT (observe) → seed dnsx → httpx, then bounded intelligence follow-up of **authorized** indicators
- **Central authorization** — every active probe must pass `authorize_active_indicator` (`ALLOW` / `DENY` / `UNKNOWN`). `UNKNOWN` fails closed. A `CollectionScope` object is not itself authorization
- **Evidence-driven intelligence** — Certificate Transparency / TLS SANs are retained as observations even when they are out of scope. Hydra records the relationship; it does not probe unauthorized names. Follow-up reasons such as `CERTIFICATE_SAN` are rejected unless the referenced evidence, SAN observation, and certificate entity exist
- **First-class entities** — Domain, IP, Certificate (SHA-256 fingerprint first), ASN, nameserver, HTTP service. `Host` is an attack-surface **projection**. Intel relationships are the correlation truth
- **Optional plugins** — URLhaus reputation, WebKit cloaking detection, amass, naabu, katana, hakrawler, gau, waybackurls, nuclei, assetfinder, unfurl, anew. Crawlers/scanners consume `authorized_alive.txt`, not raw `alive.txt`
- **SQLite intelligence store** (`core/store.py`, `output/recon.db`) — hosts plus entities, observations, evidence, relationships, and durable indicator lifecycle persist across scans
- **Correlation, not attribution** — shared certificate / IP / ASN / nameserver / favicon / body hash with named confidence. Shared IP, CDN, ASN, favicon, or body hash alone is never `HIGH`. Shared cloud IPs are `shared_cloud_tenancy` (MEDIUM). Hydra never emits actor/owner/campaign entities
- **Query without rescanning** — `investigate`, `graph`, `relationships`, `evidence` (domain or relationship id), `certificates`, `indicators`, `diff DOMAIN` or `diff RUN_A RUN_B`. CLI, HTML, Markdown, and JSON consume the same `serialize_relationship()` objects
- **Historical diffing** (`core/diff.py`) — host fields plus entities, observations, evidence, relationships (appeared / disappeared / confidence / evidence), indicators, and certificate rotation
- **Interactive HTML reports** — dark/light theme toggle, live search, risk-level filtering
- **Async execution** — concurrent optional tools, non-blocking subprocess I/O
- **Rich TUI** — live progress, tool status, statistics, logs, and results tables
- **Structured logging** — console + file, configurable levels
- **Secure subprocess** — no `shell=True`, input validation, path sanitization
- **Fail-closed OPSEC mode** (`STRICT_OPSEC`) — proxy-only egress, header suppression, and a `check-opsec` pre-flight diagnostic command
- **Bug bounty headers** — configurable `X-HackerOne-Researcher` and custom HTTP headers via `.env`
- **Outputs** — JSON and HTML/Markdown reports; httpx also writes a per-run `httpx.csv` artifact. Follow-up writes sidecar files (`resolved_followup_<pass>.txt`, `alive_followup_<pass>.txt`, …) and unions them into canonical artifacts without clobbering the seed snapshot

---

## Installation

### 1. System Requirements

- Python 3.10+
- Go 1.21+ (for installing ProjectDiscovery and community tools)

### 2. Clone and Install Python Dependencies

```bash
cd /path/to/hydra
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Browser cloaking detection is intentionally separate because it downloads and
executes a full browser:

```bash
pip install -r requirements-optional.txt
playwright install webkit
```

### 3. Install Recon Tools

The framework invokes external CLI tools via subprocess. Install the mandatory tools first:

#### macOS (Homebrew)

```bash
brew install subfinder dnsx httpx
```

#### Ubuntu / Debian / Kali

```bash
# Install Go if not present
sudo apt update && sudo apt install -y golang-go

# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Ensure Go binaries are on PATH
export PATH="$PATH:$(go env GOPATH)/bin"
```

#### Optional Tools

| Tool | macOS | Linux |
|------|-------|-------|
| naabu | `brew install naabu` | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| katana | `brew install katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| nuclei | `brew install nuclei` | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| gau | `brew install gau` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` | same |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` | same |
| hakrawler | `go install github.com/hakluke/hakrawler@latest` | same |
| unfurl | `go install github.com/tomnomnom/unfurl@latest` | same |
| anew | `go install github.com/tomnomnom/anew@latest` | same |
| amass | `brew install amass` | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| whois | included with macOS | `sudo apt install whois` |
| nmap | `brew install nmap` | `sudo apt install nmap` |

`asn_lookup` (Team Cymru), `ctlogs` (crt.sh), and `threat_intel` (URLhaus) are
built-in — they use direct sockets / `urllib` from the Python standard
library, not an external binary. `browser_probe` needs Playwright (see the
"Browser cloaking detection" install step above), not a CLI tool.

### 4. Verify Tool Installation

```bash
python app.py check-tools
```

### 5. Configure Environment

```bash
cp config/.env.example .env
# Edit .env with your program settings
```

---

## Configuration

All settings live in `.env`. Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `OUTPUT_DIRECTORY` | Run output base directory | `output` |
| `X_HACKERONE_RESEARCHER` | HackerOne researcher header value | — |
| `HTTP_CUSTOM_HEADERS` | Additional headers (JSON or `Header: val` pairs) | — |
| `RESEARCHER_ATTRIBUTION_HEADER` | Program-mandated attribution header, any name (`"Name: value"`, e.g. `X-HackerOne-Research: your_h1_handle`) — sent with every active request against the target itself, never to fixed third parties (OSV.dev, crt.sh, WHOIS, URLhaus) | — |
| `ATTRIBUTION_USER_AGENT` | Program-mandated User-Agent attribution (e.g. Bugcrowd: "Include the string 'bugcrowd' in your User-Agent") — appended in parentheses to the normal User-Agent for httpx/katana/nuclei/hakrawler/the internal HTTP client, and to browser_probe's mobile UA without replacing its device fingerprint. Use `RESEARCHER_ATTRIBUTION_HEADER` when a program wants a custom *header* (HackerOne's convention), this when it wants the *User-Agent* itself (Bugcrowd's convention) — set both if a program asks for both. Suppressed under `STRICT_OPSEC`, same as the header. | — |
| `SCOPE_FILE` | Domain/wildcard scope, plus `!domain/path-glob` path exclusions and whole-domain `!domain` exclusions — see `scope.example.txt` | — |
| `OWNED_DOMAINS` | Comma-separated domains you own — anything else triggers external-target-mode | — |
| `EXTERNAL_TARGET_MODE` | Force conservative defaults regardless of `OWNED_DOMAINS` (also: `run --external`) | `false` |
| `TIMEOUT` | Subprocess timeout (seconds) | `300` |
| `THREADS` | Default thread count | `50` |
| `HTTPX_THREADS` | httpx concurrency | `50` |
| `ENABLE_NAABU` | Enable port scanning | `false` |
| `ENABLE_PORT_VERIFY` | Verify Naabu results with bounded `nmap -sV` scans | `true` |
| `NAABU_CONFIRM_OPEN_PORTS` | Re-probe first-pass open ports before trusting them | `true` |
| `NAABU_TARPIT_CHECK` | Probe arbitrary canary ports before trusting any naabu result | `true` |
| `NAABU_TARPIT_OPEN_THRESHOLD` | Canary ports responding "open" before flagging `tarpit_suspected` | `2` |
| `ENABLE_WILDCARD_CHECK` | Probe random canary subdomains before trusting passive enum | `true` |
| `ENABLE_SOFT404_CHECK` | Probe a random nonexistent path before trusting HTTP 200 | `true` |
| `ENABLE_BROWSER_PROBE` | Compare httpx vs mobile WebKit destinations (opt-in, active) | `false` |
| `ENABLE_THREAT_INTEL` | Check live hosts in URLhaus (requires Auth-Key) | `false` |
| `URLHAUS_API_KEY` | Free key from https://auth.abuse.ch/ | — |
| `BROWSER_PROBE_MAX_HOSTS` | Maximum active browser navigations per run | `20` |
| `STRICT_OPSEC` | Fail closed and permit verified proxy-routed components only | `false` |
| `OUTBOUND_PROXY_URL` | Required HTTP(S) CONNECT proxy for strict mode | — |
| `ENABLE_NUCLEI` | Enable nuclei scanning | `false` |
| `ENABLE_CACHE` | Reuse a plugin's prior artifact for identical input + network mode | `true` |
| `MAX_DISCOVERY_DEPTH` | Follow-up depth (0 = seeds only) | `1` |
| `MAX_FOLLOWUP_INDICATORS` | Cap on extra in-scope collects | `50` |
| `ENABLE_FOLLOWUP_COLLECTION` | One bounded follow-up pass after the seed collect | `true` |
| `MAX_HTTP_PROBES` / `MAX_DNS_PROBES` | Follow-up HTTP/DNS budgets | `200` |
| `MAX_ENTITIES` / `MAX_RELATIONSHIPS` | Intelligence graph caps (fail closed, no dummy rows) | `5000` / `20000` |
| `CACHE_TTL_SECONDS` | How long cached artifacts remain valid (max 604800 / 7 days) | `86400` |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |

See `config/.env.example` for the full list.

---

## Usage

### Single Domain

```bash
python app.py run -d example.com
```

### Multiple Domains from File

```bash
# targets.txt — one domain per line, # for comments
python app.py run -f targets.txt
```

### Headless Mode (no TUI)

```bash
python app.py run -d example.com --no-ui
```

### List Registered Plugins

```bash
python app.py list-plugins
python app.py heads
```

`heads` prints every plugin as a Hydra head: name, whether it is currently
active, whether it is opt-in, and a one-line role.

### Verify Strict OPSEC Before a Real Scan

```bash
python app.py check-opsec
```

Checks proxy configuration, TCP reachability, and a live functional request
*through* the proxy; confirms httpx would actually route through it without
direct TLS/IP/CNAME side-probes; and lists which plugins would be blocked.
Exits non-zero on any failing check, so it's safe to gate a scan script on it:

```bash
python app.py check-opsec && python app.py run -d example.com --no-ui
```

Add `--skip-network` to check configuration only (no live requests), or
`--reveal-direct-ip` to also make one non-proxied request to a public IP-echo
service so you can visually confirm the proxied and direct IPs differ (opt-in,
since it deliberately reveals your real IP to that third-party service).

### Query persisted intelligence (no rescan)

```bash
python app.py investigate virusbarrier.xyz
python app.py graph virusbarrier.xyz
python app.py relationships virusbarrier.xyz
python app.py evidence virusbarrier.xyz
python app.py evidence <relationship_id>
python app.py certificates virusbarrier.xyz
python app.py indicators virusbarrier.xyz
python app.py diff virusbarrier.xyz
python app.py diff run_a run_b
```

`investigate` includes analyst-readable `explanations` for each relationship
(certificate fingerprint, SAN cardinality, cloud tenancy, named confidence,
`active_collection`). It never emits actor/owner/threat-group language.

### Custom Run ID (for reruns / comparison)

```bash
python app.py run -d example.com --run-id program_v1_baseline
```

---

## Pipeline Workflow

```
CLI: python app.py run -d <target>
      ↓
Authorization context (CollectionScope from seeds + SCOPE_FILE)
      ↓
WHOIS (authorized roots only)
      ↓
Subfinder (+ optional amass, assetfinder)
      ↓
Certificate Transparency (observe SANs; do not seed-resolve the whole set)
      ↓
Seed dnsx (authorized enum names, not the full CT merge)
      ↓
httpx (authorized inputs; OOS redirect landings are observations, not alive targets)
      ↓
Intelligence ingest → evidence → relationships → indicator queue
      ↓
authorize_active_indicator (ALLOW / DENY / UNKNOWN)
      ↓
Bounded follow-up DNS/HTTP into sidecar artifacts
      ↓
Deterministic authorized union → canonical resolved.txt / alive.txt
      ↓
SQLite persist (entities, observations, evidence, relationships, indicator lifecycle)
      ↓
Reports + CLI (investigate / relationships / evidence / diff)
```

Hard invariants:

- No active network collection without a concrete authorized indicator.
- No relationship without evidence.
- No `HIGH` correlation from a single weak signal (shared IP / ASN / CDN / favicon / body hash).
- `COLLECTED` is set only after collection succeeds. Crashes and empty follow-up leave seed artifacts intact.

Follow-up is bounded (`MAX_DISCOVERY_DEPTH`, `MAX_FOLLOWUP_INDICATORS`, `MAX_DNS_PROBES`, `MAX_HTTP_PROBES`, `MAX_RUNTIME`). There is no unrestricted recursive crawler.

---

## Intelligence & Historical Data

Every plugin's raw output still lands on disk as before (see Output
Structure below), but each artifact is also parsed by a per-tool `ToolParser`
(`core/parsers/registry.py`) into a canonical `Host` object (`core/assets.py`)
that carries full provenance — which tool observed a field, when, and at what
confidence. All `Host` objects for a run are merged in an in-memory
`HostRegistry` (`core/registry.py`), then persisted to a single SQLite
database shared across every run:

```
output/recon.db
```

Two layers share that file:

- **Host reporting view** (`hosts`, `http_services`, `ports`, `graph_nodes` / `graph_edges`) — what the HTML/Markdown reports render.
- **Intelligence store** (`intel_entities`, `intel_observations`, `intel_evidence`, `intel_relationships`, `intel_indicators`) — the source of truth for `investigate` / `graph` / `relationships` / `evidence`. The in-memory graph is a view over these rows, not a second database.

**Collect vs observe.** Active collectors (dnsx, httpx, naabu, crawlers, …) run only against indicators that pass `authorize_active_indicator`. Certificate Transparency SANs, plugin emissions, and parser hosts may still be **observed** when out of scope. Observation is not authorization. Indicator states are `DISCOVERED` → `ELIGIBLE` → `IN_FLIGHT` → `COLLECTED` or `FAILED` (or `NOT_ALLOWED` / `REJECTED`). An interrupted `IN_FLIGHT` row becomes `FAILED`, never `COLLECTED`.

**Correlation vs risk.** Named bands (`VERY_HIGH` / `HIGH` / `MEDIUM` / `LOW`) belong to evidence-backed **relationships**, not to Hosts. Host `risk_score` answers “how interesting is this surface?” Shared certificates do not bump risk. Shared cloud IPs are `shared_cloud_tenancy` (MEDIUM), not ownership. Host graph edges for CDN/ASN are `LOW` projections; they must not contradict intel relationships.

**Follow-up.** After seed collect, Hydra ingests artifacts into `IntelEngine`, verifies evidence for certificate-backed names, re-checks authorization and wildcard DNS, and runs bounded extra DNS/HTTP passes. Follow-up writes `resolved_followup_<n>.txt` / `alive_followup_<n>.txt` (and matching jsonl/json) then unions into canonical files. Seed snapshots (`resolved_seed.txt`, `alive_seed.txt`) remain intact if follow-up is empty or crashes. Depth default is 1.

After collection, `core/intel/engine.py` is the correlation truth. `core/intelligence/` still profiles hosts and scores risk for the reporting view. CLI / HTML / Markdown / `assets.json` serialize relationships through `core/intel/serialize.py`.

---

## Output Structure

Each run creates a timestamped directory under `output/`:

```
output/20250629_143022/
├── subdomains.txt      # Enumerated subdomains (may include observed OOS CT names)
├── authorized_dns_targets.txt  # Seed DNS input (enum+seeds, not the full CT merge)
├── resolved.txt        # Canonical authorized DNS union
├── resolved_seed.txt   # Seed DNS snapshot (immutable during follow-up)
├── resolved_followup_1.txt     # Follow-up DNS sidecar
├── alive.txt           # Canonical authorized HTTP union
├── alive_seed.txt      # Seed HTTP snapshot
├── alive_followup_1.txt
├── authorized_alive.txt        # Centrally authorized view for crawlers/scanners
├── httpx.json          # Canonical httpx JSON union
├── httpx.csv           # httpx CSV export
├── whois.jsonl         # Parsed WHOIS registration data
├── asn.jsonl           # Team Cymru ASN/IP ownership
├── ctlogs.jsonl        # Certificate Transparency (crt.sh) records
├── port_verify.jsonl   # nmap -sV verification of naabu findings
├── port_verify_raw/    # Raw nmap -sV stdout/stderr per host (audit trail)
├── tarpit_check.jsonl  # Canary port probe results (tarpit/portspoof detection)
├── wildcard_check.jsonl # Canary subdomain probe results (wildcard DNS detection)
├── soft404_check.jsonl # Canary path probe results (soft-404 / catch-all detection)
├── threat_intel.jsonl  # URLhaus reputation results (opt-in)
├── browser_probe.jsonl # WebKit cloaking probe results (opt-in)
├── browser_probe_raw/  # Rendered HTML per host (audit trail for cloaking)
├── metadata.json       # Aggregated metadata
├── summary.json        # Run statistics
└── summary.html        # Interactive HTML report (dark mode, search, filters)

output/
└── recon.db            # Cross-run SQLite store. Host tables plus intel_entities /
                         # observations / evidence / relationships / indicators.
                         # graph_nodes/graph_edges are a reporting view, not Neo4j.

reports/
├── overview.md         # Markdown overview
└── statistics.json   # Latest run statistics

logs/
└── recon.log           # Structured log file
```

---

## Project Architecture

```
.
├── app.py                  # CLI entry point
├── config/
│   ├── settings.py         # Typed settings from .env
│   └── .env.example
├── core/
│   ├── runner.py           # Async pipeline orchestrator
│   ├── tool_manager.py     # Plugin discovery & validation
│   ├── plugin_base.py      # Abstract plugin interface
│   ├── assets.py           # Canonical Host/Port/HttpService/Finding model
│   ├── registry.py         # HostRegistry — merges partial Hosts per run
│   ├── store.py            # SQLite persistence (recon.db) & queries
│   ├── provenance.py       # ProvenanceRecord — per-field discovery audit trail
│   ├── confidence.py       # Confidence scoring helpers
│   ├── normalizer.py       # Shared field/value normalization
│   ├── diff.py             # Cross-run historical diffing
│   ├── domain.py           # Domain target parsing/validation
│   ├── opsec_check.py      # `check-opsec` diagnostics
│   ├── parsers/
│   │   ├── registry.py     # One ToolParser per plugin → Host objects
│   │   └── crawlers.py     # Katana/Hakrawler/crawl-specific parsing
│   ├── dependencies/       # Phased external-tool discovery & validation
│   ├── intelligence/
│   │   ├── engine.py       # Host profiling/risk/clusters (reporting projection)
│   │   ├── profile.py
│   │   ├── risk.py
│   │   ├── clustering.py
│   │   └── graph.py        # Host visualization graph (CDN/ASN edges are LOW)
│   ├── intel/
│   │   ├── authorize.py    # ALLOW / DENY / UNKNOWN for every active probe
│   │   ├── engine.py       # Entities, observations, evidence, relationships
│   │   ├── followup.py     # Evidence-backed bounded follow-up planner
│   │   ├── artifacts.py    # Seed snapshots, sidecars, authorized union
│   │   ├── queue.py        # Indicator lifecycle
│   │   ├── serialize.py    # Canonical relationship objects for all reporters
│   │   └── cli.py          # investigate / relationships / evidence / diff
│   ├── reporter.py         # Console/Markdown/HTML — consumes serialize_relationship
│   ├── models.py           # Dataclasses & enums
│   ├── logger.py           # Structured logging
│   └── exceptions.py
├── modules/                # Tool plugins (one file per tool)
│   ├── _base.py
│   ├── subfinder.py
│   ├── dnsx.py
│   ├── httpx.py
│   ├── whois.py, asn_lookup.py, ctlogs.py     # Infrastructure intelligence
│   ├── port_verify.py, threat_intel.py        # Verification & reputation
│   ├── browser_probe.py                       # Cloaking detection (opt-in)
│   └── ...
├── ui/
│   ├── dashboard.py        # Rich live TUI
│   ├── tables.py           # Result tables
│   ├── progress.py         # Progress tracking
│   ├── dependency_report.py # `check-tools` rendering
│   └── opsec_report.py     # `check-opsec` rendering
├── utils/
│   ├── subprocess.py       # Secure async subprocess
│   ├── files.py            # File I/O helpers
│   ├── validators.py       # Domain & path validation
│   ├── security.py         # Path confinement, log redaction, atomic writes
│   └── network.py          # Proxy-aware urllib wrapper (strict OPSEC)
├── output/
├── logs/
└── reports/
```

---

## Extending the Framework

Adding a recon tool is not “one new file”. You typically need:

1. `modules/my_tool.py` with declarative `produces`, `capability`, `active_collection`, `strict_opsec_allowed`
2. `enable_my_tool` / path in `config/settings.py` and `config/.env.example`
3. Import in `modules/__init__.py` (auto-registers via `__init_subclass__`)
4. A parser in `core/parsers/registry.py` if the artifact is not already covered
5. Runner stage placement is derived from `capability` for subdomain / URL / DNS / post-HTTP groups; a brand-new stage still needs an explicit call in `core/runner.py`

Subprocess isolation is unchanged (`no shell=True`). Plugins may also attach
`PluginResult.data["intel"]` (`StructuredEmission`) so the engine can ingest
entities without a new parser class. Artifact files remain the production path.

```python
# modules/my_tool.py
from pathlib import Path
from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin

class MyToolPlugin(BaseToolPlugin):
    name = "my_tool"
    display_name = "My Tool"
    required = False
    stage_order = 45
    produces = ("domains",)
    followup_kinds = ("domains",)
    capability = "enumerate_domains"
    active_collection = False
    strict_opsec_allowed = False

    install_hint_macos = "brew install my_tool"
    install_hint_linux = "go install example.com/my_tool@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_my_tool

    def get_binary_path(self) -> Path:
        return self.settings.my_tool_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "my_tool.txt")
        args = [str(self.get_binary_path()), "-l", str(input_path)]
        return await self._execute(context, args, output_path)
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Subprocess over Python wrappers | Avoids dependency on unmaintained wrappers; uses native tool CLIs directly |
| Plugin registry via `__init_subclass__` | Zero-config registration; new module = new plugin |
| Async subprocess with `asyncio` | Non-blocking I/O for concurrent optional tools |
| Rich TUI over web UI | Faster iteration, works over SSH, no extra ports |
| Per-run output directories | Easy reruns, diffing, and historical comparison |
| `.env` for all configuration | Program-agnostic; swap config per engagement |
| Mandatory vs optional tools | Core pipeline always works; extras are opt-in |
| nuclei disabled by default | Prevents accidental aggressive scanning |
| No auto-install of tools | Respects user environment; provides hints only |

---

## Security Considerations

- All subprocess calls use `asyncio.create_subprocess_exec` — **never** `shell=True`
- Domain input validated against RFC 1123 pattern; shell metacharacters rejected
- Paths resolved and optionally constrained to base directories
- Custom headers passed as discrete `-H` arguments, not interpolated into shells
- Intended for **authorized** reconnaissance only — respect program scope and rules
- Hydra never launches an automatic `nmap -p-` scan. Port verification is limited
  to Naabu observations and bounded by `PORT_VERIFY_MAX_HOSTS` and
  `PORT_VERIFY_MAX_PORTS_PER_HOST`.
- **Tarpit/portspoof detection**: many shared-hosting providers run an anti-
  reconnaissance defense that fabricates "open" TCP handshakes for arbitrary,
  unassigned ports to poison scan results. Before trusting any Naabu output for
  a host, Hydra probes a handful of randomly-chosen high ports (20000-60000)
  that have no legitimate service association. If `NAABU_TARPIT_OPEN_THRESHOLD`
  or more of them come back "open," the host is flagged `tarpit_suspected: true`
  — its real port scan is skipped, its raw naabu/port_verify data is kept in
  `assets.json` for audit only, and confidence/risk scoring exclude that data
  entirely. Reports surface this under an explicit "⚠ Tarpit/Portspoof
  Suspected" warning instead of listing individual ports as findings.
- **Wildcard DNS / soft-404 canaries**: before trusting passively enumerated
  subdomains or HTTP 200 as "exists", Hydra probes random improbable
  subdomains (via dnsx) and a random nonexistent path on each live host. Hits
  produce informational Findings (`wildcard-dns-detected`, `soft-404-detected`)
  and demote confidence / warn in reports — data is kept, not discarded.
- **Browser Probe executes potentially malicious JavaScript and follows hostile
  redirects. Run it only inside a disposable, network-restricted container or VM,
  never on the analyst's primary workstation.** Headless mode and the browser
  sandbox do not provide anonymity or complete containment. Install with
  `pip install -r requirements-optional.txt && playwright install webkit`.
- **Parameter Discovery (`ENABLE_PARAM_FUZZ`) and Cloud Bucket Enumeration
  (`ENABLE_CLOUD_BUCKET_ENUM`) are active probes** — they send HTTP requests
  against the target (or brand-derived S3/GCS/Azure URLs). Both are **disabled
  by default**. Enable only when you own the asset or have explicit authorization
  from a bug-bounty program. They detect parameter influence/reflection and
  bucket existence/listing only — **no exploit payloads** (no SQLi/XSS/path
  traversal, no object download beyond observing a public list). Defaults use
  conservative delays (`PARAM_FUZZ_DELAY_MS=200`, `CLOUD_BUCKET_ENUM_DELAY_MS=150`).
  S3/Azure use virtual-hosted URLs (`{bucket}.s3.amazonaws.com` /
  `{account}.blob.core.windows.net`); if canary calibration hits DNS resolution
  failures, that is usually a network/resolver limit (GCS uses a fixed host and
  often still works) — re-run from a network with normal public DNS.

### Network boundary — what is actually enforced

Full detail, exact code citations, and how each claim was verified:
[`docs/FINAL_SECURITY_AUDIT.md`](docs/FINAL_SECURITY_AUDIT.md),
[`docs/FINAL_NETWORK_BOUNDARY_AUDIT.md`](docs/FINAL_NETWORK_BOUNDARY_AUDIT.md), and
[`docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md`](docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md). Summary:

**Guaranteed by Hydra** (application-level, verified against real binaries/browsers/local
servers, not mocks): no active-collection plugin can make a network/subprocess call without an
attached `CollectionScope` (all 19 active-collection plugins are covered by one test). A single
mechanism, `ScopeEnforcingProxy` (`core/collection/crawler_proxy.py`), is the connection-level
enforcement point for six components — katana, hakrawler, nuclei, **httpx** (both the seed probe
and every redirect hop), **browser_probe** (WebKit's own network stack via Playwright's
launch-time `proxy=`, not just JS-visible `route()` interception), and the urllib-based
`soft404_check`/`param_fuzz`/`cloud_bucket_enum` — so a tool that discovers or is redirected to a
destination on its own still cannot reach an out-of-scope host. Beyond the hostname check, every
one of these resolves the destination and validates the actual IP
(`core/collection/ssrf.py`) against loopback/RFC1918/CGNAT/link-local/metadata/multicast/reserved
ranges (IPv4 and IPv6, including IPv4-mapped IPv6 literals) before connecting to the exact
resolved address — not a second, independent resolution at connect time, closing the DNS-rebinding/
TOCTOU window a naive "authorize-then-connect" design would leave open. An operator-configured
external OPSEC proxy (`OUTBOUND_PROXY_URL`) is never talked to directly by any of these six
components — `ScopeEnforcingProxy` chains to it internally, so Hydra's own authorization always
runs before anything is forwarded to it. `core/collection/gateway.py:CollectionGateway` — whose
`http_get()` only accepts a sealed `AuthorizedCollectionTarget`, not a bare URL string, checked at
runtime — is the structural (not just conventional) entry point for one plugin so far
(`soft404_check`); `AuthorizedCollectionTarget`'s own constructor unconditionally rejects direct
construction (including via `dataclasses.replace()`), closing a real forgery gap a plain frozen
dataclass never closed. A static guard (`tests/test_no_bypass_network_primitives.py`) fails the
test suite if a future built-in collector imports a raw network primitive without an explicit,
justified exception.

**Guaranteed only when the tool itself supports it, or only past a boundary Hydra doesn't
control**: the crawler proxy authorizes by destination host, not by TLS content — `CONNECT`
tunnels are never decrypted or inspected, only the tunnel target is checked. nuclei's interactsh
OOB channel is disabled by default (`NUCLEI_ENABLE_INTERACTSH=false`) because it legitimately
needs to contact third-party ProjectDiscovery infrastructure that per-target scope confinement
cannot distinguish from an unauthorized destination. Once an authorized request is chained through
an external `OUTBOUND_PROXY_URL`, that proxy resolves and connects to the target from its own
network location — Hydra's destination-IP pinning does not extend past that hop (Hydra's own
socket never touches the target directly in this configuration either way). `soft404_check`,
`param_fuzz`, `cloud_bucket_enum`, `httpx`, and `browser_probe` are all structurally confined
through `CollectionGateway`/`ScopeEnforcingProxy` — no bare URL string reaches the underlying HTTP
primitive for any of them. WHOIS registration lookups are a native Python TCP:43 client
(`core/collection/whois_client.py`), not the system `whois` binary — every hop of the IANA →
registry → registrar referral chain has its resolved IP validated against the same SSRF policy as
HTTP targets before Hydra connects to it, and a blocked hop stops the chain there rather than being
followed blindly.

**Cannot be proxy-confined at all — authorization-only, not connection-pinned**: `naabu` and
`port_verify` (nmap) perform raw TCP/SYN operations that cannot be routed through an HTTP forward
proxy; their confinement is authorization-only (the target must be in scope before the scan
starts), not connection-pinned the way HTTP/WHOIS targets are. A real destination-IP boundary for
these two would require OS-level enforcement (a network namespace or firewall rule), which is out
of scope for Hydra's own application-level confinement. `NAABU_TARPIT_CHECK` and
`NAABU_CONFIRM_OPEN_PORTS` are result-integrity controls (is this "open" port real, not
tarpit-fabricated) — they do not change this boundary.

**Requires external network isolation** (outside anything Hydra's own code can enforce): a tool
that ignores its own configured `-proxy` — a bug, or a raw-socket code path bypassing its
configured HTTP transport — is invisible to the confinement proxy, demonstrated concretely with a
real subprocess in `tests/test_untrusted_network_bypass.py`, not merely asserted. Nothing at the
OS/process level stops this; closing it needs a network-namespaced or firewalled sandbox around
the whole Hydra process, which is an operational choice, not a Hydra feature. DNS resolution is
not proxied by `STRICT_OPSEC` either — see `check-opsec`'s DNS-leak check, which reports this
honestly as informational, not a guarantee. **Hydra does not claim universal process-level or
OS-level network confinement**, and no documentation here should be read as claiming it.

### Strict OPSEC mode

Set both values before scanning:

```bash
STRICT_OPSEC=true
OUTBOUND_PROXY_URL=http://user:password@proxy.example:8080
```

Strict mode fails before scanning if no proxy is configured. It suppresses
custom researcher headers, uses a generic User-Agent, routes crt.sh, URLhaus,
httpx, and Playwright through the proxy, and blocks raw DNS/TCP tools or plugins
whose proxy behavior is not verified. HTTP hostnames are resolved by the proxy.
Outputs, databases, and logs are owner-only, and provenance omits local absolute
paths. Cached plugin artifacts are also scoped to the active network mode, so a
result fetched via a direct (non-proxied) run can never be replayed as a
"cache hit" for a later strict-OPSEC/proxied run of the same plugin, or vice versa.

This is exposure reduction—not anonymity. The proxy, ISP, passive intelligence
providers, target infrastructure, browser fingerprinting, and endpoint
compromise can still correlate activity. Use a disposable VM/container,
dedicated credentials, a trusted egress proxy, and network-layer firewall rules
that permit only the proxy. Hydra cannot enforce host firewall policy itself.

---

## Suggested Improvements

- [x] SQLite backend for cross-run querying and deduplication (`core/store.py`, `output/recon.db`)
- [x] Historical diffing — overlapping targets, field-level changes (`core/diff.py`, `python app.py diff`)
- [x] Integration with Amass as an additional plugin (`modules/amass.py`)
- [x] Export to JSONL for downstream tooling — intelligence plugins write `.jsonl`
- [x] Scope file authorization (`SCOPE_FILE`; out-of-scope names are observed, not probed)
- [ ] Resume interrupted runs from last completed stage
- [ ] Webhook notifications on completion (Slack, Discord) — optional webhook exists for diffs only
- [ ] Config profiles (`--profile h1-program-name`)
- [ ] massdns integration for high-volume DNS resolution
- [ ] Completely separate evidence model for actor/owner attribution (intentionally absent)

---

## License

For authorized security research only. Use responsibly and within program scope.
