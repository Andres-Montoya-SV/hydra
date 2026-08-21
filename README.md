# Hydra — Attack Surface Intelligence Framework

[![CI](https://github.com/Andres-Montoya-SV/hydra/actions/workflows/ci.yml/badge.svg)](https://github.com/Andres-Montoya-SV/hydra/actions/workflows/ci.yml)

Hydra is an Attack Surface Intelligence Framework that transforms reconnaissance data into actionable intelligence for security researchers. Multiple recon "heads" (plugins) operate in a coordinated pipeline.

Works on **macOS**, **Ubuntu**, **Debian**, and **Kali Linux**.

**Authorization:** only scan systems you own or have explicit written permission to test. See [AUTHORIZED_USE.md](AUTHORIZED_USE.md). Licensed under [MIT](LICENSE).

---

## Features

- **Plugin architecture** — each recon tool is an isolated module; add new tools without touching core code
- **Mandatory pipeline** — subfinder → dedupe → dnsx → httpx
- **Infrastructure intelligence** — WHOIS, Certificate Transparency, ASN ownership, DNS, HTTP, and port provenance
- **Optional plugins** — URLhaus reputation, WebKit cloaking detection, amass, naabu, katana, hakrawler, gau, waybackurls, nuclei, assetfinder, unfurl, anew
- **Canonical intelligence model** — every tool's output is parsed into a single `Host` object (`core/assets.py`) with full provenance (which tool found it, when, at what confidence) instead of siloed per-tool files
- **SQLite intelligence store** (`core/store.py`, `output/recon.db`) — hosts, ports, HTTP services, DNS records, findings, and run history persist across scans for querying and cross-run comparison
- **Intelligence engine** (`core/intelligence/`) — automatic host profiling/categorization, confidence scoring, risk scoring (Critical/High/Medium/Low/Info), clustering, and an infrastructure graph (ASN/CDN/provider/cert/technology relationships)
- **Historical diffing** (`core/diff.py`) — each run is automatically compared against the previous run for the same target(s); new/removed hosts, ports, and technologies surface as warnings
- **Interactive HTML reports** — dark/light theme toggle, live search, risk-level filtering, sortable host tables
- **Async execution** — concurrent optional tools, non-blocking subprocess I/O
- **Rich TUI** — live progress, tool status, statistics, logs, and results tables
- **Structured logging** — console + file, configurable levels
- **Secure subprocess** — no `shell=True`, input validation, path sanitization
- **Fail-closed OPSEC mode** (`STRICT_OPSEC`) — proxy-only egress, header suppression, and a `check-opsec` pre-flight diagnostic command
- **Bug bounty headers** — configurable `X-HackerOne-Researcher` and custom HTTP headers via `.env`
- **Multiple outputs** — JSON, CSV, HTML, Markdown reports

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
| `ENABLE_BROWSER_PROBE` | Compare httpx against mobile WebKit redirects | `false` |
| `BROWSER_PROBE_MAX_HOSTS` | Maximum active browser navigations per run | `20` |
| `STRICT_OPSEC` | Fail closed and permit verified proxy-routed components only | `false` |
| `OUTBOUND_PROXY_URL` | Required HTTP(S) CONNECT proxy for strict mode | — |
| `ENABLE_NUCLEI` | Enable nuclei scanning | `false` |
| `ENABLE_CACHE` | Reuse a plugin's prior artifact for identical input + network mode | `true` |
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

### Custom Run ID (for reruns / comparison)

```bash
python app.py run -d example.com --run-id program_v1_baseline
```

---

## Pipeline Workflow

```
Validate Input
      ↓
WHOIS registration intelligence
      ↓
Subfinder + Certificate Transparency (+ optional: amass, assetfinder)
      ↓
Deduplicate
      ↓
dnsx → Team Cymru ASN ownership (+ optional: naabu)
      ↓
Optional nmap service verification for Naabu observations
      ↓
httpx
      ↓
Optional URLhaus host reputation
      ↓
Optional: katana, hakrawler, unfurl, nuclei
      ↓
Optional active WebKit cloaking probe
      ↓
Collect Metadata
      ↓
Generate Reports
      ↓
Display Results
```

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
output/recon.db   # hosts, ports, http_services, dns_records, findings, runs, provenance
```

After collection, the intelligence engine (`core/intelligence/`) runs over
every host and:

- assigns a **category** (e.g. admin interface, API, staging, forgotten
  subdomain) and a **priority** (`critical` / `high` / `medium` / `low` /
  `info`) with a confidence score (`profile.py`, `risk.py`)
- **clusters** related hosts by shared certificate, ASN, or technology
  fingerprint (`clustering.py`)
- builds an **infrastructure graph** of ASN/CDN/provider/technology/cert
  relationships (`graph.py`)
- **diffs** the current run against the most recent prior run for the same
  target(s) (`core/diff.py`), surfacing new/removed hosts, ports, and
  technologies as warnings in the report — no flags needed, this happens
  automatically whenever history exists for a target

Reports (console, Markdown, HTML) read from this store rather than re-parsing
raw tool files, so "Top assets to investigate" and risk summaries reflect the
merged, cross-tool picture rather than any single tool's view.

---

## Output Structure

Each run creates a timestamped directory under `output/`:

```
output/20250629_143022/
├── subdomains.txt      # Enumerated subdomains
├── resolved.txt        # DNS-resolved hosts
├── alive.txt           # Live HTTP URLs
├── httpx.json          # Full httpx JSON output
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
└── recon.db            # Cross-run SQLite intelligence store (hosts, ports,
                         # HTTP services, DNS records, findings, run history)

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
│   │   ├── engine.py       # Orchestrates the post-collection intelligence pipeline
│   │   ├── profile.py      # Host categorization + priority assignment
│   │   ├── risk.py         # Risk scoring
│   │   ├── clustering.py   # Certificate/ASN/technology clustering
│   │   └── graph.py        # Infrastructure relationship graph
│   ├── reporter.py         # Console/Markdown/HTML report generation
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

Adding a new recon tool requires **only one new file** in `modules/`:

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
    stage_order = 45  # Controls pipeline position

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

Then:

1. Add `enable_my_tool` and `my_tool_path` to `config/settings.py` and `.env.example`
2. Import the module in `modules/__init__.py`

The plugin auto-registers via `__init_subclass__`. No core changes needed.

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
- [x] Historical diffing — automatic, per target, against the most recent prior run (`core/diff.py`)
- [x] Integration with Amass as an additional plugin (`modules/amass.py`)
- [x] Export to JSONL for downstream tooling — every new intelligence plugin (WHOIS, ASN, CT logs, port verify, threat intel, browser probe) writes `.jsonl`
- [ ] Resume interrupted runs from last completed stage
- [ ] Standalone `diff`/`export` CLI subcommands (diffing/export currently happen automatically or via `AssetStore` API, not a dedicated CLI flag)
- [ ] Scope file integration (in-scope / out-of-scope filtering)
- [ ] Webhook notifications on completion (Slack, Discord)
- [ ] Config profiles (`--profile h1-program-name`)
- [ ] massdns integration for high-volume DNS resolution

---

## License

For authorized security research only. Use responsibly and within program scope.
