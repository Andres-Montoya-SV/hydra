# Authorized Use

Hydra is an attack-surface intelligence framework for security researchers.
**You may only run it against systems you own or have explicit written
authorization to test** (for example a bug-bounty program whose scope
covers the target).

Unauthorized scanning, probing, or enumeration of third-party systems is
illegal in most jurisdictions. The authors accept no responsibility for
misuse.

## Scope file (fail-closed)

Set `SCOPE_FILE` to a text file listing authorized root domains (one per
line; optional `*.example.com` wildcards). When configured, Hydra **refuses
to start** if any CLI target is outside that list. Copy `scope.example.txt`
to `scope.txt` (gitignored) and edit it for your program.

```bash
SCOPE_FILE=scope.txt python app.py run -d www.metaversejustice.com
```

Without `SCOPE_FILE`, Hydra does not enforce program scope — that remains
your responsibility.

A `SCOPE_FILE` line prefixed with `!` excludes a specific path from an
otherwise-authorized domain/wildcard, e.g. a program that authorizes
`*.example.com` but carves out `/legal/whistleblowing` as explicitly out of
scope:

```
*.example.com
!example.com/legal/whistleblowing
```

An exclusion always wins over a positive domain/wildcard match. See
`scope.example.txt` for a full example.

## Researcher attribution header (several programs require this)

Several bug-bounty programs require every testing request to carry an
identifying header, so their traffic-classification systems can tell
authorized researcher activity from a real attacker — e.g. HackerOne's
`X-HackerOne-Research: <your handle>`. **Set this before running anything
active against a formal program**, not after:

```bash
RESEARCHER_ATTRIBUTION_HEADER="X-HackerOne-Research: your_h1_handle" python app.py run -d target.example
```

This is sent on every active request Hydra makes *against the target
itself* (httpx, browser_probe, param_fuzz, cloud_bucket_enum, soft404_check,
katana/nuclei via `-H`) — never to a fixed third party (OSV.dev, crt.sh,
WHOIS, URLhaus), where a researcher-identifying header has no meaning.
Suppressed entirely under `STRICT_OPSEC`, same as every other identifying
header, since sending it would defeat the purpose of non-attributable
probing.

## External targets (third-party programs) default to a conservative posture

Declare the domains you actually own in `OWNED_DOMAINS` (comma-separated).
Any run targeting a domain outside that list — most importantly a
third-party program on someone else's infrastructure, e.g. a financial
institution's bug-bounty scope — automatically:

- Lowers `RATE_LIMIT` (naabu), `PARAM_FUZZ_DELAY_MS`, and
  `CLOUD_BUCKET_ENUM_DELAY_MS` to conservative values (unless you already
  set your own, which is never silently overridden).
- Requires an explicit `[y/N]` confirmation before running
  `ENABLE_PARAM_FUZZ`, `ENABLE_CLOUD_BUCKET_ENUM`, or `ENABLE_BROWSER_PROBE`
  — even if they're already `true` in `.env`. Declining disables just those
  modules for that run; discovery/observation still proceeds. A
  non-interactive invocation (no terminal attached) declines automatically
  rather than hanging or silently running active modules.
- Prints a scope summary (authorized domains/wildcards, path exclusions,
  whether the researcher attribution header above is configured) before
  anything active starts.

No `OWNED_DOMAINS` set at all means every run is treated as external — the
setting exists to name what's exempt, not the other way around. Force this
posture regardless of `OWNED_DOMAINS` with `run --external`.

## Active / intrusive modules

These plugins send live HTTP(S) requests to the target or to brand-derived
cloud endpoints. They are **disabled by default** unless noted. Enable them
only with ownership or explicit authorization.

| Module | Setting | What it does | What it does **not** do |
|--------|---------|--------------|-------------------------|
| Parameter Discovery | `ENABLE_PARAM_FUZZ=true` | GET requests with an inert canary query value | No SQLi/XSS/path-traversal payloads |
| Cloud Bucket Enumeration | `ENABLE_CLOUD_BUCKET_ENUM=true` | Unauthenticated GETs to S3/GCS/Azure names derived from the brand | No object download beyond observing a public listing; no writes |
| Browser Probe | `ENABLE_BROWSER_PROBE=true` | Headless WebKit visit (executes page JavaScript) | Run only in a disposable, network-restricted VM/container |
| Security Headers | `ENABLE_SECURITY_HEADERS` (on by default) | Inspects response headers already collected by httpx | No extra attack traffic |
| CVE Correlation | `ENABLE_VULN_MATCH` (on by default) | Queries OSV.dev (and optional WPScan) for known versions | Reports source identifiers only; does not exploit |

Nuclei (`ENABLE_NUCLEI`) is a separate scanner with its own template
severity — treat it as an authorized active scan.

## Residual risk

Even with `STRICT_OPSEC` and a proxy, the proxy operator, ISP, passive
intelligence providers, target infrastructure, and endpoint compromise can
still correlate activity. Hydra cannot enforce host firewall policy.
See `README.md` § Strict OPSEC mode and `SECURITY.md`.
