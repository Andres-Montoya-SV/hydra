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

A `SCOPE_FILE` line prefixed with `!` excludes a path **and everything
beneath it** from an otherwise-authorized domain/wildcard, e.g. a program
that authorizes `*.example.com` but carves out the whole
`/legal/whistleblowing` subtree as explicitly out of scope:

```
*.example.com
!example.com/legal/whistleblowing
```

This excludes `/legal/whistleblowing`, `/legal/whistleblowing/report`, and
any deeper subpath — not just that exact URL. A different path that merely
starts with the same text (`/legal/whistleblowing-info`) is a distinct path
segment and is **not** excluded.

An exclusion always wins over a positive domain/wildcard match. See
`scope.example.txt` for a full example.

A `!domain` line with **no path at all** excludes that domain entirely
(and any further subdomain of it) from every collection path — not just a
URL. Real case: Linktree authorizes `*.linktr.ee` but excludes its own
`community.linktr.ee` subdomain in full:

```
*.linktr.ee
!community.linktr.ee
```

Unlike the path-specific exclusion above, this also blocks a bare-hostname
indicator with no URL at all — DNS resolution, a CT-log-observed name, a
plain line in `resolved.txt` — since there is no path to reason about for a
whole-domain exclusion in the first place.

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

## User-Agent attribution (Bugcrowd-style programs require this)

Some programs identify authorized researcher traffic through the
**User-Agent** instead of a custom header — Bugcrowd's own published
convention (quoting two real program briefs): *"Include the string
'bugcrowd' in your User-Agent, or add 'bugcrowd' to one of the fields of
any form post not requiring account information."* Use
`ATTRIBUTION_USER_AGENT` for this — it is generic, not hardcoded to
"bugcrowd", since a future program may require its own marker the same way:

```bash
ATTRIBUTION_USER_AGENT="bugcrowd; your_handle" python app.py run -d target.example
```

**Use the header for HackerOne-style programs, the User-Agent for
Bugcrowd-style programs, and set both if a program's brief asks for both**
— they are independent and do not conflict.

Appended in parentheses to the normal User-Agent — `hydra/1.0 (bugcrowd;
your_handle)` — for httpx, katana, nuclei, hakrawler (all four set it via
their custom-header flag; none has a dedicated User-Agent flag — verified
against each installed binary's own `-h` output, not assumed), and the
internal HTTP client used by `param_fuzz`/`cloud_bucket_enum`/
`soft404_check`. For `browser_probe`, it is appended to the existing mobile
Safari/iPhone User-Agent it already sends for cloaking-detection
fingerprinting — **appended, never substituted**, since replacing that
fingerprint would break the cloaking comparison against httpx. `naabu` does
not apply (raw TCP port scan, no HTTP layer). Suppressed entirely under
`STRICT_OPSEC`, same reasoning and same behavior as the header above.

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
