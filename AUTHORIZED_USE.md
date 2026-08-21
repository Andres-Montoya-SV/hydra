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
