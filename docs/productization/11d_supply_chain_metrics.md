# Product Phase 11d — Supply Chain and Metrics

Branch: `productization/11d-supply-chain-metrics`. Base: `main` @ `3188df1`
(after PR #116, Phase 11c).

Decisions (2026-10-01):

- **Scan policy: gate, fix and allowlist.** CI fails on Critical or High
  findings that have a fix. Fixable findings that can't be fixed right
  now go into a reviewed allowlist, each entry with a reason and an
  expiry date.
- **Metrics:** `/metrics` needs an **operator API key** (as for the other
  admin surfaces, 11b).

## SBOM and image scan (CI `docker` job)

After the image is built:

1. **SBOM.** Syft writes a CycloneDX SBOM of the whole image (OS packages,
   Python packages, and the Go modules compiled into each recon binary).
2. **Scan.** Grype matches the SBOM against current advisories.
3. **Gate** (`scripts/vuln_gate.py`) fails when either:
   - a **Critical/High finding with a fix** isn't covered by an entry in
     `security/vulnerability-allowlist.json`; or
   - an entry has **expired**.
4. **Artifacts.** The SBOM and the full scan report are kept as a build
   artifact (`hydra-image-sbom-and-scan`).

Syft and Grype run from their official images, pinned by digest. Trivy's
current release was a day old, so it was not chosen. Medium and lower
findings, and findings without a fix, are counted in the gate's report
but don't fail the build.

**The allowlist.** Each entry matches exactly one finding (vulnerability,
package, location) and carries a reason and an `expires` date. Entries
that no longer match anything are reported as stale (not fatal) so they
can be removed. A test checks that every entry has a reason and that
there are no duplicates.

### What the first scan found (2026-10-01)

The local image had been built from cached layers. It showed 9 Critical
and 57 High fixable findings.

- **Debian packages** (OpenSSL 3.5.7: 4 CVEs; pcre2): **fixed by
  rebuilding**. The final stage already runs `apt-get upgrade`, so a
  fresh build (as CI's always is) picks up the patched packages.
- **Go modules inside the pinned recon binaries** (52 findings):
  **allowlisted until 2026-11-15**.
  - The tools: naabu, katana, hakrawler, nuclei, dnsx, subfinder, httpx.
  - The modules: old `x/crypto`, `x/net` and `x/text`, plus `pgx`, `grpc`,
    `go-git`, `xpath`.
  - These binaries are pinned and qualified in Phase 09, so fixing them
    means newer upstream releases or rebuilds with bumped modules, plus
    re-qualification. That is the **recon-tool dependency refresh**,
    which must land before the entries expire.
- **CPython 3.12** (1 finding): the scanner's only fix is 3.14.0b1.
  Allowlisted until a 3.12 patch release or a newer base image.

A fresh build passes the gate: 53 allowed, 0 blocking. Removing any one
entry fails it on exactly that finding.

The full report also lists 30 Critical and 326 High findings that **have
no fix yet**, mostly Debian packages. They are visible in every CI
artifact and don't fail the build.

**Note:** the advisory database changes daily, so a new fixable
Critical/High can turn CI red on an unrelated PR. That is the point of a
gate. The fix is to patch, or to add a reviewed, dated entry.

## Metrics (`GET /metrics`, `api/metrics.py`)

Prometheus text format, behind an operator's API key (everyone else gets
404). Scrapes aren't written to the security audit log: they arrive every
15 seconds or so and carry aggregates only.

| Metric | What |
|---|---|
| `hydra_http_requests_total{method,route,status}` | requests handled |
| `hydra_http_request_duration_seconds{method,route}` | latency histogram |
| `hydra_control_db_up` | whether the control database answered (0 is reported, not raised) |
| `hydra_scans{status}` | the scan queue and history |
| `hydra_integration_deliveries{status}` | the outbox, including `dead` |
| `hydra_pending_tenant_deletions{kind}` | scheduled deletions (11c) |
| `hydra_loop_seconds_since_alive{loop}` | each background loop's heartbeat age |
| `hydra_db_pool{stat}` | Postgres pool counters (size, available, requests waiting...) |

- **Bounded labels.** `route` is the matched route **template**, never the
  raw path. Unmatched paths share `unmatched`, so ids never become label
  values and probing random URLs can't grow the series count. A test
  checks this.
- **Per process.** Counters are per process; scrape each API process, or
  sum in Prometheus.
- **Scrape config:** send the operator key as an `X-API-Key` header
  (`http_headers` in the scrape config).

New dependency: `prometheus-client==0.26.0` (pip-audit: no known
vulnerabilities).

## Tests

- **`tests/test_vuln_gate.py`:**
  - fixable Critical/High blocks;
  - unfixed findings and Medium never block;
  - one entry covers exactly one finding;
  - an expired entry blocks again;
  - a stale entry is reported, not fatal;
  - an entry needs a reason;
  - CLI exit codes;
  - the repository allowlist is well-formed.
- **`tests/test_metrics.py`:**
  - operator-only access;
  - counting by route template, with no raw ids in labels;
  - the state gauges;
  - an unreachable database reported as `hydra_control_db_up 0`.
