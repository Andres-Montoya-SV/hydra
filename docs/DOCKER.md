# Running Hydra in Docker

This document covers building and running Hydra as a container: what's
inside the image, how persistent state and secrets are kept out of it, the
exact commands for a real run, and — the part that actually matters for a
tool built around network confinement — the verification that Docker's own
networking does not open a hole in `ScopeEnforcingProxy`/`CollectionGateway`.

Scope of this document: containerization only. Deploying that container to
EC2/a VM is a separate, later piece of work and is not covered here.

## What's in the image

A two-stage build (`Dockerfile`):

1. **`go-builder`** (`golang:1.25.14-bookworm`) compiles the Go-based
   tools Hydra can orchestrate, each pinned to an explicit released
   version — never `@latest`:

   | Tool | Version | Module |
   |------|---------|--------|
   | subfinder | v2.16.0 | `github.com/projectdiscovery/subfinder/v2` |
   | dnsx | v1.3.1 | `github.com/projectdiscovery/dnsx` |
   | httpx | v1.12.0 | `github.com/projectdiscovery/httpx` |
   | naabu | v2.6.1 | `github.com/projectdiscovery/naabu/v2` |
   | katana | v1.7.0 | `github.com/projectdiscovery/katana` |
   | nuclei | v3.11.1 | `github.com/projectdiscovery/nuclei/v3` |
   | hakrawler | 2.1 | `github.com/hakluke/hakrawler` |

   These are the 7 tools this task named. Hydra's plugin system also
   supports `amass`, `gau`, `waybackurls`, `assetfinder`, `unfurl`, and
   `anew` (all disabled by default) — left out of the image deliberately
   to hold the size down (see **Image size**, below); add any of them with
   the exact same `go install <module>@<pinned version>` pattern in the
   `go-builder` stage if you need one.

   Every version above was test-built (`go install ...@<version>`)
   before being pinned here, not guessed. One tool needed a workaround:
   `tomnomnom/anew`'s only release past `v0.1.1` is literally tagged
   `v0.2` (not `v0.2.0`), which is not a valid Go-modules semver string —
   `go install` rejects it outright. If you add it back, pin it by the
   commit that tag points to instead (`go install
   github.com/tomnomnom/anew@26ebc8ce1f0bdbaaee2930ea7ab191ed0c0da261`),
   which resolves correctly and is exactly as reproducible as a tag.

2. **`final`** (`python:3.11-slim-bookworm`) — the runtime:
   - The 7 Go binaries above, copied from the builder stage.
   - `nmap`, `whois`, `jq` (apt) — the non-Go tools Hydra's plugins call.
   - Playwright, pinned to `1.62.0` (matching `requirements-optional.txt`
     exactly), with **only WebKit** installed —
     `modules/browser_probe.py`'s one supported engine. Chromium and
     Firefox are never downloaded.
   - The full Python dependency set: `requirements.txt` +
     `requirements-dev.txt` + `requirements-optional.txt` — dev tooling
     (pytest, ruff, black, isort, mypy, bandit) is included in the same
     image on purpose, so `docker compose run hydra pytest tests/ -q` and
     `docker compose run hydra ruff check .` work against the exact same
     environment as a real scan, with no second image to keep in sync.

### Non-root, and naabu's one exception

The container never runs as root. A dedicated `hydra` user
(uid/gid `10001`) is created early in the build, and every subsequent
`COPY`/`RUN` writes with that ownership from the start — see **Image
size** below for why "create the user first" matters beyond just security
posture.

naabu's SYN-scan engine needs `CAP_NET_RAW`. Rather than running the whole
container `--privileged` (or granting the broader `CAP_NET_ADMIN`), the
Dockerfile grants `cap_net_raw+ep` to the `naabu` binary alone via
`setcap`, at build time:

```dockerfile
RUN setcap cap_net_raw+ep /usr/local/bin/naabu
```

Every other tool in the image — including `nmap`, which Hydra only ever
invokes as `nmap -sV -Pn` (version detection, not a raw SYN scan) — runs
with zero elevated capabilities and works correctly as the unprivileged
`hydra` user; nmap transparently falls back to a full TCP connect scan
without `CAP_NET_RAW`, which is exactly the technique `-sV -Pn` uses
anyway. (naabu is disabled by default — `ENABLE_NAABU=true` is what
actually exercises this capability.)

## Image size

Final image: **2.72 GB**. Above the low end of a "normal" Python image,
for reasons that are inherent to what this image bundles (7 large
statically-linked Go security tools, a real browser engine, and
Playwright's own bundled Node.js driver) — but one real bug was found and
fixed while getting here, worth documenting so it doesn't come back:

**Found:** an early draft finished `COPY . .` and the venv/Playwright
install, then ran a single trailing `RUN chown -R hydra:hydra /app
$VENV_PATH $PLAYWRIGHT_BROWSERS_PATH` to fix ownership before `USER
hydra`. That one "cleanup" step alone added **~940 MB** to the image —
confirmed by comparing `docker history` before and after removing it.
Docker layers are additive diffs, not in-place edits: rewriting every
file's ownership metadata in its own layer, after the layer that created
those files, does not mutate the original layer — it duplicates the
touched files' content into a new layer on top. The image was **3.66 GB**
with this bug, **2.72 GB** without it.

**Fix:** create the `hydra` user before anything else, then either
`COPY --chown=hydra:hydra` or run the content-creating step (venv
creation, `pip install`, `playwright install webkit`) already switched to
`USER hydra`, so files land with the right ownership the first time. The
one place that genuinely needs root — `playwright install-deps webkit`,
which shells out to `apt-get` for WebKit's OS-level shared libraries — is
isolated to its own `RUN` step that only touches apt state, with the
actual ~280 MB WebKit browser download happening later, after `USER
hydra`, as part of the same layer as everything else the non-root user
installs.

**What's left, and why it's not further "bloat" to chase:**

| Layer | Size | What it is |
|---|---|---|
| `playwright install-deps webkit` (apt) | ~670 MB | WebKit's OS-level shared-library dependencies (GTK, GStreamer, X11, font/codec libraries) — Playwright's own supported dependency installer for Debian 12; not something worth hand-rolling a fragile minimal package list to shave, since it would need re-validating against every Playwright release. |
| `pip install` (all 3 requirements files) + WebKit browser download | ~575 MB | `/opt/venv` (≈281 MB — the largest single package is `playwright`'s own site-packages directory at 135 MB, because the Python `playwright` package bundles a full Node.js driver binary internally) + `/opt/playwright` (≈280 MB, the WebKit engine binary itself, which decompresses to roughly 3x its ~96 MB download size). |
| 7 Go binaries | ~437 MB | `nuclei` alone is 169 MB (embeds a template engine and its own TLS stack); the rest average 30–75 MB each — normal for statically-linked Go security tooling. |
| Python 3.11 base (`slim-bookworm`) | ~108 MB | The base image itself. |

Check the current size yourself with `docker images hydra` after building.
If it grows noticeably beyond ~2.7 GB on a future change, `docker history
<image> --no-trunc --format '{{.Size}}\t{{.CreatedBy}}' | sort -rh` is the
first thing to run — it is what caught the chown bug above.

## Building

```bash
docker build -t hydra:local .
```

Or via Compose (also builds `hydra:local` per `docker-compose.yml`):

```bash
docker compose build
```

There is no fixed `ENTRYPOINT` — the image's `CMD` only supplies a default
(`python app.py --help`) when no command is given. This is deliberate: the
same image runs a real scan, the test suite, or the linters, by simply
overriding the command:

```bash
docker run --rm hydra:local                              # prints --help
docker run --rm hydra:local python app.py --version
docker run --rm hydra:local pytest tests/ -q
docker run --rm hydra:local ruff check .
docker run --rm -it hydra:local bash                      # interactive debugging
```

## Persistent state — never baked into the image

`output/` (which holds `recon.db`, the SQLite store), `logs/`, and
`reports/` must live in a mounted volume, not the container's writable
layer — otherwise recreating the container silently discards every past
run. `.env` and `SCOPE_FILE` must never be `COPY`'d into the image either
(a pushed image layer is not a safe place for either) — inject them at
`docker run`/`docker compose` time instead.

### One-time host setup

```bash
mkdir -p docker-data/output docker-data/logs docker-data/reports
# The image runs as uid:gid 10001:10001 — pre-own the mount points so
# Settings.ensure_directories() (which chmod(0o700)s these on first use)
# doesn't fail with a permission error against a root-owned bind mount.
sudo chown -R 10001:10001 docker-data
```

```bash
cp scope.example.txt scope.txt   # then edit scope.txt for your program
cp config/.env.example .env      # then edit .env — see config/.env.example
                                  # for every variable and what it does
```

### Running a real scan

```bash
docker run --rm \
  --env-file .env \
  -e SCOPE_FILE=/app/scope.txt \
  -v "$(pwd)/docker-data/output:/app/output" \
  -v "$(pwd)/docker-data/logs:/app/logs" \
  -v "$(pwd)/docker-data/reports:/app/reports" \
  -v "$(pwd)/scope.txt:/app/scope.txt:ro" \
  hydra:local \
  python app.py run -d example.com
```

`--env-file .env` has Docker itself parse the file into real container
environment variables — the literal file is never copied into the image
or the container's filesystem, only its parsed `KEY=value` pairs reach the
process environment, which is exactly what `Settings.from_env()` reads
(`python-dotenv`'s own file-loading path is only a fallback for when no
env vars are already set — see `config/settings.py`). `SCOPE_FILE` is a
real file path, not a simple value, so it has to be a mounted file; the
`-e SCOPE_FILE=/app/scope.txt` line points Hydra at wherever you mounted
it.

### Investigating past results (no rescan, no volumes to write)

```bash
docker run --rm \
  -v "$(pwd)/docker-data/output:/app/output" \
  hydra:local \
  python app.py investigate example.com
```

## `docker-compose.yml`

```bash
docker compose build
docker compose run hydra python app.py run -d example.com
docker compose run hydra pytest tests/ -q
docker compose run hydra ruff check .
docker compose run hydra bash          # interactive shell for debugging
```

One service, not two: `docker compose run <service> <anything>` already
overrides the command per invocation, so a real scan and the test suite
share one image and one set of volume mounts — a second service definition
would just duplicate the same `build:`/`volumes:` block for no benefit.
`docker compose up` alone (no command) is intentionally not the normal way
to use this — Hydra is not a long-running daemon, and the plain `up` path
exists mainly for the `--build` cache-warming case.

## Network confinement — verified, not assumed

`ScopeEnforcingProxy`/`CollectionGateway` were designed assuming Hydra
controls its own outbound traffic path. Docker's own networking (bridge
mode, its embedded DNS server) is a layer neither of those was written
with in mind, so this was checked directly rather than assumed to be
fine.

### What was run, inside the actual image built above

**All 13 real-binary confinement tests, previously silently skipped in
plain CI** (they gate on `shutil.which(...)`/`pytest.importorskip`, and
the tools they need — real `httpx`, `katana`, `hakrawler`, Playwright's
WebKit — are absent from a bare CI runner today):

```
docker run --rm hydra:local pytest -v \
  tests/test_httpx_confinement_live.py \
  tests/test_browser_confinement_live.py \
  tests/test_crawler_confinement_live.py
```

Result — **13 passed**, all for real, none skipped:

```
tests/test_httpx_confinement_live.py::test_httpx_reaches_authorized_target_through_confinement_proxy PASSED
tests/test_httpx_confinement_live.py::test_httpx_redirect_escape_is_blocked_by_confinement_proxy PASSED
tests/test_httpx_confinement_live.py::test_httpx_in_scope_hostname_resolving_to_private_ip_is_blocked PASSED
tests/test_httpx_confinement_live.py::test_httpx_sends_attribution_user_agent_through_confinement_proxy PASSED
tests/test_browser_confinement_live.py::test_browser_probe_reaches_authorized_target_through_confinement_proxy PASSED
tests/test_browser_confinement_live.py::test_browser_probe_in_scope_hostname_resolving_private_ip_is_blocked PASSED
tests/test_browser_confinement_live.py::test_browser_probe_appends_attribution_to_real_device_user_agent PASSED
tests/test_crawler_confinement_live.py::test_katana_redirect_escape_is_blocked_by_confinement_proxy PASSED
tests/test_crawler_confinement_live.py::test_katana_oos_url_injected_into_input_never_reaches_the_real_server PASSED
tests/test_crawler_confinement_live.py::test_hakrawler_oos_url_injected_into_input_never_reaches_the_real_server PASSED
tests/test_crawler_confinement_live.py::test_hakrawler_redirect_escape_is_blocked_by_confinement_proxy PASSED
tests/test_crawler_confinement_live.py::test_katana_sends_attribution_user_agent_through_real_request PASSED
tests/test_crawler_confinement_live.py::test_hakrawler_sends_attribution_user_agent_through_real_request PASSED
13 passed in 35.00s
```

Each test starts a real local HTTP server (the arbiter — "did the request
actually arrive"), drives the real installed binary through the real
`ScopeEnforcingProxy`, and asserts an out-of-scope redirect/injected URL
never reaches that server. Nothing about this behavior changed inside the
container.

**The verification agent's scope-exclusion canary check, against the real
historical bug it exists to catch** (`docs/VERIFICATION_AGENT_DESIGN.md`,
catalog item 5 — a `!mta*.stripchat.com`-shaped exclusion that once had
zero effect):

```bash
docker run --rm hydra:local python -c "
from core.intel.scope import CollectionScope
from core.verification.preflight import scope_exclusion_canary_check

scope = CollectionScope.from_seeds(
    ['stripchat.com'], patterns=['*.stripchat.com', '!mta*.stripchat.com']
)
findings = scope_exclusion_canary_check(scope)
assert findings == []
print('OK')
"
```

Result: `[]` — identical to the native-host result. The fix
(`core/scope.py::hostname_matches_pattern`) behaves the same way inside
Docker as on bare metal.

### A real (not assumed) DNS comparison

Since Docker's embedded DNS resolver sits in the container's default
`/etc/resolv.conf` path, `core/collection/ssrf.py::resolve_hostname_async`
— which every non-mocked SSRF/IP-classification check ultimately calls —
was run side-by-side, container vs. host, against both a loopback name and
a real public one:

| Host | Docker | Host |
|---|---|---|
| `localhost` | `['::1', '127.0.0.1']` → both `blocked_range` | `['127.0.0.1', '::1']` → both `blocked_range` |
| `example.com` | 4 real IPs → all `allowed` | same 4 IPs, different order → all `allowed` |

Same IP sets, same `classify_ip()` verdicts, in both environments — the
only difference is answer *order* within a single `getaddrinfo()` call,
which is expected (DNS record ordering is not something any resolver
guarantees, and `classify_ip()` is applied per-IP regardless of order).
`naabu` and `nmap -sV -Pn` were also confirmed to run without a permission
error as the unprivileged `hydra` user against `127.0.0.1` inside the
container.

### Known limitation — documented, not hidden

The 13 confinement tests above (and every existing DNS-rebinding test in
the suite) drive the rebinding/redirect-escape scenario by monkeypatching
`resolve_hostname_async` directly in Python — deliberately, since a real
DNS answer changing mid-test isn't something any test can trigger
on-demand against real infrastructure, in Docker or otherwise. That means
neither this verification nor the existing test suite specifically
stress-tests **Docker's own embedded DNS proxy's caching/TTL behavior**
under an actual, timed rebinding attempt (a real record changing between
two lookups a few seconds apart). The side-by-side comparison above shows
Docker's resolver returns the same answers as the host's for a static
name — it does not prove identical behavior for a name whose answer
changes mid-scan. This is a gap in what's been verified, in both
environments, not a known-bad behavior — flagged here rather than assumed
away.

`--network=host` was not used anywhere in this setup, by design (the task
explicitly ruled it out as a default). Nothing in this container needs
it: naabu's raw-socket requirement is satisfied by `setcap` on the binary,
not by the container's network mode, and every other tool works correctly
under Docker's default bridge network as shown above.

## CI

`.github/workflows/ci.yml` gained a second job, `docker`, alongside the
existing lightweight `check` matrix. It builds the image and runs, inside
it: the full test suite, `ruff`/`black`/`isort`/`bandit`, and the two
network-confinement checks above. This is the only place CI exercises the
pinned Go binaries, nmap, and Playwright/WebKit at all — the existing
`check` job never installs any of them, so every tool-gated test
(`skipif`/`importorskip`) silently skips there.

Building the image (Go compiles, apt installs, ~100 MB WebKit download)
plus running the suite inside it takes several minutes longer than the
existing `check` job's under-a-minute run. To avoid slowing down every
single push to a feature branch, the `docker` job is scoped to
`pull_request` events only — a branch still gets fast feedback from
`check` on every push, and the full containerized run gates the actual
merge into `main`.

## Multi-architecture note

This was built and verified natively on `linux/arm64` (Apple Silicon).
The Dockerfile has no architecture-specific paths — `go install` and every
`apt-get`/`pip` package used here are multi-arch — so a
`linux/amd64` build (relevant once this is deployed to a typical x86_64
EC2 instance, out of scope for this document) should produce an
equivalent image via `docker buildx build --platform linux/amd64`, but
that specific target was not built and verified as part of this task.
