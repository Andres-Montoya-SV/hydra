# Product Phase 11e — Recon-Tool Dependency Refresh

Branch: `productization/11e-recon-tool-refresh`. Base: `main` @ `85fc85c`
(after PR #117, Phase 11d).

Phase 11d's image gate allowlisted 53 findings until **2026-11-15**:
- 52 in Go modules compiled into the seven pinned recon tools;
- one in CPython 3.12.

This phase fixes the 52. **The allowlist is down to the CPython entry.**

## Why not just upgrade the tools

Each tool was already pinned to its **latest upstream release**:

| Tool | Release |
|---|---|
| subfinder | 2.16.0 |
| dnsx | 1.3.1 |
| httpx | 1.12.0 |
| naabu | 2.6.1 |
| katana | 1.7.0 |
| nuclei | 3.11.1 |
| hakrawler | 2.1, from 2022 |

Upstream hadn't picked up the fixed modules yet, and `go install
tool@version` builds exactly a release's own `go.sum`.

## How the tools are built now (`docker/build-go-tools.sh`)

**Wrapper module.** Each tool is built from a throwaway wrapper module that
requires the tool at its pinned release and raises its vulnerable
dependencies to **security floors**:

| Module | Floor |
|---|---|
| `golang.org/x/crypto` | v0.56.0 |
| `golang.org/x/net` | v0.56.0 |
| `golang.org/x/text` | v0.39.0 |
| `golang.org/x/mod` | v0.40.0 |
| `github.com/jackc/pgx/v5` | v5.9.0 |
| `google.golang.org/grpc` | v1.83.2 |
| `github.com/go-git/go-git/v5` | v5.19.2 |
| `github.com/antchfx/xpath` | v1.3.6 |

Go's minimal version selection raises only these modules. The tool's own
code, including the version it reports, is exactly the pinned release, and
module checksums are still verified against the Go checksum database.

**A floor only ever raises.** `go get module@version` sets that exact
version. Lowering a module the tool already has at a newer version can
drag other modules down with it, including the tool itself. The first
attempt did exactly this, and verification caught it.

**Toolchain.** The builder is `golang:1.26.8-trixie` with
`GOTOOLCHAIN=local`. Under `auto`, httpx's `go 1.26.0` requirement made Go
download exactly the unpatched 1.26.0 toolchain, and all seven binaries
inherited about 90 of its standard-library advisories. That was the second
thing verification and the gate caught. Now every tool is compiled by the
image's current Go release, and one needing a newer Go fails the build.

**Verified, never assumed.** After each build, the script fails the image
build unless:
- the binary was compiled by the builder's Go;
- its main module is the tool at exactly the pinned version;
- every floored module it contains is at or above its floor.

None of the pinned releases uses `replace` directives, which a wrapper
would ignore. This was checked when the floors were introduced.

**Pins.** The pins moved from the Dockerfile's `go install` lines to the
script's `build` lines. The Phase 09 test that requires every pinned
version to be a qualified version now reads them there (unchanged values).

## Re-qualification (Phase 09)

The rebuilt image was checked by:
- **the strict suite** (`HYDRA_REQUIRE_OPTIONAL_DEPS=1`,
  `HYDRA_REQUIRE_IMAGE_TOOLS=1`): **2,700 passed**. Every tool is found,
  identity-verified and qualified against its profile (version, flags);
- **the live checks** (httpx, browser and crawler network confinement,
  plus provider qualification): **52 passed**.

## Result

| | before (11d) | after |
|---|---|---|
| Fixable Critical | 9 | **0** |
| Fixable High | 44 | **1** (CPython 3.12, allowlisted) |
| Allowlist entries | 53 | **1** |

The CPython entry stays until a 3.12 patch release carries the fix, or the
base image moves to a newer Python line. It expires 2026-11-15, which
forces that review.

Findings **without** a fix (mostly Debian) are unchanged and still
reported in every CI artifact.
