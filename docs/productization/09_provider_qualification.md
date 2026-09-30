# Product Phase 09 — Provider Qualification & Engine Hardening

Branch: `productization/09-provider-qualification`. Base: `main` @ `19021b6`
(after PR #108).

## The risk

The EASM final audit left **risk #11** open: provider version-upgrade
semantics were unqualified. Hydra drives external binaries (httpx, nuclei,
naabu and others) and parses their output. Nothing tied a given binary
version to the parser that reads it, or checked that the flags each plugin
passes still exist.

What existed before this phase:

- version detection (`core/dependencies`);
- one confirmed-incompatible entry (amass v5, in
  `KNOWN_INCOMPATIBLE_VERSIONS`);
- identity checks, which tell ProjectDiscovery's httpx apart from the
  Python httpx console script;
- a Dockerfile that pins every Go tool to an exact release.

## Qualification (`core/provider_qualification.py`)

Each binary the image pins has a profile:

| Tool | Binary | Qualified | Driven by |
|---|---|---|---|
| subfinder | subfinder | 2.16.0 | `modules/subfinder.py` |
| dnsx | dnsx | 1.3.1 | `modules/dnsx.py` |
| httpx | httpx | 1.12.0 | `modules/httpx.py` |
| naabu | naabu | 2.6.1 | `modules/naabu.py` |
| katana | katana | 1.7.0 | `modules/katana.py` |
| nuclei | nuclei | 3.11.1 | `modules/nuclei.py` |
| hakrawler | hakrawler | 2.1 (no version flag; the flag surface is verified) | `modules/hakrawler.py` |
| port_verify | nmap | 7.95 (Debian trixie package) | `modules/port_verify.py`, `modules/naabu.py` (canary probe) |

A profile also lists every flag Hydra passes to the binary, each with the
token that must appear in the binary's own help output. Most tokens are the
flag itself; one exception is nmap's `-T1`, which its help documents as
`-T<0-5>`.

`qualify()` gives each tool one status, with its reasons:

| Status | Meaning |
|---|---|
| `qualified` | a pinned version, and every flag present |
| `unverified_version` | another version; runs, with a warning |
| `version_unknown` | the version couldn't be detected; runs, with a warning |
| `missing_flags` | the binary no longer lists a flag Hydra passes |
| `known_incompatible` | a confirmed-bad major version (amass v5) |
| `not_installed` | the binary isn't present |

## Where it's enforced

1. **Preflight, on every scan** (`ToolManager.validate_tools`). Every ready,
   profiled tool is qualified against its identity-verified binary, and the
   result is recorded in `context.metadata["provider_qualification"]`.
   - A binary with **missing flags** or a **known-incompatible** version
     becomes **UNAVAILABLE**, with the reason as a warning. Coverage is then
     visibly missing, never silently garbage.
   - An **unverified** or **undetectable** version runs, with a warning.
2. **`check-tools` CLI.** It prints a Provider Qualification table after the
   dependency report.
3. **CI** (`tests/test_provider_qualification.py`), in four layers:
   - **Source contract:** each plugin's flag literals (read from its source
     AST) must be covered by its binaries' profiles, and no profiled flag
     may be stale. A plugin can't start or stop passing a flag without the
     profile changing.
   - **Dockerfile pins:** every pinned version must be a qualified version.
     Bumping a pin without re-qualifying fails **every** CI job. This was
     checked by bumping httpx to 1.13.0: "Dockerfile pins httpx 1.13.0 but
     its profile qualifies ['1.12.0']: re-qualify before bumping".
   - **The real binaries in the image:** the Docker job runs with
     `HYDRA_REQUIRE_IMAGE_TOOLS=1`. Every pinned binary must be present,
     report its qualified version, and list every flag.
     - Binaries are resolved through the same identity-verified discovery
       production uses. A bare PATH lookup finds the Python httpx console
       script in the image, which the first version of this test did.
     - Outside the image, this layer skips. A developer machine
       legitimately has other versions: here it reported httpx 1.9.0,
       nuclei 3.9.0, subfinder 2.14.0, and nmap 7.97 as unverified, with
       every flag still present. The preflight reports that at scan time.
   - **The rules themselves** are unit-tested.

## Re-qualifying a tool (the procedure)

1. Bump the pin in the Dockerfile.
2. Build the image and run the tool's parser tests against real output
   from the new version.
3. Add the new version to the tool's `qualified_versions`, and adjust its
   `flags` if the plugin changed.
4. CI's Docker job then confirms the real binary qualifies.

## Deprecated modules — reconnaissance and verdict

The roadmap says not to remove them until every consumer is proven
migrated. They aren't, so both stay, and their notes are corrected:

- **`core/diff.py::ScanDiff`** — **retained.** It is the CLI's only diff,
  and it has live consumers:
  - `core/runner.py` writes `diff.json` and sends the `WEBHOOK_URL`
    notification;
  - `core/intel/cli.py` backs the `diff-runs` command.

  The EASM change-event model it was meant to be absorbed into lives in the
  API's control database, which the CLI doesn't use. The old note also
  named `core/verification/grounding.py` as an importer, which was wrong.
  Migrating needs a CLI-side change-event path first.
- **`core/intelligence.IntelligenceEngine`** — **retained.** The old note
  said its output was "silently discarded"; the code shows otherwise:
  - it sets every host's `profile` and risk score, which the scan report
    reads;
  - its clusters are persisted and read by the reporter, the JSON export
    and the run metadata;
  - its graph is the *input* to the newer engine's graph.

  Removal needs replacements for all three.

## Not done

- **Recorded-output parser fixtures for the pinned versions.** The parser
  tests use representative inline output. Real recorded output per pinned
  version needs the tools run against owned targets; that fits the
  re-qualification procedure above.
- **Phase 00's `core/confidence.py` `max()`-aggregation note.** A scoring
  change deserves its own evidence and review.
