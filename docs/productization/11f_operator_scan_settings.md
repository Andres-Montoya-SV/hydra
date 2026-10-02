# Product Phase 11f — Operator Pipeline Settings for API Scans

Branch: `productization/11f-operator-scan-settings`. Base: `main` @
`ec6b25c` (after PR #118, Phase 11e).

## The gap

`api/tenancy.py::account_settings` builds every API scan's `Settings` from
defaults, never from the operator's `.env`. That kept tenants isolated,
but it also dropped the operator's own infrastructure and safety
settings:
- a lowered `RATE_LIMIT` protecting targets;
- an `OUTBOUND_PROXY_URL` for egress;
- a tool installed at a custom path;
- tighter timeouts or caps.

## Decisions (2026-10-01)

- **Third-party data-source keys** (SecurityTrails, GitHub, URLhaus,
  WPScan): **never** used by API scans. The operator's keys, quotas and
  provider terms stay with the operator's own CLI use.
- **Tool switches** (`ENABLE_*`, `NUCLEI_ENABLE_INTERACTSH`): the operator
  **can only switch a tool off** for API scans, never on.

## The classification (`api/operator_settings.py`)

Every one of the 173 `Settings` fields is in exactly one set. A test fails
on an unclassified field, so a new setting must be classified on purpose.

| Set | Fields | API scans |
|---|---|---|
| `INHERITED` | tool binary paths; resolvers, wordlists, GeoIP database; egress proxy, user agent, strict opsec; every timeout, rate limit, thread count, concurrency and delay; all size and budget caps | use the **operator's** value |
| `ACCOUNT_ONLY` | the account's directories and CLI presentation; **scope** (`SCOPE_FILE`, `OWNED_DOMAINS`, exclusions, external-target mode, derived-bucket authorization, GitHub org); the operator's **bug-bounty identity** (researcher headers, HackerOne handle, program names, custom headers); **credentials and LLM settings** | **never** the operator's |
| `TOGGLES` | `enable_*`, `nuclei_enable_interactsh` | an explicit `false` in the operator environment switches it off; nothing switches one on |

The scope rule matters most: an API scan's scope is the tenant's verified
domains and exclusions, never the operator's `SCOPE_FILE`. The identity
rule keeps the operator's personal bug-bounty headers away from
customers' targets. The developer `.env` in this repository sets both,
which is why they're excluded by name.

## Where it applies

`api/scan_orchestrator.py::_scan_settings`, the single path for manual,
scheduled and monitoring scans:

1. Start from the account's defaults.
2. **Inherit** the operator's `INHERITED` values. They are validated, so a
   tool path that doesn't exist fails the scan with a clear error.
3. Apply the scan's capabilities: override, organization default, and
   tier ceiling.
4. Apply passive narrowing, if the scan is passive.
5. Apply the **operator disables**, last, so they win.
6. Record the effective providers, so the scan shows exactly what was
   allowed to run.

"Explicitly false" means the variable is set to `0`, `false`, `no` or
`off`. A tool that is merely off by default (unset) is not treated as
operator-disabled, so a tier that selects it can still run it.

The operator settings are also parsed **once at API startup**. A malformed
value, such as `ENABLE_NUCLEI=perhaps`, stops startup instead of failing
every scan later.

## Tests (`tests/test_operator_settings.py`, both backends)

The tests pin the operator `.env` to an empty file and clear every toggle
variable, so they behave the same on a developer machine and in CI.

- **Classification:** every field is classified exactly once; credentials,
  scope, identity and directories are account-only.
- **Inheritance:**
  - rate limit, timeout, egress proxy and a real tool path reach API scans;
  - the HackerOne handle, the SecurityTrails and GitHub keys, owned domains
    and the output directory don't;
  - the project root stays the account's.
- **Toggles:**
  - an explicit `false` removes a provider the profile and tier selected;
  - `true` never adds one;
  - the recorded effective providers reflect the switch;
  - interactsh can only be switched off.

  Mutation-checked: without the disable step, both provider tests fail.
- **Startup:** a malformed operator value stops `load_api_settings`.
