# Product Phase 13c — Client CLI and Beta Acceptance Test

Branch: `productization/13c-client-cli`. Base: `main` @ `814013e` (after
PR #129, Phase 13b). Part of Phase 13 (Private Beta Readiness): see
[13a](13a_errors_and_diagnostics.md) for the split.

## `hydra_client`: a thin API client (decision 2026-10-02)

```sh
export HYDRA_API_URL=https://api.example.com   # default http://127.0.0.1:8000
python -m hydra_client signup you@example.com --save-key ~/.hydra-key
python -m hydra_client --key-file ~/.hydra-key diagnostics
```

- **Only an API consumer.** It calls the documented public API exactly as
  any client would. It has no privileges of its own and is never a
  second way into Hydra. It uses only the Python standard library and
  runs from the repository or the image.
- **Commands:**

| Command | Does |
|---|---|
| `version` | release and contract version |
| `signup EMAIL [--save-key FILE]` | creates the account; the key is shown once, or written to `FILE` with mode 600 |
| `verify-email TOKEN` | confirms the email |
| `diagnostics`, `subscription` | the account's state and hints; tier, limits and usage |
| `orgs`, `org-create NAME`, `demo` | organizations; the demo organization |
| `domain-add DOMAIN`, `domain-verify DOMAIN [--method]` | domain verification |
| `scan DOMAIN [--profile]`, `scan-status ID`, `scan-wait ID` | scans |
| `assets ORG`, `exposures ORG`, `exposure-resolve ORG ID --reason` | inventory and triage |
| `monitor DOMAIN [--speed2]`, `feedback CATEGORY MESSAGE` | monitoring; feedback |
| `call METHOD PATH [--data JSON] [--param k=v]` | any other endpoint |

- **The key** comes from `HYDRA_API_KEY` or `--key-file`, never from a
  command-line value that other processes could read. It is sent only in
  the `X-API-Key` header, only to `HYDRA_API_URL`.
  - Redirects are never followed (a 3xx is an error), so the key can't be
    forwarded to another host.
  - Only HTTP and HTTPS can be opened.
  - Plain HTTP to a non-loopback host prints a warning.
- **Errors** print the API's `code`, message and request id to stderr.
  The exit status tells a script what happened:

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | the API refused the request |
| 2 | invalid command line or URL |
| 3 | the API could not be reached |
| 4 | `scan-wait`: the scan failed or the wait timed out |

- **Retries follow the 13a semantics.**
  - A request is retried only when the server marks the error
    `retryable` and the method is safe to repeat (`GET`, `HEAD`, `PUT`,
    `DELETE`).
  - It's retried at most three times, after `Retry-After` (capped at 60
    seconds) or an exponential backoff.
  - A `POST` is never retried automatically. For example, a scan is
    created and counted per call.
- **Path values are quoted**, so a user value is always one path segment.
  `scan-status ../admin` asks for the scan `../admin`; it can't reach a
  different path.

## The beta acceptance test (`tests/test_beta_acceptance.py`)

The roadmap's acceptance test is a realistic organization lifecycle
driven entirely through the API/CLI. It runs every step through the CLI:

1. `version`, `signup`, `diagnostics` (hint: email not verified), then
   `verify-email` with the token from the email;
2. `demo`, then exploring its exposures; trying to change one gives
   `demo_organization_read_only`;
3. `domain-add`, publishing the TXT record, then `domain-verify`;
4. `scan`, `scan-wait`; a second `scan` gives `scan_quota_exceeded` on
   Free;
5. assets and the exposure the scan found, its evidence, then
   `exposure-resolve` with a reason;
6. `monitor`, `feedback`, `diagnostics` (only the quota hint remains),
   then the account export;
7. deleting the demo organization.

**What's real:**
- the whole app: routing, auth, edge, entitlements, error shape;
- the scan worker that claims and runs the scan;
- the EASM backfill and exposure lifecycle;
- domain verification: a real DNS TXT lookup against a local test DNS
  server, through the documented, off-by-default `HYDRA_API_DEV_DNS_*`
  settings.

**What stands in:**
- the recon pipeline's network collection, replaced by fixture results
  for the verified domain only;
- the verification email, read from the token the console sender would
  have printed.

Every name and address is reserved for documentation. No real target is
contacted.

### A 13b bug it found

On Postgres, the acceptance test failed intermittently with a duplicate
asset.

**Cause.** The demo organization's fixture scan was inserted `queued` and
marked completed a moment later. A running scan worker could claim it in
between and execute it: a real scan of `example.com`. The 13b tests
didn't see it because their test app runs no workers.

**Fix:**
- The demo scan is now inserted already `completed` and is never queued.
- The worker's claim also skips `demo` scans.
- Two regression tests cover it: one runs real workers while creating a
  demo, and asserts no pipeline runs. Each fails when its safeguard is
  removed.
- After the fix, the acceptance test passed 15 of 15 runs on each
  backend.

## Tests

- **`tests/test_hydra_client.py`:**
  - retries: only retryable and safe; `Retry-After` honoured and capped;
    a `POST` never retried; at most three attempts;
  - a non-Hydra error body;
  - the key only in the header;
  - path quoting;
  - http(s) only;
  - the cleartext warning;
  - usage errors;
  - an unreachable API;
  - the real `urllib` transport against a local HTTP server: a real 429
    then 200 (retried after `Retry-After`); a redirect not followed; a
    `file:` URL refused;
  - against the real app: `signup --save-key` (mode 600), then
    `--key-file`; an API error's code and request id.
- **`tests/test_beta_acceptance.py`:** the lifecycle above, on both
  backends.
- **`tests/test_demo_and_feedback.py`:** the two new regression tests.
