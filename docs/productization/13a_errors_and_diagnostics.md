# Product Phase 13a — Errors, Retries, Version and Diagnostics

Branch: `productization/13a-errors-and-diagnostics`. Base: `main` @
`8bb5dc0` (after PR #122, Phase 12b).

Phase 13 (Private Beta Readiness) is split into four parts:

| Part | Content |
|---|---|
| **13a** (this) | one error shape for every failure; retry semantics; `GET /version`; `GET /account/diagnostics` |
| 13b | the demo organization (`POST /demo/organization`); feedback (`POST /feedback`) |
| 13c | a thin API-client CLI; the beta acceptance test |
| 13d | API reference, operator and customer runbooks, migration and rollback |

## Recon (2026-10-02, `main` @ `8bb5dc0`)

- About 75 errors returned a plain string `detail` and 12 a structured
  one, each with its own keys. There was no common, machine-readable
  code.
- An unhandled exception returned `text/plain` "Internal Server Error",
  with nothing to quote to support but the `X-Request-ID` header.
- The 429s gave no `Retry-After`.
- There was no version endpoint, and the OpenAPI document said `0.1.0`
  while the release is `1.0.0`.

## One error shape (decision 2026-10-02: additive)

Every 4xx and 5xx response, from a router, request validation, an
unhandled exception or the edge middleware, now has this shape:

```json
{"detail": "<exactly what it was before>",
 "error": {"code": "domain_not_verified",
           "message": "Domain 'example.com' is not verified for this account. ...",
           "request_id": "2f1c…",
           "retryable": false}}
```

- **`detail` is unchanged**, so no existing client breaks. Validation
  errors keep FastAPI's list.
- **`code`** is stable and machine-readable. A client should branch on
  it, never on the message.
- **`message`** is for people: the string `detail`, a structured
  detail's `message`, or a one-line summary of a validation error
  (`body.email: Field required`).
- **`request_id`** equals the `X-Request-ID` header. Quote it to
  support; the server log has the same id.
- **`retryable`**: see below.
- **A 500 never leaks** the exception. Its message is "Internal Server
  Error"; the details are only in the server log, under the request id.
- **Fixed on the way: a 500 had no request id.** Starlette answers an
  unhandled exception outside every middleware, so a 500 also lacked the
  security headers. The edge now answers it, then re-raises so the
  server still logs it and error tracking still sees it.

### Codes

Every error has a code. A specific one, when the client can act on it:

| Code | Status | Meaning, and what to do |
|---|---|---|
| `email_not_verified` | 403 | Verify the account's email (`POST /accounts/resend-verification`). |
| `verification_token_invalid` | 404 | The email token is wrong or already used. |
| `verification_token_expired` | 400 | Ask for a new one. |
| `domain_not_verified` | 403 | Verify the domain (`POST /domains`) before scanning or monitoring it. |
| `domain_verification_expired` | 403 | Re-verify the domain. |
| `scan_quota_exceeded` | 403 | This month's scans are used up. |
| `scan_not_completed` | 409 | The scan is still running; poll `GET /scans/{id}`. |
| `owner_role_required` | 403 | Only an organization owner can do this. |
| `account_suspended` | 402 | Read-only until billing is resolved (`POST /account/subscription`). |
| `entitlement_exceeded` | 403 | A tier limit (Phase 12a); `upgrade_to` names the next tier. |
| `capability_not_entitled` | 403 | The tier doesn't include that capability. |
| `invalid_capability_request` | 422 | The capability selection is malformed. |
| `target_excluded` | 422 | The target is in the organization's scope exclusions. |
| `invalid_exclusion_pattern` | 422 | The exclusion pattern isn't valid. |
| `invalid_import` | 422 | The uploaded report couldn't be imported. |
| `invalid_integration` | 422 | The integration's configuration is invalid. |
| `invalid_remediation` | 409, 422 | The remediation change isn't allowed or is malformed. |
| `invalid_transition` | 404, 409 | The workflow status change isn't allowed from the current status. |
| `secrets_key_not_configured` | 503 | The deployment can't store integration secrets yet (operator). |

Otherwise the code follows the status:
- 4xx: `bad_request`, `unauthenticated`, `payment_required`,
  `forbidden`, `not_found`, `method_not_allowed`, `conflict`, `gone`,
  `payload_too_large`, `unsupported_media_type`, `validation_failed`,
  `rate_limited`;
- 5xx: `internal_error`, `upstream_failed`, `unavailable`,
  `upstream_timeout`.

A test checks that every specific code used in `api/` is in the table
above.

## Retry semantics

`retryable` answers one question: can the **same request**, sent again
later and unchanged, succeed?

| Status | Retryable | How |
|---|---|---|
| 429 | yes | Wait `Retry-After` seconds. A key's limit refills one request every `60 / limit` seconds; account creation says to check back in an hour. |
| 502, 504 | yes | An upstream (e.g. the payment provider) failed. Back off exponentially. |
| 503 with `Retry-After` | yes | Temporarily unavailable. |
| 503 without it | no | Missing configuration, such as a payment link. Retrying won't help; tell the operator. |
| 500 | no | A bug. Report the `request_id`. |
| every other 4xx | no | Fix the request, the account or the target first. |

**Which requests are safe to repeat** after a timeout, when the client
doesn't know whether the first one arrived:
- **Safe:** every `GET`; every `DELETE`; and every "set" write, which
  ends in the same state when repeated. Examples: monitoring opt-in,
  member roles, exposure status changes, branding. The repeat may answer
  differently (a second `DELETE` is a 404, resolving a resolved exposure
  a 409 `conflict`), but the state is the same.
- **Not safe:** `POST /scans`, which creates and counts one scan per
  call. On a timeout, look for the scan first: `GET /account/diagnostics`
  lists the account's recent scans. The same applies to creating
  organizations, keys, webhooks and integrations.
- **Imports** are deduplicated: re-sending the same report changes
  nothing and doesn't count against the quota (Phase 12a).

## `GET /version`

Public, like `/health`, so a client can check compatibility before it
has a key:

```json
{"version": "1.0.0", "api_version": "1"}
```

- `api_version` changes only on a breaking change to an existing
  endpoint. New endpoints and new fields keep it.
- The OpenAPI document reports the same version.
- A test keeps `pyproject.toml`, the CLI's `--version` and `api/version.py`
  equal.
- The build commit isn't public. It's in the diagnostics: the image takes
  `--build-arg HYDRA_BUILD_COMMIT=…`, which CI sets to the commit.

## `GET /account/diagnostics`

One response a customer can read, or hand to support:
- **About the request and server:** the request id, server time, version
  and build commit.
- **About the account:** whether its email is verified, the calling key
  (id and expiry, never key material) and the number of active keys.
- **About the tier:** the tier and subscription status, and this month's
  scans used and the limit.
- **About the domains:** organizations; verified domains, and the ones
  beyond the tier's limit; monitored domains, and how many are paused.
- **The account's last 10 scans**, with status, retries and error
  message.
- **`hints`:** plain-language reasons the account may not be working,
  e.g. "Email not verified…", "Account suspended…", "This month's scans
  are used up…", "No verified domain yet…".

It is scoped to the caller. It shows only the caller's own scans, even
in an organization shared with others, and never a secret. The
adversarial suite (Phase 11g) covers it with every other route.

## Tests (`tests/test_errors_and_diagnostics.py`, both backends)

- **The envelope:**
  - every protected route (enumerated from the adversarial route table)
    without a key;
  - unknown paths and wrong methods;
  - validation;
  - the edge's NUL and size refusals;
  - an unhandled exception: JSON, with a request id and without the
    exception text;
  - a structured detail lends its code.
- **Specific codes:** the onboarding failures, scan quota, scan not
  completed, owner role, suspension.
- **Retries:** both 429s carry `Retry-After` and are retryable; a
  configuration 503 and a 404 are not.
- **Version:** public; one version in all three places; the commit isn't
  exposed.
- **Diagnostics:**
  - a new, unverified account gets its hints, and never sees its key;
  - a failed scan shows its error and the build commit;
  - another member's scans in a shared organization stay hidden;
  - a suspended, over-the-limit account gets its hints.
- **Documentation:** every specific code is in the table above.
