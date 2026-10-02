# Product Phase 11g — Adversarial Security Re-test

Branch: `productization/11g-adversarial-retest`. Base: `main` @ `a4806b7`
(after PR #119, Phase 11f).

The roadmap asks to re-run adversarial security testing once all product
endpoints exist. This is the last part of Phase 11. It is not a one-off
review: `tests/test_adversarial_api.py` is a **standing suite** that runs
on every CI build, on SQLite and on PostgreSQL with row-level security
enforced.

## How it works

The suite enumerates the **real application's routes**: 105 of them,
through FastAPI's lazily-included routers. It doesn't use a hand-kept
list, so every endpoint added later gets every attack automatically. Only
the exceptions are written down:

- `PUBLIC`: 6 routes reachable without a key on purpose. These are health
  and readiness, account creation and email verification, and the Wompi
  webhook, which is authenticated by its signature instead.
- `OPERATOR`: the 4 operator-only routes.

A test fails if either list names a route that no longer exists.

A seeded **victim** tenant has real objects:
- an organization, an asset, an exposure and a candidate asset;
- a scope exclusion, a scan, a webhook, an API key and a member.

The **attacker** is a second, verified tenant with a valid key.

| Attack | Routes | Expected |
|---|---|---|
| No API key | every non-public route (99) | 401 |
| Another tenant's key on the victim's real ids (BOLA/IDOR) | every tenant route with a path parameter | **404 every time**: never a success, never a 403 that would confirm the object exists, never a 5xx. Domain-keyed routes may answer 403 "not verified by you", which reveals nothing about the victim. |
| Non-operator on operator routes | 4 | 404 |
| Hostile path values (SQL injection, traversal, encoded traversal, NUL, 4 KB) | every route with a path parameter | never a 5xx, never a success |
| The victim's own reads | every GET with the victim's real ids | never a 5xx |
| Privileged fields in bodies (mass assignment) | organization creation, account creation, scope exclusions | ignored: a smuggled `organization_id` doesn't attach the attacker to the victim's organization; `is_operator` doesn't make an operator |

Requests are built so they reach each endpoint's own authorization check
rather than stopping at validation:
- bodies are generated from each route's request schema;
- required query parameters are filled in;
- one model-level rule (bulk remediation) has an explicit body.

The cross-tenant check accepts no 422 for this reason.

Two checks keep the 404s honest:
- **Real ids:** the same objects read successfully as the victim, so the
  attacker's 404 means isolation, not a wrong id.
- **Every response,** errors included, carries the security headers and a
  request id (11a).

## What it found (fixed here)

1. **`GET /scans/{scan_id}/report` returned 500** when a completed scan's
   report files were gone. That happens after a retention purge or a
   tenant deletion (11c). It now returns **410 Gone** and logs a warning.
   A mutation check confirmed that the regression test and the
   victim-read sweep both fail with the old 500.
2. **A NUL character in a request became a 500 on PostgreSQL.**
   PostgreSQL refuses NUL in text, and SQLite doesn't, so the SQLite run
   alone would have missed it.
   - **The edge** (`api/edge.py`) now refuses a NUL with **400**, whether it
     is in the path, the query, or the body (raw, or JSON-escaped
     `\u0000`, even split across streamed chunks). No legitimate request
     carries one.
   - **Imports** keep their own body handling, so a compressed upload
     still gets its clearer 422. The importer refuses NUL itself with a
     422, because a NUL in an imported string would otherwise reach the
     database too.

Nothing else surfaced:
- no endpoint was reachable without a key;
- no cross-tenant request succeeded or confirmed existence;
- no operator route was visible to a non-operator;
- no hostile path value produced a success;
- no privileged field was assignable.

## Phase 11 is complete

| Part | Delivered |
|---|---|
| 11a | audit; SSRF fix; request ids, body limits, security headers, CORS, readiness |
| 11b | security audit log; operator accounts |
| 11c | tenant export and deletion |
| 11d | SBOM, image vulnerability gate, metrics |
| 11e | recon-tool dependency refresh |
| 11f | operator pipeline settings for API scans |
| 11g | this adversarial re-test (standing suite) and its two fixes |

One dated item remains: the CPython 3.12 entry in the image-scan
allowlist expires on 2026-11-15 (see 11e).
