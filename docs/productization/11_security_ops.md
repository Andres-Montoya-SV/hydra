# Product Phase 11 — Product Security, Reliability & Operations

Phase 11 is broad: the roadmap lists about 25 items. This document is the
audit of where each one stands in the code, what 11a changes, and the
order of the remaining work.

## Audit (2026-10-01, `main` @ `3b0384a`)

| Item | Status | Evidence / gap | Where it lands |
|---|---|---|---|
| Secrets management | **in place** | Secrets come only from the environment. Stored third-party secrets are sealed (`api/secrets_box.py`, Fernet, key rotation). Sentry scrubs secrets. | — |
| Rate / request limits | **partial** | Per-key request rate limit and per-IP account creation limit exist. **No request body limit outside imports.** | **11a** |
| Auth / session strategy | **in place** | API keys only: Argon2id hash plus a lookup index; no sessions. Admin endpoints now take an operator account's API key; the static token is gone. | **11b** (done) |
| API keys + rotation | **in place** | `POST /keys/{id}/rotate`, `/revoke` | — |
| Audit logs | **in place** | Domain audits (capability changes, business context, remediation, scope exclusions), plus the security audit log for keys, failed sign-ins, members, integrations and admin actions. | **11b** (done, [doc](11b_audit_and_operators.md)) |
| Dependency scanning | **in place** | `pip-audit` in CI over all requirement sets, plus an image scan (Grype) gating fixable Critical/High findings. | **11d** (done) |
| SBOM | **in place** | CycloneDX SBOM of the image, built in CI (Syft), kept as an artifact. | **11d** (done, [doc](11d_supply_chain_metrics.md)) |
| Container security | **in place** | Multi-stage build, non-root user, image vulnerability gate; recon tools built with verified dependency floors on a current Go toolchain. One allowlisted finding remains (CPython 3.12, no fix in that line). | **11d** (gate), **11e** (tool refresh, [doc](11e_recon_tool_refresh.md)) |
| Backups / restore drills / DR | **in place** | Phase 10d: logical export, verified restore, rehearsals, DigitalOcean PITR procedure. | — |
| Monitoring / metrics | **in place** | Sentry (opt-in), heartbeats, and Prometheus `/metrics` (operators). | **11d** (done) |
| Structured logs | **in place** | `HYDRA_API_LOG_FORMAT=json` (`api/observability.py`) | — |
| Correlation IDs | **missing** | | **11a** |
| Health / readiness | **partial** | `/health` (database plus loop heartbeats). **No readiness probe.** | **11a** |
| Worker heartbeats | **in place** | `LoopHeartbeats` for every background loop | — |
| Stuck-job recovery | **in place** | Orphaned-scan requeue; outbox lease reclaim | — |
| Data-retention controls | **in place** | Tier retention purge (reconciliation loop), observation retention | — |
| Tenant deletion / export | **in place** | Self-service deletion with a 30-day grace period (audit and billing kept, pseudonymized) and a complete organization archive. | **11c** (done, [doc](11c_tenant_export_deletion.md)) |
| Security headers | **missing** | | **11a** |
| CORS | **missing** (implicitly none) | | **11a** (explicit allowlist) |
| Upload size / type limits | **partial** | Imports are bounded at 25 MB and parsed by type; other endpoints are unbounded. | **11a** |
| SSRF boundaries | **gap found** | Webhooks and ticketing are pinned to public addresses. **The well-known-file domain verification fetched the caller's domain with a plain client:** a domain resolving to `127.0.0.1`, a private range or `169.254.169.254` made the API fetch it. | **11a** (fixed) |
| Path traversal / SQLi / BOLA / IDOR | **in place** | Parameterized SQL only (no runtime composition, 10a–10d); IDOR tests on every endpoint; Postgres RLS (10c); re-tested over every route by the standing adversarial suite. | **11g** (done) |
| Operator pipeline config for API scans | **in place** | API scans inherit the operator's infrastructure and safety settings (classified allowlist, every field), never its scope, identity or credentials; the operator can switch tools off, never on. | **11f** (done, [doc](11f_operator_scan_settings.md)) |
| Adversarial security re-test | **in place** | Standing suite over every route (no key, cross-tenant ids, non-operators, hostile path values, mass assignment, victim reads); found and fixed a 500 on missing report files and a NUL-character 500 on Postgres. | **11g** (done, [doc](11g_adversarial_retest.md)) |

## 11a — Edge hardening (this PR)

### SSRF in the well-known-file verification (`api/domain_verification.py`)

The production path now goes through the same gate as webhook
deliveries:

1. Resolve the domain once and refuse it unless every address is public
   (the shared `core/collection/ssrf.py` blocklist: loopback, private,
   link-local and metadata).
2. Fetch from that pinned address (`api/webhooks.py::get_pinned`): no
   re-resolution (no DNS rebinding), TLS checked against the real host
   name, no redirects.
3. Read at most 4 KB of the response.

Tests check that a domain resolving to any non-public address, even one
among public ones, is never fetched.

### `api/edge.py`

One middleware in front of every router:

- **Request id.** Every response carries `X-Request-ID`, and every log
  line in the request includes it: `[id]` in text logs, `request_id` in
  JSON logs. A caller's own id is kept only if it's 8–64 characters of
  `[A-Za-z0-9._-]`; anything else is replaced, so it can't be used to
  inject into logs.
- **Body limit.** `HYDRA_API_MAX_BODY_BYTES` (default 1 MiB) applies to
  everything except imports, which keep the importer's 25 MB.
  - Oversized bodies are refused with **413** before the router runs,
    whether the size is declared up front or counted as it streams.
  - A streamed oversize body on a real FastAPI route is a 413, not a
    generic 400. A mutation check confirmed the test catches this.
- **Security headers** on every response, including 404s, 401s and 413s.
  A header a route sets itself is not overridden.

  | Header | Value |
  |---|---|
  | `X-Content-Type-Options` | `nosniff` |
  | `X-Frame-Options` | `DENY` |
  | `Referrer-Policy` | `no-referrer` |
  | `Cache-Control` | `no-store` (responses carry tenant data) |
  | `Cross-Origin-Resource-Policy` | `same-origin` |
  | `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` (omitted on `/docs` and `/redoc`, which load their UI from a CDN) |
  | `Strict-Transport-Security` | only when `HYDRA_API_HSTS_SECONDS > 0`; set it once TLS terminates in front of the API |

- **CORS.** Off unless `HYDRA_API_CORS_ORIGINS` lists exact origins
  (`https://…`; `http://` only for localhost). It never sends
  credentials and never allows `*`. Invalid values stop the API at
  startup.

### `GET /ready`

Readiness, meaning the control database answers: 200 or 503, without
authentication. `/health` keeps the full check, including background-loop
heartbeats. Load balancers should route on `/ready`.

## Order of the remaining work

| Part | Content |
|---|---|
| 11b | Security audit log (keys, members and roles, integrations and webhooks, admin actions, auth failures), plus replacing the static admin token |
| 11c | Tenant export and deletion: complete, verified, with a deletion grace period |
| 11d | Supply chain and operations: SBOM, image vulnerability scan in CI, metrics endpoint |
| 11e | Recon-tool dependency refresh: upgrade or rebuild the pinned Go tools, re-qualify (Phase 09), and empty the image-scan allowlist (due before 2026-11-15) |
| 11f | Operator pipeline settings for API scans: an allowlist, keeping per-account paths isolated |
| 11g | Adversarial security re-test of every product endpoint |
