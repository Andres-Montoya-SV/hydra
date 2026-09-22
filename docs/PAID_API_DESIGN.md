# Paid EASM API — Design (Part 1: design only, no implementation)

Status: **design only.** No production code was written for this
document. This is reviewed before any implementation work (framework
choice, endpoint code, database migration) begins in Part 2.

Everything here builds on capabilities that already exist and are already
tested in this repository — the reconnaissance pipeline (`core/runner.py`,
`PipelineRunner`), the persisted intelligence store (`core/store.py`,
`AssetStore`), the scope/authorization layer
(`core/intel/scope.py`, `CollectionScope`), and the LLM-backed features'
own cost-estimate-then-confirm discipline
(`core/reportability/cli.py`, `docs/REPORTABILITY_AGENT_DESIGN.md`). The
paid API is a multi-tenant HTTP surface in front of that engine, not a
rewrite of it — Part 2's job is mostly "pick which existing function to
call, and whose data to scope it to," not "build a new scanner."

Wompi's real capabilities were verified directly against `docs.wompi.sv`
(El Salvador) rather than assumed from `docs.wompi.co` (Colombia) — the
two products are meaningfully different, documented in Part D. Every
Wompi claim below cites the specific page it came from.

---

## Part A — Domain ownership verification

This is the non-negotiable gate: without it, the API is an unauthorized
scanning-as-a-service vector against arbitrary third-party domains, with
real legal exposure for the operator. No scan against a domain may be
queued — not even the first one — until that domain has a **current**
verification record tied to the requesting account.

> **Implemented in Round 2** (see "Round 2 implemented" below for the
> full writeup, tests, and live demonstration). A.1 and A.4 below were
> implemented exactly as drafted. **A.2 and A.3's final decisions differ
> from the draft text below** — the draft proposed a 30-day freshness
> window with automatic re-verification and a "current control always
> wins" transfer policy; Round 2 instead shipped a 90-day expiry with no
> automatic re-check and a "first successful verification wins, second
> account gets a conflict" policy. Both are simpler, deliberately-chosen
> alternatives — see "Round 2 implemented" for the reasoning — and the
> text in A.2/A.3 is kept below as the original design record, not
> silently rewritten.

### A.1 Mechanism: both DNS TXT and well-known file, client's choice

Support both, exactly as the two most common patterns (Google Search
Console's DNS-TXT method, and the ACME/`well-known` HTTP method) already
do, for the same reason those two ecosystems both offer both: which one
is *practical* depends entirely on the client's own infrastructure. A
client behind an enterprise change-control process for DNS but with
direct FTP/deploy access to their web root will find the file trivial and
the DNS record a multi-week ticket; a client on a DNS-only CDN
(Cloudflare-in-front, no direct file access) has the exact opposite
constraint. Offering only one method turns an authorization step into a
support bottleneck for whichever half of clients didn't get the
convenient option.

**Token**: one opaque, per-`(account_id, domain)` token, generated when
the client registers intent to verify a domain
(`POST /domains {"domain": "example.com"}` → returns the token and both
sets of instructions). Format: `hydra-verify-<32 hex chars>`
(cryptographically random, not derived from the domain or account — a
derivable token would let anyone guess it and self-verify a domain they
don't control).

**DNS TXT method**: the client adds

```
_hydra-verify.example.com.  TXT  "hydra-verify=<token>"
```

A dedicated `_hydra-verify` subdomain label, not a TXT record on the bare
domain — the bare domain's TXT records are usually already occupied by
SPF/DKIM/domain-verification records from other services, and colluding
with those is both fragile (a client's next SPF edit could silently break
verification) and gives Hydra no clean way to later verify a specific
*subdomain* independently, which the tier/scope model may eventually
need.

**Well-known file method**: the client publishes

```
https://example.com/.well-known/hydra-verification.txt
```

containing exactly the token, nothing else, served as `text/plain`.

**Verification is always an active check Hydra performs itself** —
`POST /domains/{domain}/verify` triggers a live DNS query (via a resolver
Hydra controls, not client-supplied) or a live HTTPS GET to the
well-known path, at the moment of the call. The API never accepts "I've
added it, mark me verified" from the client directly; a verification
record is only created as the side effect of Hydra's own successful
active check. This mirrors the project's existing principle
(`docs/VERIFICATION_AGENT_DESIGN.md` §0): don't trust an interpretation,
actively re-check it against the raw source.

### A.2 One-time or periodic? — periodic, with a defined grace window

One-time verification is not sufficient: a domain can change hands (sold,
DNS delegated to a new party, lease expired) after the original client
loses interest or forgets to cancel, and Hydra would keep authorizing
scans against infrastructure the original account no longer controls.

Design: a verification record has a `verified_at` timestamp and is
considered **fresh** for 30 days. Any `POST /scans` (or `engagement`
equivalent) against a domain checks freshness first:

- Fresh (`< 30 days`): proceed, no new check performed (an active check
  on every single scan would be wasteful and, for the well-known-file
  method, indistinguishable from Hydra's own reconnaissance traffic
  against the target — better to keep verification and scanning
  temporally separate events).
- Stale (`≥ 30 days`): Hydra automatically re-runs the same active check
  (TXT or file, whichever method is on record) **before** queuing the
  scan, transparently. Success refreshes `verified_at`; the scan
  proceeds. Failure blocks the scan with a clear "domain verification has
  lapsed — re-verify at `/domains/example.com/verify`" error, and emails
  the account. Already-completed reports/scans for that domain are never
  deleted or hidden because verification lapsed — the client already
  paid for and owns that historical data; only *new* scans are gated.

### A.3 Two accounts, same domain — the takeover-transfer case

If Account B successfully completes an **active** verification for a
domain Account A currently holds a fresh verification for, treat B's
success as authoritative and immediately supersede A's — not "first
claimant wins forever," but "whoever currently controls the DNS/web root
wins," because only the current controller can produce a fresh, valid
proof for either method. This matches how domain-control verification
works everywhere else (Search Console, Let's Encrypt/ACME): control at
time of check is the only thing ever actually proven; a prior successful
check proves nothing about who controls the domain *now*.

Concretely:
1. B's verification succeeds → B's record for `example.com` is created,
   marked fresh.
2. A's existing record for the same domain is immediately marked
   `superseded` (not silently deleted — kept for audit).
3. Both accounts are emailed: A is told verification for `example.com`
   was reclaimed by another account and any scheduled/future scans
   against it are now blocked for A; B is told they're now the verified
   owner.
4. This event is written to a dedicated security-audit log
   (`domain_verification_events`) — account IDs, domain, method, IPs,
   timestamps for both the original and superseding verification — since
   this is precisely the kind of event a legal dispute over "who
   authorized this scan" would need to reconstruct.

Two accounts *concurrently attempting* verification for the same domain
(neither yet successful) is not itself a conflict — both are just making
unproven claims; only a **successful active check** creates or transfers
authorization. Rate-limit verification *attempts* per domain across all
accounts (not just per-account) to slow down any attempt to brute-force
or race the check.

### A.4 Root domain vs. subdomains

Verifying `example.com` authorizes scans against `example.com` and
`*.example.com` — consistent with how Hydra's existing scope engine
already treats a bare domain entry in `scope.txt`
(`core/intel/scope.py`, `CollectionScope`). This is not a new policy
invented for the API; it's the existing single-tenant scope semantics
reused, and every scan request's target is checked against the account's
verified-domain set through that same scope engine, not a
separately-invented API-layer allowlist.

---

## Part B — Tier model

Three tiers, each with real technical ceilings behind the price, not just
a price:

| | **Starter** | **Pro** | **Agency** |
|---|---|---|---|
| Scans (`run`/`engagement`) per month | 5 | 30 | 150 |
| Concurrent scans | 1 | 3 | 10 |
| `assess-reportability` / `suggest-hypotheses` | **Not included** | Included, capped | Included, capped |
| Monthly LLM spend ceiling (Hydra's own Anthropic/OpenAI cost, not client price) | $0 | $15 | $75 |
| Adversarial cross-validation (`--adversarial-provider`) | N/A | Off by default, enable for +50% of the ceiling's consumption rate | On by default |
| `client-report` (Markdown/docx, both languages) | Included | Included | Included |
| Historical data retention | 30 days | 180 days | 24 months |
| Verified domains | 3 | 15 | Unlimited |
| API keys per account | 1 | 5 | Unlimited |

**Why Starter excludes the LLM features entirely, rather than giving it a
tiny budget**: a $0 ceiling is a hard, unambiguous product boundary that
needs zero runtime enforcement subtlety — the endpoint simply isn't
reachable for that tier (`403`, "upgrade to Pro"). A small-but-nonzero
budget (say $2) sounds more generous but is the actual dangerous case the
task called out: it's easy for a single `assess-reportability` call
against a large finding batch to blow past a few dollars in one request
(cost scales with `findings × rules-text length`, and the existing CLI
already warns operators about this — see the "no free token-count
endpoint" caveat in `core/reportability/cli.py`), so a "cheap tier"
that's technically allowed to use it can go negative for the operator on
its very first LLM call. Zero is the only ceiling that can't be
accidentally exceeded.

**How the spend ceiling is actually enforced — reusing the CLI's own
cost-estimate code, not a new estimator**: `core/reportability/cli.py`
already computes a real pre-call token estimate
(`primary.count_input_tokens(...)`, `core.llm.client.cost_line`) before
ever spending anything, specifically so the CLI can show the operator a
number before asking for confirmation. The API reuses the exact same
call:

1. Compute the estimate (no API spend yet).
2. Check `estimate ≤ (monthly ceiling − already-consumed this month)` for
   the account.
3. If over ceiling: refuse with `402`-equivalent
   ("`reportability_budget_exceeded`"), and **never** silently degrade
   (e.g., truncate the batch) or auto-bill an overage — the client
   explicitly chooses what happens next (see below).
4. If within ceiling: proceed, and after the real provider response comes
   back, deduct the **actual** billed cost (not the pre-call estimate,
   which is necessarily approximate for OpenAI per the CLI's own
   documented caveat) from the account's monthly counter. The estimate
   only gates the go/no-go decision; the ledger is always the real
   number.

**What happens at the ceiling — block, never auto-overage-bill**: matches
the project's existing fail-closed philosophy for money
(`docs/REPORTABILITY_AGENT_DESIGN.md`: never spend without an explicit
yes). The client is offered exactly two paths, both requiring an
explicit action: upgrade the account's tier (changes the recurring
subscription — Part D), or purchase a one-off top-up
(a separate, non-recurring Wompi charge — also Part D) that raises the
ceiling for the remainder of the current billing month only. Neither
happens automatically.

**Retention**: shorter retention on cheaper tiers is a real infrastructure
cost control (raw per-tool JSONL artifacts for a 25-minute scan against a
large attack surface are not small), enforced by a scheduled job that
purges `output/<run_id>/` artifacts and rows past the account's retention
window — never mid-scan, and the purge itself should be logged (what was
deleted, when, for which account) for the same audit-trail reasons as
Part A.3.

---

## Part C — `X-API-Key` authentication

**Format**: `hydra_live_<43 base62 chars>` / `hydra_test_<...>` — a
visible prefix distinguishing sandbox from production keys (the same
convention Stripe/similar payment-adjacent APIs use), so a key pasted
into the wrong environment is visually obvious before it's even used, and
so sandbox keys can be routed to Wompi's sandbox environment / a stubbed
scan pipeline without an extra lookup.

**Storage**: only a salted hash (e.g. Argon2id) of the key is ever
persisted — the same principle as password storage, not reversible
encryption. The raw key is shown to the client exactly once, at creation
time, in the API response; it is never retrievable again (only
revocable/rotatable).

**Association**: a key belongs to exactly one account; the account, not
the key, carries the tier. An account may hold multiple active keys
simultaneously (Starter: 1, up to Agency: unlimited, per Part B) — e.g.
one key for a CI pipeline, a separate one for a dashboard integration —
each independently named, tracked (`last_used_at`), and revocable without
touching the others or the account itself.

**Rotation/revocation**: revoking a key immediately fails every request
authenticated with it (`401`), and affects nothing else on the account —
no other key, no active scans already queued under a *different* key
authenticated the request that queued them, no subscription status.
"Rotate" is sugar over "create new key, then revoke the old one after a
24-hour dual-validity window," so an in-flight deployment holding the old
key in an environment variable doesn't hard-fail the moment rotation
happens.

**Rate limiting — independent of tier quota**: a per-key sliding-window
limit (e.g., a token-bucket counter in a fast in-memory store, keyed by
the key's hash) caps raw request *rate* — protection against a leaked key
being hammered, or automated polling misuse of `GET /scans/{id}` —
completely separate from the tier's monthly *scan* quota, which lives in
the durable database and resets monthly. The two failure modes must
produce visibly different errors (`429 rate_limited` vs.
`403 scan_quota_exceeded`) so a client can tell "you're going too fast"
apart from "you're out of scans this billing period" without guessing.

---

## Part D — Wompi integration (verified against `docs.wompi.sv`)

**This section's central finding, worth stating up front**: El
Salvador's Wompi product for recurring billing (`EnlacePagoRecurrente`)
is a **shared, merchant-created enrollment link**, not a per-customer
subscription API call. This is materially different from what the
Colombia-specific bank-integration features (Bancolombia/Daviplata) might
have implied, and it shapes the whole billing design below. Confirmed by
reading `docs.wompi.sv/metodos-api/crear-enlace-pago-recurrentes.md`
directly (not assumed).

### D.1 How `EnlacePagoRecurrente` actually works

```
POST /EnlacePagoRecurrente
{
  "diaDePago": 1,              // day-of-month all subscribers are billed
  "nombre": "Hydra Pro",
  "idAplicativo": "<wompi app id>",
  "monto": 99.00,
  "descripcionProducto": "Hydra EASM — Pro tier, monthly"
}
```

returns `urlEnlace` (a shareable enrollment URL) and `urlQrCodeEnlace`.
The merchant creates **one such link per pricing tier** (three links
total: Starter/Pro/Agency — Starter is $0 and needs no Wompi link at
all), not one per customer. A customer enrolls by visiting that shared
URL and explicitly accepting terms on Wompi's own hosted page — Wompi
collects and stores the card there; **Hydra's backend never receives or
touches raw card data for the recurring-billing path**, satisfying the
"never store card data" requirement structurally, by construction, rather
than by discipline. Once enrolled, Wompi auto-charges the subscriber's
card on `diaDePago` every month without further action from Hydra.

**A real, non-obvious consequence of the shared-link model**: `diaDePago`
is a property of the *link* (the tier), not of the individual subscriber.
Every subscriber to the Pro tier is billed on the same calendar day,
regardless of when they signed up. A customer who enrolls on the 20th
either (a) gets a partial first period free until the next billing day,
or (b) is charged a separate, explicit one-off prorated amount via the
*different* one-off endpoint (`POST /EnlacePago` or
`POST /TransaccionCompra`, both of which do carry a per-transaction
`identificadorEnlaceComercio` the recurring endpoint's request body does
not) to cover the gap, before their recurring enrollment's first regular
charge lands. Recommend (a) for the MVP — it's simpler, costs the
operator at most one partial-month's revenue per new signup, and needs no
extra one-off-charge orchestration at signup time.

**Open item to verify against a real Wompi sandbox account before Part
2**: the recurring link's own webhook/subscriber-list payload
(`GET /EnlacePagoRecurrente/{id}/suscripciones`) was only documented as
an endpoint *name* in the table of "other available endpoints," with no
example response body shown. The generic transaction webhook (below)
identifies a payer only by free-form `cliente.Nombre`/`cliente.Email`
fields — there is no confirmed merchant-injectable per-subscriber
identifier on this specific product the way `identificadorEnlaceComercio`
exists on the one-off link product. Part 2 must confirm, empirically,
exactly what identifies *which Hydra account* a given recurring-charge
webhook belongs to (candidate approach: require the email used at Wompi
enrollment to exactly match the Hydra account's registered email, and
reconcile by email at webhook-receipt time — flagged here as an
assumption to verify, not a confirmed mechanism).

### D.2 Webhook confirmation — never trust the frontend

Wompi calls the merchant's registered webhook URL with an HTTP POST on
every successful transaction (recurring charges included, since each
monthly charge is itself a transaction):

```json
{
  "IdCuenta": "...", "IdTransaccion": "...", "Monto": 99.00,
  "ResultadoTransaccion": "ExitosaAprobada",
  "EnlacePago": {"Id": 66, "NombreProducto": "Hydra Pro"},
  "cliente": {"Nombre": "...", "Email": "..."}
}
```

(`docs.wompi.sv/webhook/definicion-webhook.md`). The API key/tier upgrade
is activated **only** by this webhook arriving and validating, never by
anything the client's browser/frontend reports about its own payment flow
— a compromised or simply buggy frontend claiming "payment succeeded" is
not evidence of anything.

**Validation** (`docs.wompi.sv/webhook/validar-webhook.md`, confirmed):
every webhook carries a `wompi_hash` header — HMAC-SHA256 of the exact
raw request body, keyed with the merchant's Wompi API secret. Hydra must
read the body as literal bytes (no reformatting/re-serializing before
hashing) and compare. As a second, independent check, Wompi's own docs
recommend also calling `GET /TransaccionCompra/{IdTransaccion}` to
confirm the transaction exists and is approved before acting on it —
belt-and-suspenders against a forged webhook that somehow guessed or
leaked a valid-looking HMAC. Do both.

### D.3 Payment failure / Wompi outage handling

- **Missed or failed charge** (webhook reports non-success, or no
  success webhook arrives by end of the expected billing day): start a
  3-day grace period. During grace, existing API keys and already-queued
  scans keep working (a client shouldn't lose access over a single
  declined card while they're actively investigating something) and the
  account is emailed "payment past due." If unresolved by the grace
  deadline: **suspend**, not delete — `POST /scans` starts returning
  `402`, but `GET` on already-completed reports keeps working
  indefinitely (the client already paid for that data; withholding
  already-delivered results over a *later* billing failure is a
  different, harder-to-justify penalty than blocking new work).
- **Wompi itself unreachable** around an expected billing date (Hydra
  can't confirm success *or* failure): treat as **unknown**, not failure
  — never suspend an account because a third-party dependency, not the
  client, is down. Extend the grace window defensively and reconcile via
  a scheduled job that re-queries Wompi's transaction/subscriber-list
  endpoints once reachable again.

### D.4 Card data — tokenization, never raw storage

For the recurring-tier subscription flow (D.1), Hydra never sees card
data at all — it's entered directly on Wompi's hosted enrollment page.
For one-off LLM-budget top-ups (Part B), if a saved-card "one click
top-up" experience is wanted later, use Wompi's own
`POST /Tokenizacion` (`docs.wompi.sv/metodos-api/tokenizacion.md`) — the
client's card is tokenized by Wompi directly from their browser, and only
Wompi's token (plus, per-transaction, the CVV) is ever sent to Hydra's
backend for a subsequent charge. Hydra's database stores the Wompi token
identifier, never a PAN, never a full card number, never a stored CVV
(CVVs are one-time-use per transaction by card-network rule and must
never be persisted regardless of tokenization).

### D.5 API-level auth to Wompi itself

Wompi's own API (distinct from the client-facing Hydra API) uses OAuth2
client-credentials (`docs.wompi.sv/autenticacion/autenticacion.md`):
Hydra's backend exchanges its Wompi `client_id`/`client_secret` for a
short-lived access token at `https://id.wompi.sv/connect/token`, cached
and refreshed server-side — this credential pair is an operator secret
(environment variable / secrets manager), never exposed to any Hydra API
client.

---

## Part E — Async scan model

Scans take ~25 minutes; nothing in this API can be a synchronous
request/response.

```
POST /scans {"domain": "example.com", "options": {...}}
  → 202 Accepted {"scan_id": "...", "status": "queued"}

GET /scans/{scan_id}
  → {"status": "queued"|"running"|"completed"|"failed", "progress": {...}}

GET /scans/{scan_id}/report
  → 409 if status != "completed"; otherwise the run's summary/report data
```

`POST /scans` performs the Part A domain-verification-freshness check and
the Part B/C quota/rate checks synchronously (fast, in-request) before
ever queuing pipeline work — a scan that will be rejected for
authorization or quota reasons should fail immediately with a clear
error, not silently sit in a queue and fail later. Internally, `scan_id`
maps 1:1 to the existing pipeline's own `run_id`
(`PipelineRunner`/`AssetStore` — no new run-identity concept is invented,
the API just exposes the existing one under tenant scoping, per Part F).

### E.1 Translating the CLI's `[y/N]` cost gate to HTTP

The CLI's interactive confirmation
(`Proceed with this assessment? [y/N]:`) has no HTTP equivalent — there's
no terminal to block on, and no session state between two HTTP calls the
way a single CLI process has between printing an estimate and reading the
next line of stdin. The one interactive flow becomes two separate,
stateless calls:

```
GET /scans/{scan_id}/reportability-estimate?program_rules_id=...
  → {"estimate_id": "...", "estimated_cost_usd": 0.42, "expires_at": "..."}
  (no spend; safe to call repeatedly)

POST /scans/{scan_id}/reportability-assessment
  {"estimate_id": "...", "confirm": true}
  → only proceeds if confirm is explicitly true AND estimate_id is
    still valid (not expired, not already consumed) — anything else
    (missing confirm, confirm: false, expired/reused estimate_id) is a
    400, never an implicit "sure, go ahead."
```

`estimate_id` binds the confirmation to the *specific* priced estimate
the client saw (short-lived, e.g. 10 minutes, single-use) — without it, a
confirm call would be trusting a cost number the client claims they saw
rather than one Hydra actually just computed, reopening exactly the kind
of "don't trust the frontend's claim" problem Part D.2 already solved for
payment webhooks. The same pattern — estimate token, then explicit
confirm — applies identically to `suggest-hypotheses`.

`client-report` has no cost gate (it's free, local, no LLM) — it's a
plain `POST /scans/{scan_id}/client-report {"format": "markdown"|"docx",
"language": "en"|"es"}` returning the generated document directly, same
`--language`/`--format` semantics as the CLI command it wraps
(`core/client_report/cli.py`).

---

## Part F — Multi-tenancy as a structural guarantee, not a convention

### F.1 The existing single-tenant discipline, extended one level

`core/intel/cli.py`'s query functions already never let a caller
implicitly query "whatever run" — `open_query(db_path, run_id, ...)`
takes `run_id` as a mandatory, explicit parameter everywhere, precisely
so a new query function can't be added later that forgets to scope by
run. Multi-tenancy needs the identical discipline one level up:
`account_id` must be a mandatory, explicit, non-optional parameter on
every repository/query function that touches tenant data — never a
default, never inferred, never "add the WHERE clause later." A code
review checklist item is not a structural guarantee; a function signature
that doesn't compile without it is.

### F.2 Storage isolation: one SQLite file per account, not one shared DB with row filtering

This is the concrete, repository-specific recommendation, not generic
SaaS advice: `core/store.py`'s `AssetStore` already assumes exactly one
`recon.db` per Hydra "installation." Rather than migrating to Postgres
with row-level security (a real, valid pattern, but a much larger Part-2
lift that touches every existing query), the recommended MVP path is
**one SQLite file per `account_id`**, opened by whichever file path the
authenticated request resolves to. This is a *stronger* isolation
guarantee than a shared database with a `WHERE account_id = ?` filter or
even Postgres RLS — there is no filter to forget, and no policy to
misconfigure, because a connection opened against Account A's file
physically cannot return Account B's rows; the failure mode "the filter
was missing on this one query" is categorically impossible rather than
merely policed. It also means **zero changes to `core/runner.py`,
`AssetStore`, `PipelineRunner`, or any existing pipeline internals** —
the entire existing, already-tested single-tenant engine runs unmodified;
the API layer's only new responsibility is resolving `account_id → db
path` immediately after authentication and threading that path through,
exactly the way `settings.output_directory` already gets threaded through
every command today.

Trade-off, stated honestly: cross-account operator-facing analytics
("how many total scans ran this month across all customers") need a
separate aggregation step (a small metadata table outside any per-account
file, updated by each scan's completion) rather than a single SQL query
across tenants — an acceptable cost for an MVP, and revisit
Postgres+RLS if/when that kind of cross-tenant reporting or heavier
concurrent-write volume actually materializes.

### F.3 `run_id`/`scan_id` is never trusted bare

Even with per-account file isolation, a `scan_id` in a URL path
(`GET /scans/{scan_id}`) must never be used to open a database file
without first confirming, via a small central `scans` metadata table
(account_id, scan_id, db_path), that the *authenticated* account_id owns
that scan_id. This catches the case where per-account file isolation
alone wouldn't: an authenticated request accidentally (or maliciously)
supplying a `scan_id` string that happens to collide with, or in a future
refactor is used to construct, a path outside the caller's own file. Two
independent checks — "which file does this account's data live in" and
"does this account actually own this specific scan_id" — rather than
relying on either one alone.

### F.4 Domain verification and account-scoping compose

Part A already scopes domain-verification records by `account_id`; Part
F's isolation guarantee means Account A's verified-domains list is a
query against *its own* file, so there's no code path where Account B's
verification status for a domain is even reachable within a request
authenticated as Account A — the two systems reinforce each other rather
than needing to separately duplicate an authorization check.

---

## Sources consulted (docs.wompi.sv, not docs.wompi.co)

- https://docs.wompi.sv/metodos-api/crear-enlace-pago-recurrentes.md — recurring-link request/response shape, `diaDePago` semantics
- https://docs.wompi.sv/metodos-api/enlace-de-pago.md — one-off payment link, `identificadorEnlaceComercio`/`configuracion.urlWebhook` (absent on the recurring endpoint)
- https://docs.wompi.sv/webhook/definicion-webhook.md — webhook payload shape
- https://docs.wompi.sv/webhook/validar-webhook.md — HMAC-SHA256 `wompi_hash` validation, transaction-lookup double-check
- https://docs.wompi.sv/metodos-api/tokenizacion.md — card tokenization endpoint
- https://docs.wompi.sv/autenticacion/autenticacion.md — OAuth2 client-credentials flow for Hydra→Wompi API auth
- https://docs.wompi.sv/llms.txt — full documentation index (used to confirm no per-customer subscription-creation endpoint exists beyond the shared recurring-link model)

---

## Round 1 implemented (`api/`) — Parts C, E, F

Round 1 built the multi-tenant core, `X-API-Key` auth, and the async scan
lifecycle — Parts A (domain-ownership verification), B (tiers/quotas),
and D (Wompi) are deferred to Rounds 2/3. **Any authenticated account can
scan any domain without restriction right now** — that is intentional
scope for this round, not an oversight; it lets the core plumbing be
proven before authorization/billing complexity sits in front of it.

### Framework choice, confirmed against current docs, not memory

FastAPI (`fastapi==0.141.1`, `uvicorn[standard]==0.53.0`) — confirmed
directly against `fastapi.tiangolo.com` before pinning: actively
maintained (a 2026 FastAPI Conf is scheduled), native `async def` request
handlers, and `uvicorn` as its own documented recommended ASGI server.
The scan orchestration itself uses a plain `asyncio.create_task` (no
Celery/RQ + Redis) — see "Known Round 1 limitations" below for exactly
what that trades away.

### Repo layout

`api/` is a separate, independently-deployable package — never imported
by `app.py`, and it imports `app.py`'s own `_external_mode_preflight` /
`_run_headless_pipeline` (deferred, inside `api/scan_orchestrator.py`)
rather than reimplementing pipeline orchestration. `core/client_report/`
is reused directly for `POST /scans/{id}/client-report` — that endpoint
calls the exact same `cmd_client_report` the CLI does.

### Running it locally

```bash
pip install -r requirements.txt -r requirements-api.txt -r requirements-dev.txt
```

**Important, and easy to miss**: the Python `httpx` package (needed only
for `fastapi.testclient.TestClient` in tests) installs a console script
also named `httpx`. `pip install httpx` — no extra, exactly as pinned —
already creates it: confirmed directly via `importlib.metadata` that the
`console_scripts` entry point is unconditional package metadata, not
gated behind the `cli` extra (only its runtime dependencies —
`click`/`rich`/`pygments` — are). There is no pip flag that avoids this;
it is a real, unavoidable name collision with the ProjectDiscovery
`httpx` recon binary this project also shells out to
(`modules/httpx.py`), not a configuration mistake.

**This does not put real scans at risk.** `core/dependencies/service.py`
already has multi-candidate discovery + identity-marker validation
specifically built for this — its own comment says "handles httpx vs
python-httpx" — and `httpx`'s `ToolDefinition`
(`core/dependencies/registry.py`) already declares
`identity_markers=("projectdiscovery", ...)` plus a `path_denylist`
covering `.venv`/`site-packages`/`Python.framework`. Any real
`PipelineRunner`/`ToolManager`-driven run (`app.py run`, `engagement`,
and this API's own scan orchestration) resolves and verifies the genuine
binary regardless of the shim — confirmed with a real impostor script in
`tests/test_dependency_binary_identity.py`, not just by reading the code.

The narrow gap is test code that constructs a plugin/`Settings` directly,
bypassing `ToolManager` on purpose to test something else (confinement-
proxy behavior, not tool discovery) —
`tests/test_httpx_confinement_live.py`,
`tests/test_redirect_destination_oracle.py`, and
`tests/test_followup_adversarial_oracle.py` originally did this and
inherited the raw-PATH vulnerability as a side effect the first time this
dependency was added (10 failures, confirmed as this exact cause). They
now use the `verified_httpx_path` fixture (`tests/conftest.py`) — which
reuses that same production discovery/validation — to get the same
protection explicitly, so **no manual remediation is required** for the
test suite to pass correctly regardless of the shim's presence. If you
want the shim gone from your shell for ad-hoc `httpx` command-line use
anyway, it's harmless to remove:

```bash
rm .venv/bin/httpx    # optional — the test suite no longer depends on this
```

Then run the service:

```bash
uvicorn api.main:app --reload
# or, to control where account/scan data is stored:
HYDRA_API_DATA_DIR=/path/to/data uvicorn api.main:app --reload
```

### Creating an account and a first key

Round 1's `POST /accounts` is deliberately unauthenticated — there is no
tier or billing gate to sit behind yet (Rounds 2/3). **This must be
removed or gated behind payment/tier logic before this service is ever
exposed publicly** (also stated in `api/routers/accounts.py`'s own
module docstring, so it isn't missed when Part D lands):

```bash
curl -s -X POST http://127.0.0.1:8000/accounts
# {"account_id": "...", "api_key": "hydra_live_...", "key_id": "..."}
```

Save `api_key` now — it is never retrievable again, only revocable
(`POST /keys/{key_id}/revoke`) or rotated with a 24h dual-validity window
(`POST /keys/{key_id}/rotate`).

### Full cycle — real sequence of calls and responses

Captured from a real `uvicorn` process actually running on
`127.0.0.1`, hit with real `curl` requests over a real TCP socket. The
scan's own network collectors (subfinder/dnsx/httpx) were stubbed at the
plugin-class boundary — the same "fixture fiel" pattern
`tests/test_api_scans.py` uses — purely so this demonstration finishes in
seconds instead of ~25 minutes; everything from the HTTP layer down
through the control-plane database, per-account SQLite isolation, and
`client-report` generation is the real, unstubbed production path.

```
$ curl -s -X POST http://127.0.0.1:8124/accounts
{"account_id":"365e63d7fe988a6f49f08356b2a5b8e6","api_key":"hydra_live_e2cd76050d450109ba79236e0b7c12593bfa940e23b4b6c179be306262060f6d","key_id":"4917a887f85a499688d1ecd2ca9ac71d"}
HTTP_STATUS:201

$ curl -s -X POST http://127.0.0.1:8124/scans \
    -H "X-API-Key: hydra_live_e2cd76050d450109ba79236e0b7c12593bfa940e23b4b6c179be306262060f6d" \
    -d '{"domain": "demo-target.example"}'
{"scan_id":"e0affa088c9c19f09b26ea3336456154","status":"queued"}
HTTP_STATUS:202

$ curl -s http://127.0.0.1:8124/scans/e0affa088c9c19f09b26ea3336456154 \
    -H "X-API-Key: hydra_live_e2cd..."
{"scan_id":"e0affa088c9c19f09b26ea3336456154","domain":"demo-target.example","status":"completed", ...}
HTTP_STATUS:200

$ curl -s http://127.0.0.1:8124/scans/e0affa088c9c19f09b26ea3336456154/report \
    -H "X-API-Key: hydra_live_e2cd..."
{"targets_count":1,"subdomains_count":1,"resolved_count":1,"alive_count":1, ...}
HTTP_STATUS:200

$ curl -s -X POST http://127.0.0.1:8124/scans/e0affa088c9c19f09b26ea3336456154/client-report \
    -H "X-API-Key: hydra_live_e2cd..." -d '{"format":"markdown","language":"en"}'
Security Report — demo-target.example
...
## What You Need to Know

No vulnerability was confirmed with real evidence of impact in this review. ...
HTTP_STATUS:200

# A second account, with the EXACT same scan_id, gets a plain 404 — the
# scan effectively doesn't exist from its point of view:
$ curl -s -X POST http://127.0.0.1:8124/accounts   # second, unrelated account
{"account_id":"c34387bcaaab0d7af8091c34a0f896c4", "api_key": "hydra_live_787ff3...", ...}
$ curl -s http://127.0.0.1:8124/scans/e0affa088c9c19f09b26ea3336456154 \
    -H "X-API-Key: hydra_live_787ff3..."
{"detail":"Scan not found"}
HTTP_STATUS:404
```

A real (non-stubbed) attempt against `example.com` was also run during
this round's verification — it correctly progressed through
`queued → running` (real WHOIS + subfinder execution, visible in the
server's own logs) before ultimately failing with a genuine `dnsx`
timeout under external-target-mode's conservative rate limiting, the
same characteristic already documented from this project's Docker
Quickstart validation (a similar public domain returned 22,000+
subdomains for that same conservative-rate-limit machinery to resolve
within its timeout). That's a real, expected pipeline characteristic for
a large attack surface under conservative defaults, not an API bug — the
scan's `status` correctly transitioned to `"failed"` with a real,
specific `error_message`, which is exactly the behavior `GET /scans/{id}`
exists to surface.

### Known Round 1 limitations (stated explicitly, not silently assumed away)

- ~~Scan orchestration is single-process, in-memory~~ — **resolved**, see
  "Durable, multi-worker-safe scan execution" below: scans now run on a
  SQLite-backed queue (`api/scan_worker.py`), and a scan interrupted by a
  worker crash or restart is automatically requeued and re-executed
  (bounded by a retry ceiling), not abandoned at `"running"` forever.
- ~~Rate limiting is single-process, in-memory~~ — **resolved**, same
  section: `api/rate_limit.py::PersistentTokenBucketLimiter` persists
  bucket state in `control.db`, enforcing the same limit whether one
  `uvicorn` worker process serves a key's requests or several do, and
  surviving a restart instead of resetting.
- **`POST /accounts` is unauthenticated** — narrowed since Round 1
  (per-IP rate limited, email-verification-gated before anything can
  scan — Hallazgo 1), but still no tier/billing gate of its own; still
  worth hardening further before wide-open public exposure.

### Tests

`tests/test_api_auth.py` (account/key creation, revocation, the 24h
rotation dual-validity window — tested by moving `expires_at` into the
past directly in the control DB rather than sleeping a day or mocking
`datetime.now()` globally —, and per-key rate limiting), plus
`tests/test_api_scans.py`/`tests/test_api_client_report.py` (full async
scan lifecycle, cross-account isolation with the exact same `scan_id`,
and byte-for-byte parity between the API's `client-report` endpoint and
calling `cmd_client_report` directly against the same account data).

Also added as part of this round's own httpx-shadowing incident (see
above): `tests/test_dependency_binary_identity.py`, which exercises
`core/dependencies/`'s pre-existing impostor-rejection mechanism with a
real fake binary — confirming a same-named script that runs successfully
but isn't the genuine tool is rejected with a clear reason, and that a
genuine binary reachable elsewhere is still correctly selected even when
an impostor scores as the first PATH candidate. That mechanism predates
this round; it simply had no test coverage before now.

## Round 2 implemented (`api/`) — Part A, domain ownership verification

Round 2 closes the gap Round 1 left open on purpose: `POST /scans` now
**rejects** any domain the requesting account has not currently verified,
with a `403` and a clear message on how to fix it. This lives in the same
mandatory-`account_id` code path as Round 1's scan-ownership checks
(`api/routers/scans.py`'s `_require_verified_domain_or_403`, called from
`create_scan` before any scan row is created) — not a separate
middleware/dependency layer a future route could add without remembering
to include it.

### A.1/A.4 — implemented exactly as drafted

Both DNS TXT and well-known-file methods, client's choice
(`api/domain_verification.py`). `POST /domains {"domain": "example.com"}`
generates a per-`(account_id, domain)` token (`secrets.token_hex(16)`)
and returns both sets of instructions; `POST /domains/{domain}/verify`
performs a real, live check — a real DNS query via `dnspython`
(`dns.asyncresolver`) against `_hydra-verification.<domain>` for the TXT
method, or a real `httpx.AsyncClient` HTTPS GET against
`/.well-known/hydra-verification-<token>.txt` for the file method. The
API never trusts a client's claim that a record/file exists; a
verification record is only ever created as the side effect of Hydra's
own successful active check, exactly as A.1 specifies. Verifying
`example.com` covers `*.example.com` (A.4), reusing the same
`domain_is_covered` prefix-match semantics as `CollectionScope`'s
existing bare-domain convention — tested explicitly, including the
`notexample.com` vs `example.com` false-positive-prefix edge case.

### A.2 — decided: 90-day expiry, no automatic re-check per scan

The draft above proposed a 30-day window with Hydra automatically
re-running the active check on every stale scan request. Round 2 instead
ships:

- A verification is valid for **90 days** from `verified_at`
  (`DEFAULT_EXPIRY_DAYS` in `api/domain_verification.py`).
- `POST /scans` checks only the **persisted** status/expiry
  (`ControlDB.get_verified_domains_for_account` /
  `get_all_verifications_for_account`, joined in
  `classify_scan_gate`) — it never performs a live DNS/HTTP check as a
  side effect of queuing a scan.
- Expired: the scan is rejected with a `403` that explicitly says
  *expired* (distinct from *never verified*) and names the expiry date,
  telling the client to `POST /domains/{domain}` again to restart
  verification.

**Trade-off, stated explicitly**: this is less safe than a live
re-check on every stale scan (a domain could theoretically change hands
within the 90-day window without Hydra noticing until the next scan
attempt lands after expiry) but is simpler, cheaper, and avoids exactly
the problem A.2's own draft text flagged with the well-known-file method
— an automatic re-check performed as a side effect of an unrelated
`POST /scans` call is indistinguishable, from the target's perspective,
from Hydra's own reconnaissance traffic starting early. 90 days (versus
the draft's 30) reduces how often a legitimate, still-owning client is
interrupted, at the cost of a longer window before a genuine transfer is
caught — judged an acceptable trade for this round given verification
is re-checked at the top of every registration/verify call anyway,
never silently assumed forever.

### A.3 — decided: first successful verification wins; second account sees a conflict

The draft above proposed "current control always wins" (a second
account's successful check silently supersedes the first). Round 2
instead ships **first-verification-wins**:

- `ControlDB.get_active_verification_for_domain(domain)` is checked,
  cross-account, at the moment a *second* account's active check
  succeeds (`POST /domains/{domain}/verify` in
  `api/routers/domains.py`).
- If another account already holds a current, unexpired verification
  for that domain, the second account's otherwise-successful check is
  rejected with `409 Conflict` — `"... already verified by another
  account"` — and no record is created or superseded for either
  account.
- The original account's verification is untouched; nothing is emailed
  or superseded, because nothing changed.

**Why this differs from the draft, and from the general "current
control wins" instinct**: this round's task explicitly called for
treating same-domain-two-accounts as the anomalous case it almost always
actually is (a support/dispute situation, not a routine transfer) rather
than an automatic, silent hand-off — silently reassigning a domain's
verified-owner status the moment *any* other account can pass the same
public check removes the original account's ability to notice or
dispute it before their authorization is revoked. A genuine transfer
(the previous owner deliberately gave up the domain) is handled instead
by the *original* account's verification simply expiring at the 90-day
mark (A.2) and the new controller registering and verifying normally
once nothing active blocks them — slower, but never silent. Documented
in full, with this same reasoning, in `api/domain_verification.py`'s
module docstring next to `classify_scan_gate`.

### Dev/test override — explicit, off by default

`api/settings.py`'s `dev_dns_nameserver` / `dev_dns_port` /
`dev_well_known_base_url` let tests (and only tests) point the real
DNS/HTTP checks at a local test server instead of the live internet —
all three default to `None` and are only ever set via the explicit
`HYDRA_API_DEV_DNS_NAMESERVER` / `HYDRA_API_DEV_DNS_PORT` /
`HYDRA_API_DEV_WELL_KNOWN_BASE_URL` environment variables. Real
production behavior (live DNS resolution, live HTTPS GET against the
actual domain) is the unconditional default; there is no code path that
silently skips the real check.

### Tests

`tests/test_api_domain_verification_logic.py` (16 tests) — pure-function
coverage of normalization, subdomain coverage (including the
`notexample.com` false-positive-prefix case), and `classify_scan_gate`'s
covered/expired/never-verified classification, with no I/O.

`tests/test_api_domain_verification_live.py` (9 tests) — `verify_dns_txt`
and `verify_well_known_file` directly, against real local servers: a
hand-built minimal DNS server speaking real wire-format DNS (via
dnspython's own message-parsing classes, `tests/_dns_test_server.py`)
for the TXT method, and a real `http.server` instance for the file
method — the same "real server as arbiter" pattern already established
by `tests/test_httpx_confinement_live.py`, extended to DNS.

`tests/test_api_domain_verification_endpoints.py` (7 tests) — full
HTTP end-to-end through the real FastAPI app (`TestClient`): register →
verify → scan succeeds (both methods); verify fails clearly when the
record/file is missing; a never-verified domain gets `403` and creates
no scan row; a subdomain of a verified domain is covered; two accounts
racing for the same domain get the A.3 conflict; an expired verification
is rejected with a message distinguishable from never-verified.

**A real bug this round's own test infrastructure surfaced and fixed
(documented here since it's a load-bearing lesson for future
network-backed test servers, not just a footnote):** the first version
of `tests/_dns_test_server.py` used `asyncio.DatagramProtocol` on the
calling coroutine's own event loop. `fastapi.testclient.TestClient` runs
the ASGI app on its *own* event loop in a separate thread via anyio's
`BlockingPortal`; a synchronous `client.post(...)` call blocks the
calling thread until the response returns, which starves whatever
asyncio loop that same thread owns — so the DNS test server's own
`datagram_received` callback never got to run while a `client.post(...)`
call to `/domains/{domain}/verify` was in flight, and every DNS-backed
endpoint test timed out at the query's own 10s `lifetime`, despite the
server having the exact right record configured and being independently
reachable outside `TestClient`. Fixed by rewriting the server to use
`socketserver.UDPServer.serve_forever()` on a genuine background OS
thread — no asyncio-loop dependency at all — mirroring the thread-based
`socketserver.TCPServer` pattern
`tests/test_httpx_confinement_live.py`'s `_serve()` already used
successfully for HTTP. Any future in-process test server consumed by
`TestClient`-driven code should use this same thread-based pattern, not
asyncio, for exactly this reason.

**CI network note**: all DNS/HTTP checks exercised in the test suite run
against local, in-process servers (loopback only) — no test depends on
live public DNS or the live internet, specifically because this sandbox
environment was independently confirmed to block outbound UDP/53 to
public resolvers even though macOS's own system resolver (`dig`,
`getaddrinfo`) works fine via a different code path. CI's network
environment should therefore behave identically regardless of its own
outbound DNS policy, since none of these tests ever leave loopback.

## Round 3 implemented (`api/`) — Part B (Free/Medium/Pro/Ultra tiers) and Part D (Wompi)

Round 3 closes the two remaining gaps Round 1 stated explicitly:
unlimited scanning per verified account, and no billing at all. **This
round's tier table is a different, more specific instruction than Part
B's original Starter/Pro/Agency draft above** — four tiers
(Free/Medium/Pro/Ultra) with exact numbers given by the task, not the
three-tier draft — implemented as given, the same "more specific,
more recent instruction wins" reasoning Round 2 already applied to Part
A.2/A.3. See `api/tiers.py`'s own docstring/table for the authoritative
current limits; this section covers the reasoning, the honest gaps, and
what was confirmed against real Wompi documentation versus inferred.

### Task 1 — Tiers: Free's $0 ceiling is structural, not a low limit

`api/tiers.py::TierLimits.reportability`/`.hypotheses` are `None` for
Free — there is no code path to reject, because there is no ceiling
object to check in the first place. `api/routers/reportability.py` and
`api/routers/hypotheses.py` both gate on this being `None` as the
FIRST thing they do, before even resolving `scan_id`, and respond `404`
— identical to a route that was never registered, never `403` (which
would confirm the feature exists but is merely forbidden; Part F.3's
"a mismatch reads identically to not found" principle, reused one level
up for tier gating instead of ownership).

**Numbers the task left for this round to pick, and the reasoning
used** (the task explicitly said "define un techo razonable" /
"decide cuál, documenta la elección" for these):

- Ultra's scan "fair use" ceiling: 500/month, the task's own suggested
  example.
- Pro's `assess-reportability` monthly ceiling: **$40** — no figure was
  given (only Medium's $10 and Ultra's $100 examples), so this splits
  the gap closer to Medium (Pro's likely usage shape — one active
  tester/small team, not agency-scale volume) while still being
  meaningfully higher for the added cross-validation cost.
- Pro's/Ultra's `suggest-hypotheses` ceilings ($25/$60): scaled from
  their respective reportability ceilings by roughly the same ratio the
  table itself uses between Pro's and Ultra's reportability numbers,
  since hypothesis generation runs on a smaller per-call input
  (relationships/entities, not full findings batches) and is
  proportionately cheaper.
- Medium + adversarial cross-validation requested: **auto-degrades to
  single-provider**, never rejected outright (the task offered both
  options and asked for a documented pick) — rejecting the whole
  request over one extra parameter the client is only one tier away
  from having felt disproportionate; the response always carries
  `degraded_from_adversarial: true` so this is never silently invisible
  (`api/subscriptions.py::resolve_adversarial_provider`).
- Ultra's "configurable por cuenta" retention: no fixed tier default;
  resolved per-account via `subscriptions.retention_days_override`
  (settable only through the admin reconciliation endpoint today),
  falling back to a 730-day default (`DEFAULT_ULTRA_RETENTION_DAYS`) if
  the operator never set one explicitly.

**Reused, not rebuilt**: the task said to extend Round 1's per-key rate
limiting (`api/rate_limit.py`'s `TokenBucketLimiter`, still
unmodified) rather than rebuild it — Round 3's tier quotas are a
different, complementary axis (monthly scan/spend ceilings, not
requests-per-minute) and live in a new sibling module
(`api/subscriptions.py`) that both `api/routers/scans.py` and
`api/routers/domains.py` call from the exact same mandatory-`account_id`
gate position Round 2 already established — `_require_billing_and_
quota_ok` sits directly next to `_require_verified_domain_or_403` in
`create_scan`, not a separately bolted-on layer.

**Stated honestly, not silently built**: `TierLimits.priority_queue`
is recorded (Pro/Ultra: `True`) and surfaced via `GET
/account/subscription`, but Round 1's scan execution is still a plain
`asyncio.create_task` per scan with no real job queue to reorder
(already a documented Round 1 limitation) — this field is a no-op today,
present so a real scheduler landing later has something to read. The
`white_label` flag on `POST /scans/{id}/client-report` is
tier-validated (only Ultra can set it `true`) but does **not** yet
change the generated report's content — `core/client_report/` has no
white-label rendering mode, and building one was out of this round's
tested scope (the task's six required tests don't exercise it). Flagged
here rather than silently claimed.

### Task 2 — Wompi OAuth client: confirmed against real docs.wompi.sv

Directly re-verified (not assumed from the earlier design doc) before
writing `api/wompi_client.py::WompiClient`:

- `POST https://id.wompi.sv/connect/token`, form-encoded
  (`grant_type=client_credentials&audience=wompi_api&client_id=...&
  client_secret=...`) → `{"access_token", "expires_in", "token_type":
  "Bearer", "scope"}`.
- The REST API host is `https://api.wompi.sv` — confirmed from that
  page's own literal example (`POST https://api.wompi.sv/EnlacePago`),
  not assumed to be the same host as `id.wompi.sv`.
- The token is cached and refreshed 60 seconds before its own
  `expires_in`, never re-requested on every call, per Wompi's own
  documented guidance.

Tested against a real local HTTP server standing in for both hosts
(`tests/_fake_wompi_server.py`, `tests/test_wompi_client.py`) — real
form-encoding, real caching behavior, real expiry-driven refetch.
**One real, live call was also made** against the actual
`id.wompi.sv` with the operator's real `WOMPI_CLIENT_ID`/
`WOMPI_CLIENT_SECRET` (side-effect-free — a token exchange spends no
money and creates nothing) as part of this round's live demonstration;
see below for the captured result.

### Task 3 — Webhook authenticity: confirmed mechanism, one honest inference

Confirmed directly against `docs.wompi.sv/webhook/validar-webhook.md`:
the signature header is literally `wompi_hash`, the algorithm is
HMAC-SHA256 over the **exact raw request body bytes** (never a
re-serialized/re-parsed-then-dumped version), and the comparison uses
`hmac.compare_digest` (`api/wompi_client.py::verify_webhook_signature`),
never `==` — a timing-safe comparison, so this can't be brute-forced one
byte at a time. `api/routers/subscription.py::wompi_webhook` reads
`await request.body()` before any JSON parsing, specifically so the
bytes hashed are the bytes Wompi actually sent, and performs Part D.2's
second, independent check (`GET /TransaccionCompra/{id}`) before ever
activating anything from the webhook body alone.

**The one inference, stated as plainly as the task asked for**: Wompi's
OAuth documentation
(`docs.wompi.sv/autenticacion/autenticacion.md`) calls the OAuth2
`client_secret` the merchant's **"API Secret"**; the webhook validation
documentation (`docs.wompi.sv/webhook/validar-webhook.md`)
independently calls the HMAC key the merchant's **"API Secret"** too —
same term, on two otherwise-unrelated pages. This implementation uses
`WOMPI_CLIENT_SECRET` as the webhook HMAC key on the strength of that
terminology match. **No Wompi sandbox account was available to enroll a
test card, trigger a real webhook, and confirm the `wompi_hash` value
against a known secret end-to-end** — this is a documentation-
terminology-confirmed inference, not an observed-in-production-confirmed
one. If a sandbox becomes available before this goes live, confirming
this one point is the single highest-value thing to check first.

**Subscriber identification — the task's own explicitly-flagged open
question, and the fallback it asked for**: `docs.wompi.sv`'s
`EnlacePagoRecurrente` creation/response schema
(`metodos-api/crear-enlace-pago-recurrentes.md`) has no merchant-
settable per-subscriber reference field, and the subscriber-list
endpoint (`GET /EnlacePagoRecurrente/{id}/suscripciones`) is named in
the docs but its response body is not documented — both re-confirmed
directly, not assumed from the earlier design doc. No sandbox account
was available to observe either endpoint's real behavior. Implemented,
exactly as the task's fallback instructed:

1. `POST /account/subscription {"tier": "pro", "billing_email": "..."}`
   records a `wompi_pending_enrollments` row (account_id, tier,
   billing_email) and returns that tier's pre-configured, shared
   `EnlacePagoRecurrente` URL — Part D.1's "one link per tier, not per
   customer" reused unchanged.
2. The webhook handler matches an incoming success payload's
   `cliente.Email` (case-insensitive) against a still-`'pending'` row
   for the same tier/product. A match activates the tier and stores
   `billing_email` on the account's `subscriptions` row, so a LATER
   recurring charge (success or failure) can be matched the same way
   without a pending-enrollment row still existing.
3. **No match → `wompi_unmatched_payments`, never discarded, never
   guessed** (Task 3's non-negotiable) — `GET /admin/wompi/unmatched`
   lists them, `POST /admin/wompi/reconcile` links one to an account by
   hand. The admin endpoints are gated by a single static
   `HYDRA_API_ADMIN_TOKEN` — an honestly-temporary MVP mechanism (no
   real operator/admin auth system exists yet, the same kind of stated
   gap Round 1's unauthenticated `POST /accounts` already has), not a
   production-grade admin auth system.

### Task 3.2 — Payment failure / grace period (Part D.3, confirmed as drafted)

3-day grace period (`GRACE_PERIOD_DAYS`, `api/subscriptions.py`): a
webhook reporting anything other than `"ExitosaAprobada"` for an
already-billing-email-linked account starts `status = "past_due"` —
scans and existing API keys keep working exactly as `"active"` does
during grace (Part D.3's own reasoning: a client shouldn't lose access
over a single declined card while actively investigating something).
Only `status == "suspended"` blocks `POST /scans`, with `402` (never
`403` — this is a billing state, not an authorization/quota one).
**Not built this round, stated honestly**: the scheduled job that
detects a grace period's 3 days elapsing with no resolving webhook and
flips `past_due` → `suspended` automatically — `grace_period_expired()`
exists as a pure function ready for that job to call, but no scheduler
invokes it yet. `api/scan_worker.py`'s durable queue (see "Durable,
multi-worker-safe scan execution" below) is purpose-built for SCANS
specifically, not a general-purpose periodic-job scheduler — this and
retention purging would each need their own periodic sweep, the same
shape but a different table, not something the scan queue already
covers for free.
`GET` on an already-completed report is never gated by billing status
at all (checked nowhere in `api/subscriptions.py`) — the client already
paid for that specific, already-delivered data.

### Task 3.3 — Card data (Part D.4, unchanged, reconfirmed)

Unchanged from the original design: the recurring-tier flow never sends
card data to Hydra at all — it's entered directly on Wompi's own hosted
enrollment page (`urlEnlace`). Hydra's backend never implements a card
form, never accepts a PAN/CVV over its own API for the subscription
flow, and this round did not add a one-off top-up/tokenization endpoint
(Part B's LLM-budget top-up is still deferred — not part of this
round's required tests).

### Task 4 — Subscription management endpoints

`GET /account/subscription` (current tier, status, this period's scan/
LLM usage, verified-domain count, effective retention) and `POST
/account/subscription {"tier": ...}` — `tier: "free"` switches
immediately (no payment involved, Part D.1's $0-tier reasoning reused);
`tier` set to a paid tier requires `billing_email` and returns that
tier's payment link, but does **not** change the account's actual tier
— only a confirmed webhook does that (Task 3). `POST /account/
subscription`'s response always reports whether the target tier would
leave the account over its new domain/scan limits
(`exceeds_domain_limit`/`exceeds_scan_limit`) so a client sees the
consequence up front, not as a later, unexplained 403 — see the next
section for what "over the limit" actually does.

### Task-implied decision — downgrade never silently revokes anything

Not explicitly asked as a numbered task, but required by Task 5's test
6: a tier change applies its new scan-quota/LLM-ceiling/domain-count
limits **immediately, looking forward only** — an already-used scan
count for the current month is never reset or backdated, and an account
that now holds more verified domains than its new tier allows keeps
every one of them fully valid until each one's own Round-2 expiry.
Downgrading only ever blocks NEW consumption past the new, stricter
ceiling (a new domain registration once over the limit; a new scan once
already at/over the new monthly count) — nothing already obtained is
taken away as a side effect of a plan change. `api/subscriptions.py`'s
own module docstring documents the full reasoning, including why this
was chosen over an automatic revoke/purge.

### Tests

`tests/test_api_tiers_and_subscriptions_logic.py` (35 tests) — pure
tier-table/quota/budget/tier-change logic, no I/O.
`tests/test_wompi_client.py` (14 tests) — OAuth caching, transaction
lookup, and webhook-signature verification against a real local server
(`tests/_fake_wompi_server.py`), never a mocked `httpx` call.
`tests/test_api_subscription_endpoints.py` (18 tests) — full HTTP
end-to-end: all six of Task 5's required scenarios (Free-tier route
gating returns `404`; valid/invalid/missing webhook signatures;
duplicate-webhook idempotency; unknown-reference → manual reconciliation
→ resolved; scan-quota-reached names the upgrade tier; suspended vs.
past-due billing states; tier-change consequences on both scans and
domains), plus the transaction-double-check and payment-failure-grace
paths. `tests/test_api_reportability_hypotheses_endpoints.py` (3 tests)
— Medium's auto-degrade end-to-end (with the real reportability-
assessment pipeline reused, LLM provider mocked, a real completed scan
with a real finding seeded through `AssetStore`), Pro's real cross-
validation path, and the LLM budget ceiling actually blocking a request.

**A real bug this round's own effort to wire in LLM credentials
surfaced, and a decision about it, stated honestly**:
`api/tenancy.py::account_settings()` builds each account's pipeline
`Settings` with a bare `Settings(project_root=...)` constructor, never
`Settings.from_env()` — meaning no account's scan pipeline has ever
actually inherited the operator's real `.env` configuration (tool
enable flags, thread counts, rate limits, LLM keys, etc.) since Round 1;
every field silently falls back to the dataclass's own built-in
defaults instead. This was NOT changed in Round 3: fixing it would touch
the exact scan-orchestration code path Round 1/2 already tested and
shipped, for a concern outside this round's actual task (tiers/Wompi),
and risked a real regression for no benefit to this round's own work.
Instead, `api/reportability_orchestrator.py`/`api/hypotheses_orchestrator.py`
each load a SEPARATE, purpose-built `_operator_settings()` (a fresh
`Settings.from_env()` pointed at the real repo-root `.env`) specifically
to read the operator-wide `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`/
`REPORTABILITY_*`/`HYPOTHESIS_*` config — correct for this round's own
need (LLM credentials are legitimately operator-wide, not per-account,
per Part B's own "Hydra's own cost, not client price" framing) without
touching the pre-existing, already-tested per-account settings path.
Flagged here as a known, pre-existing gap for a future round to
consider, not something Round 3 fixed or hid.

**CI/environment independence, stated explicitly per this project's own
process**: every reportability/hypotheses test replaces
`_operator_settings` with fake, deterministic credentials via
`monkeypatch` — verified concretely by moving the real (gitignored)
`.env` aside and re-running the full file, confirming it still passes
with zero dependency on real ambient environment or secrets. The Wompi
webhook/OAuth tests never contact the real `id.wompi.sv`/`api.wompi.sv`
either — only the one documented live OAuth call below does, and it is
outside the automated suite.

### A second real bug the live demonstration itself caught

`api/settings.py::load_api_settings()` read only `os.environ` directly
and never loaded the repo-root `.env` file at all — unlike
`config.settings.Settings.from_env()` (the CLI/pipeline's own loader),
which has always called `load_dotenv()` first. This has been true since
Round 1, harmlessly, because Round 1/2's own env vars
(`HYDRA_API_DATA_DIR`, dev DNS/well-known overrides) are the kind an
operator either accepts as defaults or actually exports. Round 3 made it
consequential: an operator who puts `WOMPI_CLIENT_ID`/
`WOMPI_CLIENT_SECRET` in `.env` — the obvious, already-documented place,
confirmed as this project's real convention (`config/.env.example`,
every other credential in this repo's own `.env`) — would have every
Wompi call silently fail with "not configured," discovered only by
running the live demonstration below and watching the real OAuth call
fail with `No module named 'api'`... then, after fixing that import
path, succeed suspiciously without ever having exported anything.
Fixed: `load_api_settings()` now calls `load_dotenv(repo_root/".env",
override=False)` before reading any variable — `override=False` means
an already-exported real environment variable still always wins; this
only fills in what a `.env` file provides and nothing was already set.
Confirmed via the live run below (the real OAuth call actually
succeeded against `id.wompi.sv` afterward) and via the full test suite
(no test calls `load_api_settings()` or the bare module-level
`api.main.app` directly, so this fix has zero effect on any test's
behavior — verified by re-running the full Round 3 test files
afterward, unchanged pass count).

### Live demonstration

Captured from a real `uvicorn` process (throwaway `/tmp` data
directory), hit with real HTTP requests, a real local DNS test server
for the domain-verification step, and one real call to the actual
`id.wompi.sv` using the operator's real `WOMPI_CLIENT_ID`/
`WOMPI_CLIENT_SECRET` (side-effect-free — a token exchange spends
nothing and creates nothing):

```
=== 1. Real OAuth token exchange against the REAL id.wompi.sv ===
[demo] real access_token received (prefix): eyJhbGciOiJS...

=== 2. Create account (defaults to Free tier) ===
HTTP 201
{"account_id":"bf44dfdab934cf220acba46b60499635","api_key":"hydra_live_1da963f8b3a6f5687fc414547b5aa770f0a8c9e51c398f1192645440a41a0c71","key_id":"e2e16c0a74694ee78ef23e5c3f9c0145"}

=== 3. Free tier: assess-reportability route behaves as if it does not exist ===
HTTP 404
{"detail":"Not Found"}

=== 4. Register + verify a real domain (real DNS wire protocol) ===
HTTP 200
{"domain":"hydra-round3-demo.example","status":"verified","method":"dns_txt","verified_at":"2026-09-19T14:51:08.417030+00:00","expires_at":"2026-12-18T14:51:08.417030+00:00"}

=== 5. First scan succeeds (Free = 1/month) ===
HTTP 202
{"scan_id":"ea0c121a6aee504f224f9da34a5b6f5b","status":"queued"}

=== 6. Second scan this month is blocked, names the tier that would help ===
HTTP 403
{"detail":"Monthly scan quota reached (1 for the 'free' tier). Upgrade to 'medium' for a higher monthly limit."}

=== 7. POST /account/subscription tier=pro -> returns the configured payment link ===
HTTP 200
{"tier":"free","status":"active","payment_url":"https://pay.example/pro-demo-link","previous_tier":null,"exceeds_domain_limit":false,"exceeds_scan_limit":false}

=== 8. A locally-simulated Wompi webhook, signed with the REAL WOMPI_CLIENT_SECRET ===
HTTP 502
{"detail":"Could not independently confirm this transaction: Wompi TransaccionCompra lookup failed: HTTP 404 {\"servicioError\":\"Transaccion\",\"mensajes\":[\"La transaccion al que desea acceder no existe\"],\"subTipoError\":\"ElementoNoExiste\"}"}

=== 9. Confirm subscription is still Free (no real transaction backs the demo webhook) ===
{"tier":"free","status":"active","scans_used_this_period":1,"scans_limit":1,"verified_domains_count":1,"verified_domains_limit":1,"grace_period_started_at":null,"retention_days":7}
```

**Step 8 is the single most informative result in this whole
demonstration, stated plainly rather than glossed over**: the simulated
webhook body was signed with the real `WOMPI_CLIENT_SECRET` and DID pass
this service's own `wompi_hash` verification (it never got the `401` an
actually-wrong signature produces in the automated test suite) — but
Part D.2's independent `GET /TransaccionCompra/{id}` check against the
REAL `api.wompi.sv` correctly found that `demo-txn-1` does not exist
there (a real, well-formed `ElementoNoExiste` error from Wompi's own
API) and refused to activate anything. This is the belt-and-suspenders
safeguard actually firing for real, against Wompi's real infrastructure,
not a simulated pass — proof that a validly-HMAC-signed payload alone
is never sufficient in this implementation, exactly as Task 3 required.
No tier was ever activated by anything other than a webhook this service
could independently confirm.

## Post-Round-3 hardening — two production gaps closed (frontend-team review)

An independent review from the `hydra-styling` frontend team, verified
against the real code before being acted on, found two real gaps —
both closed on `fix/account-abuse-and-orphaned-scans`, off `main` after
Round 3 merged.

### Hallazgo 1 — unauthenticated `POST /accounts` enabled unlimited Free-tier abuse

Before this fix, anyone could create unlimited Free accounts with no
verification at all — combined with Free's 1-scan/month quota
(Part B), a script could create a fresh account every time its quota
ran out and scan indefinitely for free. `POST /accounts` cannot simply
require `X-API-Key` (it's the entry point where an account is born —
there is no key yet), so the fix attacks the abuse itself along two
independent, complementary axes, neither of which blocks a real user
creating their one real account:

1. **Per-source-IP rate limit** (`api/routers/accounts.py::_require_
   account_creation_not_rate_limited`): a rolling 24-hour window, not a
   calendar day (a fixed midnight reset would let a script simply wait
   and burst again) — default 3 accounts per IP per 24h
   (`APISettings.account_creation_rate_limit_per_ip_per_day`, env
   `HYDRA_API_ACCOUNT_CREATION_RATE_LIMIT_PER_IP_PER_DAY`). Persisted in
   a new `account_creation_attempts` table (`api/control_db.py`), not
   Round 1's in-memory per-key `TokenBucketLimiter` — that limiter only
   ever runs AFTER authentication, and this endpoint has none; a
   persisted counter also means the limit survives a process restart,
   unlike an in-memory one. A failed attempt (e.g. a duplicate email,
   see below) still counts against the limit — recorded BEFORE the
   creation attempt itself — so probing for already-registered emails
   can't be used to dodge it.

2. **Email verification before the account can scan**:
   `POST /accounts` still returns a working `api_key` immediately (the
   multi-tenant plumbing keeps working unchanged for anyone who
   completes verification) but the account starts with
   `email_verified_at = NULL`. `POST /scans`
   (`api/routers/scans.py::_require_verified_email_or_403`, checked
   FIRST, before billing/quota/domain gates) refuses to run anything
   until `POST /accounts/verify-email {"token": "..."}` confirms the
   token sent to that address. This is what actually raises the cost of
   abuse: a script now needs a real, distinct, receivable email address
   per account, not just a different IP. `accounts.email` carries a
   partial unique index (`WHERE email IS NOT NULL`) — enforced by the
   database itself, not just application logic — so two accounts can
   never share an email; `ControlDB.create_account` raises
   `DuplicateEmailError` (→ `409`) on a collision.

**`EmailSender` is a `Protocol`, not a hard dependency**
(`api/email_sender.py`) — the same structural-interface choice
`core/reportability/provider.py::ReportabilityProvider` already made.
At the time this fix shipped, only one implementation existed
(`ConsoleEmailSender`, log-only) — **a real provider was connected in a
follow-up, "Wire a Real Email Provider (Postmark)" below**; that section
is now the current source of truth for this gap, not this paragraph.

**Backward compatibility, verified explicitly**: an account created
before this fix shipped (`email` column never populated) is treated as
already verified — `_require_verified_email_or_403` only gates an
account that genuinely HAS an email on file and hasn't confirmed it.
Retroactively locking out every already-onboarded account the moment
this shipped would have been an unannounced regression, not a security
fix. `tests/test_api_account_verification.py`'s own
`test_a_pre_fix_account_with_no_email_on_file_is_treated_as_already_
verified` constructs exactly this legacy shape (bypassing `POST
/accounts` entirely, calling `ControlDB.create_account()` the old,
email-less way) and confirms it can still scan.

**A real schema-migration gap this fix had to solve, not just a new
table**: `accounts` already existed (Round 1) with real rows in it by
the time this fix landed — `CREATE TABLE IF NOT EXISTS` never adds
columns to a table that's already on disk. `ControlDB.__init__` now
runs `_migrate_accounts_table` (checks `PRAGMA table_info(accounts)`,
`ALTER TABLE ... ADD COLUMN` for whatever's missing) BEFORE the schema
script — otherwise the schema script's own `CREATE UNIQUE INDEX ... ON
accounts(email)` would fail with "no such column" against any
`control.db` created by an earlier round.

**Also added**: `POST /accounts/resend-verification` (authenticated by
the account's own already-issued `api_key` — an unverified account can
still authenticate, it just can't scan; regenerating a token always
invalidates the previous one outright) — not explicitly asked for, but
a direct, low-cost consequence of "don't block a real user": a lost or
expired verification email should never permanently strand a legitimate
account.

### Hallazgo 2 — a server restart left `running`/`queued` scans stuck forever

> **Superseded — see "Durable, multi-worker-safe scan execution"
> below.** This section is kept as the original design record (what the
> problem was, what this fix's own — deliberately narrow — scope was),
> but `ControlDB.fail_orphaned_scans` described below no longer exists
> in the code; a later task replaced the "mark everything failed once at
> startup" mechanism with automatic requeue-and-actually-re-execute,
> bounded by a retry ceiling. Read the section below for what's actually
> true today.

Scans run as a plain `asyncio.create_task` inside the same process
serving HTTP requests (a known, already-documented Round 1 limitation —
no durable job queue). If that process restarts (deploy, crash) while a
scan is `running`, the row stayed `running` forever, with no signal it
had actually died — worse than a clean failure, since the client sees a
status that never resolves.

**Not a durable job queue** (explicitly out of scope for this fix,
per the task) — the actual recovery this round ships:
`ControlDB.fail_orphaned_scans(reason=...)`, called once in
`api/main.py`'s lifespan, immediately after `ControlDB` is constructed
and BEFORE the app accepts a single request. Any scan found
`queued`/`running` at that exact moment can only be leftover state from
a previous, now-dead process — this process has queued or started
nothing yet — and is marked `failed` with
`error_message = "interrupted by server restart"`, unconditionally, no
exceptions. A scan that had already resolved (`completed`/`failed`)
before the "restart" is left completely untouched.

**Stated honestly, exactly as the task asked**: this is reconciliation
of STATUS, not recovery of WORK — the scan itself is never resumed,
its partial progress (if any) is discarded, and the client must start a
fresh scan if they still want the result. A real durable job queue
(Celery, RQ, or similar) is the actual next architectural step if real
high-availability recovery (resuming, not just cleanly failing) is ever
needed — not built here, and not pretended to be.

### Tests

`tests/test_api_account_verification.py` (12 tests) — rate limiting
under/over the ceiling (including the failed-duplicate-attempt-still-
counts case), an unverified account's scan attempt rejected with a
clear message, a verified account scanning exactly as before,
duplicate-email rejection, expired/invalid/already-consumed tokens, the
resend flow, and the pre-fix-account backward-compatibility case.
`tests/test_api_orphaned_scan_recovery.py` (3 tests) — `queued`/
`running` rows seeded directly (simulating a dead previous process)
resolve to `failed` with the exact reason on the next app startup, an
already-`completed` scan is left untouched, and a scan started and
completed within the SAME process (no restart at all) is unaffected —
the explicit no-regression case. `tests/_verified_account.py` (new
shared test-support module, matching `tests/_verified_domain.py`'s
established split) creates an account through the real `POST /accounts`
(so the now-mandatory email field and uniqueness constraint are
genuinely exercised) and short-circuits verification directly in
`ControlDB` for the many existing tests across Round 1-3 whose actual
subject is something else entirely — every one of those files (`tests/
test_api_auth.py`, `test_api_scans.py`, `test_api_client_report.py`,
`test_api_domain_verification_endpoints.py`,
`test_api_subscription_endpoints.py`,
`test_api_reportability_hypotheses_endpoints.py`) was updated to use it
instead of the old, now-invalid bare `client.post("/accounts")`.

### Live demonstration

Captured from a real `uvicorn` process, real `curl`/HTTP requests, and
— for Hallazgo 2 — an actual process kill and relaunch (not a
simulated restart inside one test process) against the same on-disk
`control.db`:

```
=== HALLAZGO 1: per-IP rate limit on POST /accounts ===
account 0: HTTP 201
account 1: HTTP 201
account 2: HTTP 201
4th account (over limit): HTTP 429
{"detail":"Too many accounts created from this network recently (limit: 3 per 24 hours). Try again later."}

=== HALLAZGO 1: unverified account cannot scan ===
reusing account 823fab6246adad6c24ecdb64f991ad04, api_key issued, unverified
scan attempt on unverified account: HTTP 403
{"detail":"This account's email address has not been verified yet. Check your inbox for the verification link, or POST /accounts/resend-verification for a new one."}

=== HALLAZGO 2 setup: seed a scan stuck in 'running' directly in control.db ===
before restart: scan status = 'running'

=== HALLAZGO 2: restart the SAME process against the SAME control.db ===
after restart: scan status = 'failed', error = 'interrupted by server restart'
```

The Hallazgo 2 sequence is the more load-bearing of the two to have run
for real rather than only inside a `TestClient`: the demo script
`terminate()`s the actual `uvicorn` OS process, seeds a `'running'` scan
row directly against the on-disk SQLite file with no app running at
all (genuinely simulating a crash mid-scan, not a mock of one), then
launches a brand-new `uvicorn` process pointed at that same file —
confirming the startup reconciliation runs correctly across a real
process boundary, not just within one long-lived Python interpreter a
unit test never actually exits.

## Wire a Real Email Provider (Postmark) — 2026-09-22

Follow-up to Hallazgo 1's own explicitly-stated gap above
("`ConsoleEmailSender`... is NOT built and must happen before this flow
is exposed to real, non-operator users"). Closes it with a real
provider — **Postmark** (`postmarkapp.com`), a deliberate choice made
before this task started (dedicated transactional-only sending
reputation, no sandbox/production-access approval gate to go live,
simple REST API, negligible cost at Hydra's actual volume) — not
substituted for SES/SendGrid/Resend/SMTP.

### What's actually true now, confirmed against Postmark's own current docs

Re-verified directly against `postmarkapp.com`'s documentation before
writing `api/email_sender.py::PostmarkEmailSender` (not assumed from
memory), the same discipline `api/wompi_client.py` already established
for Wompi:

- `POST https://api.postmarkapp.com/email`
  (`postmarkapp.com/developer/api/email-api`) — JSON body, header
  `X-Postmark-Server-Token` for auth (confirmed: not a bearer token,
  not a query parameter).
- Error responses (`postmarkapp.com/developer/api/overview`): `401`
  (missing/invalid server token), `422` (validation failure — malformed
  or suppressed recipient), `429` (rate limited); body always
  `{"ErrorCode": <int>, "Message": <str>}` on any non-2xx.
- Domain verification (needed before Postmark will send from an address
  on your own domain, `postmarkapp.com/support/article/1046-how-do-i-
  verify-a-domain`): a DKIM **TXT** record plus a Return-Path **CNAME**
  record (hostname `pm_bounces`, value `pm.mtasv.net`), each verified
  within Postmark's own dashboard — confirmed to typically show as
  verified within 48 hours of the DNS records propagating, or sooner via
  the manual "Verify" button once they're live. DMARC is recommended but
  optional below Postmark's own bulk-sending threshold.

### Selection logic — zero-config path is unchanged, byte-for-byte

`api/main.py::create_app`'s `lifespan` selects `PostmarkEmailSender`
only when BOTH `POSTMARK_SERVER_TOKEN` and `HYDRA_API_EMAIL_FROM` are
set; otherwise `ConsoleEmailSender` — the exact same object, same
behavior, as before this task. Verified two ways, not just by reading
the code: `tests/test_api_email_provider_selection.py`'s
`test_no_postmark_env_vars_selects_console_email_sender` constructs a
real `TestClient(create_app(settings))` with no Postmark fields set and
asserts the wired sender's type directly, and the full pre-existing test
suite (which sets no Postmark configuration anywhere) is part of this
task's own 3x-green confirmation below. A single INFO-level log line at
startup states which mode is active in plain words ("Postmark
configured — sending real verification emails." /
"No email provider configured — verification emails are only logged,
not sent."), so this is never ambiguous from the logs alone.

**Partial configuration fails loudly at startup, not at the first
request**: `api/settings.py::validate_email_provider_config`, called
from `create_app()` itself (before `ControlDB` is even constructed),
raises `EmailProviderMisconfiguredError` — naming the specific missing
variable — if exactly one of the two is set. A half-configured boot
that only surfaces as a confusing failure on the first real
`POST /accounts` would be strictly worse than refusing to start at all.

### The failure-handling decision, made and stated explicitly

A `PostmarkEmailSender` send failure — Postmark returning a non-2xx, or
the request itself raising (timeout, DNS, connection refused) — is
caught **inside** `send_verification_email` and never propagates.
**`POST /accounts` always succeeds and returns a real, usable `api_key`
regardless of whether the email actually sent**; the failure is logged
at `ERROR` with the HTTP status and Postmark's own `ErrorCode`/`Message`
(or the exception type for a network failure), never swallowed
silently.

Reasoning: `POST /accounts/resend-verification` (Hallazgo 1) already
exists as the exact recovery path for "the email never arrived" — a
transient Postmark outage or a misconfiguration not yet fixed (wrong
server token, unverified sender) blocking the ENTIRE account-creation
endpoint would be a strictly worse failure mode than an account that
exists, authenticates, and can retry verification once the underlying
problem is fixed. This mirrors the existing precedent in this codebase
for a degraded-but-not-fatal external dependency (Part D.3's
payment-failure grace period: a third party being unreliable is never
treated as the client's fault).

**The one hard rule enforced regardless**: the Postmark server token
itself must never appear in a log line, an exception message, or
anything that could reach `control_db`/an HTTP response body. Every
error path builds its log message from Postmark's own returned
`ErrorCode`/`Message`/HTTP status, or the exception's type name — never
from the outgoing request (whose headers carry the token). Verified by
a dedicated test
(`test_a_401_response_never_logs_the_server_token`,
`test_a_network_error_never_leaks_the_server_token_in_a_log_line`), not
just asserted in a comment.

### Configuration — three environment variables

Same pattern `wompi_client_id`/`wompi_client_secret` already established
(`api/settings.py`): a dataclass field, read via `os.getenv(...) or
None` in `load_api_settings()`, `.env` loaded first via `load_dotenv`.

| Variable | Required together? | Default | Purpose |
|---|---|---|---|
| `POSTMARK_SERVER_TOKEN` | Yes, with the next one | `None` (→ console sender) | The Server API Token from your Postmark server's "API Tokens" tab. |
| `HYDRA_API_EMAIL_FROM` | Yes, with the previous one | `None` | The verified sender address (must be on a domain you've verified in Postmark — see below). |
| `HYDRA_API_EMAIL_FROM_NAME` | No | `"Hydra"` | Display name on the `From` header. |

**No real credentials exist anywhere in this branch** — not in code,
not in tests (`tests/_fake_postmark_server.py`/
`tests/test_postmark_email_sender.py` use
`postmark-server-token-placeholder`/`noreply@example.com`, obviously
fake), not in `.env` (only `config/.env.example` gets the new
placeholder entries), not in this document (only variable *names*
above, never a value). `docker-compose.yml`'s single `hydra` service
already loads `.env` wholesale (`env_file: .env`) the exact same way
`WOMPI_CLIENT_ID`/`WOMPI_CLIENT_SECRET` already do — no new plumbing was
needed or added there; confirmed by reading it, not assumed.

### What Andrés still has to do by hand before real email sends

1. Create a Postmark account at `postmarkapp.com` (free to start; no
   credit card required to send a low volume).
2. Create a **Server** in the Postmark dashboard (e.g. "Hydra API") —
   this is the sending context the Server API Token below belongs to.
3. Verify a **sending domain** (Sender Signatures / Domains in the
   dashboard) — the address in `HYDRA_API_EMAIL_FROM` must be on a
   domain verified here, not an unverified address:
   - Add the DKIM **TXT** record Postmark shows you to your domain's
     DNS.
   - Add the Return-Path **CNAME** record (hostname `pm_bounces`, value
     `pm.mtasv.net`).
   - Wait for Postmark to show both as verified (usually well under 48
     hours once the DNS records are live), or click "Verify" once
     you've confirmed the records have propagated.
4. Copy the **Server API Token** from that server's "API Tokens" tab.
5. Set three environment variables (in `.env`, or exported in your real
   deployment's environment) and restart the process:
   ```bash
   POSTMARK_SERVER_TOKEN=<the real token from step 4>
   HYDRA_API_EMAIL_FROM=<the verified address from step 3>
   HYDRA_API_EMAIL_FROM_NAME=Hydra   # optional, this is the default
   ```
6. Confirm it took: the startup log should read "Postmark configured —
   sending real verification emails." — if it instead reads "No email
   provider configured," re-check step 5 (both variables must be set
   together, and `load_api_settings()` only reads `.env` from the repo
   root, `_PROJECT_ROOT / ".env"`).

Nothing else is required — no code change, no redeploy beyond a
restart.

### Tests

`tests/test_postmark_email_sender.py` (8 tests) — against a real local
HTTP server standing in for `api.postmarkapp.com`
(`tests/_fake_postmark_server.py`, the same "real server as arbiter"
pattern `tests/_fake_wompi_server.py` already established): correct
request shape (headers, endpoint, recipient, from address), no
clickable link in the body, a `401`/`422`/network-error response never
raises and never leaks the server token into any log line, and a slow
server past the configured timeout is actually cut off (not left to
hang) — a real, enforced timeout, not merely a documented intention.
`tests/test_api_email_provider_selection.py` (7 tests) — the zero-config
default (`ConsoleEmailSender`, including a full account-creation request
through it, unaffected), `PostmarkEmailSender` selected when both
variables are present, and partial configuration raising
`EmailProviderMisconfiguredError` before `ControlDB` is even
constructed, in both directions (token-without-from,
from-without-token).

### A real logging gap this task's own requirement surfaced, fixed along the way

Stated honestly, not silently patched around: **nothing in `api/` ever
configured Python's `logging` module** — no `basicConfig`, no handler,
no level. Without one, the stdlib's own "handler of last resort" is all
that's active (stderr, `WARNING`+ only), which meant every `INFO`-level
line — this task's own "log, once, at startup, which mode is active" for
Postmark, and the pre-existing Hallazgo 2 orphaned-scan-reconciliation
log — was silently dropped in a real `uvicorn` process's actual console
output, never visible at all. Confirmed the hard way: captured a real
`uvicorn` process's stdout before and after the fix (below). Fixed with
one `logging.basicConfig(level=logging.INFO, ...)` call at the top of
`api/main.py` — a no-op if a real deployment's own logging setup already
attached a handler before this module imports (checked: `basicConfig`
only acts on a root logger with zero handlers), so this can't clobber
anyone's own configuration, only provide a sane default where none
existed.

### Live demonstration

No real Postmark credentials exist anywhere in this task, by design (the
operator supplies those after merge) — so unlike the Wompi OAuth
integration's one real live call, this demonstration proves the real,
wired-up HTTP call against a real LOCAL server standing in for
`api.postmarkapp.com`, through a real `uvicorn` process, not a mocked
function call:

```
=== 1. Zero-config: no Postmark env vars -> ConsoleEmailSender ===
HTTP 201 — account created without any Postmark config
startup log confirmed: 'No email provider configured...'

=== 2. Real HTTP call to a real local server standing in for Postmark ===
HTTP 201 — account created
Postmark stub received: To=real-flow-demo@example.com, From=Hydra <noreply@example.com>, Subject='Confirm your Hydra account'
Server token header present: True
startup log confirmed: 'Postmark configured...'

=== 3. Partial configuration fails loudly at startup ===
exit code: 1
Confirmed: app refuses to construct, naming the missing variable.
```

Step 1 and step 2 are two SEPARATE real `uvicorn` process launches (not
the same process reconfigured), each with its own captured stdout,
specifically to prove the startup log line differs correctly based on
which configuration that particular process actually has — the fix from
the section above is what made either log line observable at all. Step
3 shells out to `python3 -c "from api.main import create_app;
create_app()"` as its own subprocess specifically so the raised
`EmailProviderMisconfiguredError` and its exit code are captured
independently of this demo script's own process.

### Explicit non-goals for this pass — deferred, not silently skipped

- **Bounce/complaint/suppression webhook handling from Postmark.** A
  hard-bounced or complained-about address currently has no feedback
  loop back into Hydra at all — it will simply keep failing sends
  silently-to-the-user (loudly-to-the-operator's logs) on every
  `resend-verification` attempt. A real fix needs a new inbound webhook
  endpoint and is a large enough addition to warrant its own task.
- **Any email besides the verification one.** Scan-complete
  notifications, billing emails, password reset — none of that exists
  yet; `EmailSender`'s Protocol shape (`send_verification_email`
  specifically, not a generic `send`) doesn't even support them without
  its own extension.
- **A clickable verification link.** No frontend base URL exists yet to
  build one against — token-only email stays correct, exactly as
  `ConsoleEmailSender` already documented; `_verification_email_content`
  is factored out specifically so this is a one-line change later.
- **Choosing between Postmark's transactional/broadcast message
  streams.** Only one kind of email is sent today, so there's no second
  option to choose between yet — no stream-selection config was added
  for a choice that doesn't exist.

## Durable, multi-worker-safe scan execution — 2026-09-22

Closes the two remaining gaps every prior round's own documentation
named honestly and left open: scan orchestration was single-process,
in-memory `asyncio.create_task` (a restart abandoned in-flight scans,
only cleanly-failed by Hallazgo 2's later fix, never actually
recovered), and `api/rate_limit.py`'s per-key limiter was single-
process, in-memory (reset on restart, never coordinated across worker
processes).

**Architecture, stated plainly**: no message broker, no Celery/RQ/
Redis — SQLite, already this project's own chosen source of truth for
every other piece of cross-cutting control-plane state (accounts, keys,
domain verification, billing, the account-creation rate limit), is
enough at Hydra's real current scale. `docker-compose.yml`'s only
service (`hydra`) is the CLI/recon-pipeline tool, not this API —
confirmed by reading it, not assumed. The paid API has no Docker story
of its own at all today; it runs as a bare `uvicorn api.main:app`
process directly on the host ("Running it locally," earlier in this
document). There is no second container to run a separate worker
process in without inventing both a worker AND an entire containerized-
API deployment nobody has built — so the worker is an in-process
`asyncio` loop (`api/scan_worker.py::run_worker_loop`), started in
`api/main.py`'s `lifespan` alongside the HTTP server, not a separate
`python -m api.worker` process. No changes were made to `docker-
compose.yml`/`docs/DOCKER.md` for this task — there was nothing there
to extend (Wompi's own env vars were never threaded through either,
confirmed the same way during the Postmark task). The claim mechanism
itself doesn't care which model is running it: it's a single atomic SQL
statement (`ControlDB.claim_next_queued_scan`) keyed only on the
`scans` table's own `status`, correct whether one `uvicorn` worker
process calls it or several do — `uvicorn --workers N` (the realistic
next scaling step on one machine, if the API ever does get a real
Docker deployment) needs zero code changes here, each process just runs
its own copy of this exact loop against the same `control.db`.

### What "durable" means here — and does NOT mean

This is status durability and automatic re-EXECUTION from scratch, not
true mid-scan resumption. A scan interrupted 80% of the way through
does not continue from 80% — it restarts the whole pipeline run against
the same `scan_id`, exactly like a client manually resubmitting would,
just automatic instead of requiring the client to notice and retry.
Real partial-progress resumption would mean checkpointing
`_run_headless_pipeline`'s internal state — a substantially bigger
project, explicitly out of scope, not attempted here.

### The queue: `scans` table, three new columns

`retry_count` / `worker_id` / `heartbeat_at`, added to the existing
`scans` table (migrated onto an existing `control.db` the same way
Hallazgo 1 added `accounts.email` — `_migrate_table_columns`, now
generalized from that fix's accounts-only version rather than
duplicated). No new table for the queue itself — `scans` already had
everything else a queue row needs (`status`, `created_at`).

- `ControlDB.claim_next_queued_scan(worker_id)` — one `UPDATE ...
  WHERE scan_id = (SELECT ... ORDER BY created_at LIMIT 1) AND status =
  'queued' RETURNING *` statement. SQLite serializes writers; by the
  time a second concurrent claimer's own UPDATE actually executes, its
  subquery re-evaluates against the now-current state and finds a
  different row (or none) — never the one the first claimer just took.
  **Verified under real concurrent access, not just reasoned about**:
  `tests/test_scan_queue_durability.py::TestDoubleClaimRace` hammers a
  single queued row with 20 threads racing via a `threading.Barrier`
  (maximizing actual contention, not just sequential calls) and asserts
  exactly one wins, plus a 15-scan/10-worker version asserting every
  scan is claimed exactly once, never twice.
- **Liveness, not just a status flag**: `status='running'` alone can't
  tell a genuinely-executing scan apart from one whose worker died
  without updating it, once more than one worker process can exist.
  Each claimed scan gets a concurrent heartbeat sub-task
  (`api/scan_worker.py::_heartbeat_loop`) touching `heartbeat_at` every
  `scan_heartbeat_interval_seconds` (default 30s) for as long as
  execution is genuinely in progress.
- `ControlDB.sweep_stale_running_scans` — runs every poll cycle (every
  `scan_poll_interval_seconds`, default 0.5s in this codebase's own
  test-friendly default; negligible against a ~25-minute scan), not
  just once at startup. This is what lets an ALREADY-RUNNING other
  worker reclaim a scan whose worker just died, without waiting for any
  process to restart at all. A `running` scan whose `heartbeat_at` is
  `NULL` or older than `scan_stale_after_seconds` (default 120s —
  comfortably 4 heartbeat intervals, so one slow/delayed write under
  load never false-triggers a requeue of a scan that's actually fine)
  is either requeued (`retry_count` incremented, `worker_id`/
  `heartbeat_at` cleared, status back to `'queued'`) or, if already
  requeued `scan_max_retries` times (default **3**), given up on as
  `failed` with a diagnosable reason
  (`"...: exceeded 3 retries after repeated interruption"`).

  **Why 3**: a scan interrupted this many times in a row is far more
  likely to be one that reliably crashes the process itself (a genuine
  bug, a domain that triggers a fatal pipeline error) than one that's
  just been unlucky with restart timing. Requeuing it forever would
  occupy a concurrency slot indefinitely and never surface the real
  problem to anyone; giving up after a bounded number of attempts is
  what actually protects the rest of the queue. Verified explicitly
  (`TestSweepRequeueAndRetryCeiling::test_exceeding_the_retry_ceiling_
  gives_up_with_a_diagnosable_reason`): requeued exactly `max_retries`
  times, then `failed` on the next interruption, and never requeued
  again after that.

### Concurrency limit

`max_concurrent_scans` (default **3**) — naabu/httpx/nuclei subprocesses
are real host resources, not free just because they're invoked from
async code. A scan beyond this ceiling simply stays `'queued'` — the
worker loop's claim step only runs while `len(active) <
max_concurrent_scans`; nothing is ever silently dropped, it just waits
its turn on the same FIFO-by-`created_at` ordering every other queued
scan uses.

### What the client sees

Nothing new. `GET /scans/{id}` already returns
`queued`/`running`/`completed`/`failed`; a requeue-after-interruption
sets status back to exactly `'queued'`, the SAME value it had before
ever being claimed the first time — the client's existing poll loop
sees it resume naturally through `queued → running → completed/failed`
with no new status value invented. The only observable difference from
before this task is that a scan interrupted mid-run now eventually
completes instead of permanently ending in an unresolvable `failed`
(Hallazgo 2's old behavior) or staying stuck at `running` forever
(Round 1's original gap).

### The persisted rate limiter

`api/rate_limit.py::PersistentTokenBucketLimiter` replaces (not
supplements — running both would just be two sources of truth for the
same decision) the old in-memory `TokenBucketLimiter` as what
`api/main.py` actually wires up to `app.state.rate_limiter`. Same
`.check(key_id)` / `RateLimitExceededError` interface, so
`api/auth.py::require_api_key` needed zero changes. The refill-and-
consume decision happens in ONE atomic SQL statement
(`ControlDB.check_and_consume_rate_limit_token`, an
`INSERT ... ON CONFLICT DO UPDATE ... WHERE <refilled tokens> >= 1.0`)
— the `WHERE` clause on the conflict branch is what makes this a real
atomic gate: if there aren't enough tokens, NEITHER branch changes
anything, `cursor.rowcount` comes back `0`, and that's the "denied"
signal, with no separate read-then-write (which would itself be a race
between two processes checking the same key at once) ever happening.
Wall-clock (`_now_iso()`), never `time.monotonic()` — Round 1's
in-memory version used monotonic time freely, safe only because it
never needed comparing across processes with independent monotonic-
clock epochs; wall-clock is the only meaningful choice once this state
is shared.

**Verified under real concurrent access AND across real separate
`ControlDB`/limiter instances**, per the task's own explicit
requirement: `TestPersistedRateLimiterCrossProcess::
test_two_separate_limiter_instances_share_the_same_persisted_limit`
constructs two independent `ControlDB`/`PersistentTokenBucketLimiter`
pairs against the SAME on-disk file (simulating two worker processes)
and confirms the limit is enforced across both combined, not doubled;
`test_concurrent_callers_never_exceed_capacity` hammers one bucket with
30 threads racing via a barrier and confirms exactly `capacity` of them
are allowed, never more.

`TokenBucketLimiter` (the old in-memory class) is kept in
`api/rate_limit.py`, unused by the real app — removing a working,
self-contained, still-correct-for-its-narrower-use-case class would
have been deletion for its own sake, not a real simplification.

### Verified against a REAL separate process, kill and relaunch — not simulated

Per the task's own explicit requirement (the same standard Hallazgo 2's
own live demonstration set): `tests/test_scan_queue_durability.py::
TestKillAndRelaunchAgainstARealSeparateProcess` launches a genuinely
separate Python process
(`tests/_scan_worker_subprocess_helper.py` — a standalone launcher
needed because a `monkeypatch`-installed pipeline stub in the pytest
parent process has no effect on a truly separate process's own fresh
imports), creates an account and a scan through real HTTP against that
real child process, waits for the real worker loop inside it to
actually claim the scan (`status` observed as `'running'` over real
HTTP, not asserted from inside the same process), then **hard-kills
that process** (`proc.kill()` — no graceful shutdown, no cooperative
signal handling) mid-execution. A second, genuinely separate process is
then launched against the SAME on-disk `control.db`; the test asserts
the scan's status is observed reaching `'completed'` through that
SECOND process's own real HTTP server, with `retry_count >= 1` as real
evidence it actually went through the requeue path, not a lucky
re-claim of a scan that somehow never got marked `running` in the first
place.

**Real captured output from this exact test** (`pytest -s
--log-cli-level=INFO`, second process's own log — `port 8602` is
process 2, launched fresh against process 1's abandoned `control.db`
after `proc1.kill()`):

```
INFO:     127.0.0.1:51659 - "GET /scans/da0f65ce... HTTP/1.1" 200 OK
2026-09-22 12:11:56 | INFO | recon.runner | Subfinder: OK
2026-09-22 12:11:56 | INFO | recon.runner | Stage: dnsx Resolving DNS
2026-09-22 12:11:56 | INFO | recon.runner | dnsx: OK
2026-09-22 12:11:56 | INFO | recon.runner | Stage: httpx Probing HTTP services
2026-09-22 12:11:56 | INFO | recon.runner | httpx: OK
2026-09-22 12:11:56 | INFO | recon.runner | Pipeline complete in 5.1s

Complete. Output: .../accounts/6778f0e3.../output/da0f65ce0a0da013ab95c7ee6226ab41
Subdomains: 1 | Resolved: 1 | Alive: 1
INFO:     127.0.0.1:51659 - "GET /scans/da0f65ce... HTTP/1.1" 200 OK
```

This is the SAME `run_id`/output directory process 1 would have used
had it not been killed — process 2 never knew process 1 existed, it
just found a stale `running` row via the sweep, requeued it, reclaimed
it via its own `claim_next_queued_scan`, and ran the real pipeline
(stubbed subfinder/dnsx/httpx, real `PipelineRunner`/`AssetStore`
underneath, unstubbed) against it from scratch — exactly the "re-
execution, not resumption" contract this section states.

### Tests

`tests/test_scan_queue_durability.py` (12 tests) — the double-claim
race (two variants: single hot row under 20-way contention, and a
15-scan/10-worker version), the sweep/requeue/retry-ceiling logic
(fresh heartbeat never swept, stale heartbeat requeued with incremented
`retry_count`, a requeued scan claimable by a DIFFERENT worker,
exceeding the retry ceiling gives up with a diagnosable reason and is
never requeued again after that, a `completed` scan is never touched),
the persisted rate limiter (cross-instance sharing, independent
per-key buckets, real wall-clock refill timing, 30-way concurrent-caller
race never exceeding capacity), and the real process kill+relaunch
scenario above. `tests/test_api_orphaned_scan_recovery.py` (3 tests,
rewritten) — Hallazgo 2's original test asserted the now-superseded
"everything becomes failed" behavior; updated to assert what's actually
true now (a scan left `running` by a dead process is requeued and
ACTUALLY completes, with `retry_count >= 1` as evidence), plus the
still-valid no-orphans-is-a-no-op and normal-lifecycle-unaffected cases.

### Explicit non-goals — deferred, not silently skipped

- **True mid-scan resumption.** Stated above and worth repeating here:
  a requeued scan restarts the pipeline from scratch. No checkpointing
  of `_run_headless_pipeline`'s internal progress was attempted.
- **Multi-machine/distributed worker coordination.** The claim/sweep/
  rate-limit mechanisms are all correct for multiple PROCESSES sharing
  one SQLite file on one machine; none of them were designed for or
  tested against multiple machines contending for the same file over a
  network filesystem, which SQLite itself does not reliably support
  regardless of anything this task could add on top.
- **A dashboard or admin UI showing queue depth/worker health.** The
  existing `logger.warning`/`logger.error` lines on every requeue/
  give-up (now actually visible thanks to the logging-configuration fix
  from the Postmark task) are what exists today; a real operator-facing
  view was judged unnecessary for this task's scope.
- **Real priority ordering for Pro/Ultra scans.** `TierLimits.
  priority_queue` remains a recorded-but-inert field — the claim query
  is strict FIFO by `created_at`, no tier-aware reordering.

## Explicitly deferred beyond Round 3

- Client-facing dashboard/frontend (built separately, Next.js/Firebase —
  this API never knows Firebase exists; `X-API-Key` only).
- ~~A durable job queue and a shared rate limiter~~ — **resolved**, see
  "Durable, multi-worker-safe scan execution" below (SQLite-backed, not
  Redis — a deliberate choice stated and justified there). What that
  section does NOT claim: true mid-scan resumption (a requeued scan
  restarts the pipeline from scratch, it doesn't continue from where it
  left off) or multi-MACHINE coordination (a real broker) — both stated
  as explicit non-goals there, not silently assumed away. A real
  "priority queue" for Pro/Ultra scans (`TierLimits.priority_queue` is
  still a recorded-but-inert field) would still need more than this —
  the claim mechanism has no concept of priority ordering today, only
  FIFO by `created_at`.
- The scheduled jobs Part B/D describe but this round did not build: the
  retention-purge job (Part B), and the grace-period-expiry-without-a-
  webhook detector (Part D.3).
- Confirming the webhook-secret inference and the email-based subscriber
  correlation mechanism against a REAL Wompi sandbox account, per this
  round's own honesty requirement — both are implemented and tested
  against real local stand-ins, neither is observed-in-production-
  confirmed yet.
- White-label report content rendering (`core/client_report/` itself) —
  the tier gate exists; the actual branding-free output does not yet.
- One-off LLM-budget top-ups via Wompi tokenization (Part B/D.4's
  `POST /Tokenizacion` flow) — still not built, not required by this
  round's tests.
- Postgres+RLS migration, if/when cross-tenant aggregate reporting is
  actually needed (Part F.2).
