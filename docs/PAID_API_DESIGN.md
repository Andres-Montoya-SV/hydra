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

## Explicitly deferred to Part 2

- Web framework choice (FastAPI/Flask/etc.)
- Actual endpoint implementation, request/response schemas beyond what's sketched above
- Client-facing dashboard/frontend
- The exact per-subscriber identification mechanism for `EnlacePagoRecurrente` webhooks (D.1's open item) — needs a real Wompi sandbox account to observe
- Postgres+RLS migration, if/when cross-tenant aggregate reporting is actually needed (F.2)
