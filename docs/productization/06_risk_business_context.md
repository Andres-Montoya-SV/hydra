# Product Phase 06 — Risk & Business Context v2

Branch: `productization/06-risk-context`. Base: `main` @ `067ee1b` (after
PRs #102 and #103).

## Starting point

`core/risk_scoring.py` (Fase 21) already classified every exposure
deterministically, and each level came with its reasons. It used four
inputs:

- severity;
- whether the asset is in confirmed (verified) scope;
- exposure age (30 days or more escalates one level);
- relationship-graph context (a direct neighbor with an open high or
  critical exposure escalates one level).

The roadmap asks the engine to be **extended, not replaced**. It lists
more factors, and requires that unknown signals stay unknown and are never
invented. Reconnaissance found what already exists for each one:

| Factor (roadmap) | Before this phase | Now |
|---|---|---|
| Severity | observed | unchanged |
| Confirmed scope | observed | unchanged |
| Exposure age | observed | unchanged |
| Relationship-graph context | observed | unchanged |
| Environment (prod/staging/dev) | no source | **declared** by the organization |
| Business criticality | no source | **declared** |
| Identity / payment / personal-data infrastructure | only hostname heuristics inside the scan DB | **declared** (`data_handled`) |
| Owner / business unit | no source | **declared** (cited, doesn't move the level) |
| Confidence quality | stored (`confidence_score`), not used | **observed**: below 50 caps escalation |
| Internet reachability | implicit | **observed**: a remote detection location |
| Exploitability / validation, threat intel (KEV/EPSS) | no source | listed as **unknown** |
| Auth surface | only hostname heuristics inside the scan DB | not used: a heuristic isn't evidence |

Hostname heuristics were deliberately not promoted into risk inputs. For
example, "staging." in a name, or a host profiled as "payments", is a
guess, not evidence. The organization declares these facts instead, and
every declaration is audited.

## Declared business context

| Endpoint | Who |
|---|---|
| `GET /organizations/{org}/assets/{asset}/context` | member |
| `PUT /organizations/{org}/assets/{asset}/context` | owner |
| `GET /organizations/{org}/assets/{asset}/context/audit` | member |

The fields are:

- `environment`: production, staging, development or test;
- `criticality`: critical, high, medium or low;
- `data_handled`: any of identity, payment and personal_data;
- `owner`: plain text, at most 200 characters, no control characters.

A PUT replaces the whole context, and null or empty clears a field. Each
change is written to `asset_business_context_audit` in the same
transaction, with before and after values. Saving identical values writes
nothing. Another organization's IDs return 404, like every other endpoint.

## The rule

Applied in order. It is deterministic: the same inputs always produce the
same result.

1. The base level comes from severity.
2. Each escalating factor raises the level by one:
   - age of 30 days or more;
   - relationship to a critical asset;
   - **declared business impact**: criticality critical or high, or
     handling identity, payment or personal data. This counts once, however
     many of them apply.

   Exception: **if detector confidence is below 50, no escalation
   applies**, and the level stays at base severity. This implements the
   evidence invariant: no high-confidence claim from one weak signal.
3. **A declared non-production environment lowers the level by one**, with
   low as the floor. This applies only if no business impact was declared,
   so a business-critical asset is never downgraded for being in staging.

`GET .../exposures/{id}/risk` still returns `level` and `reasons`, and
adds:

- `factors`: every factor considered, with its value, its `source`
  (observed or declared) and its `effect` (escalates, de-escalates, caps or
  none);
- `unknowns`: the signals Hydra could not assess, for example "business
  criticality: not declared" or "exploitability: no exploit validation or
  known-exploited (KEV/EPSS) data source".

**Backward compatible:** with none of the new inputs, the classification
and its `reasons` are exactly the Fase 21 ones, text included. All existing
risk tests pass unchanged.

The new signals also reach the other places that use the engine, with no
extra wiring:

- the explanation resource;
- the client exposure report;
- monitoring's `RISK_CHANGED` alert. After someone declares an asset
  critical, the next scan that observes its exposure alerts on the change
  and cites the declaration.

## Not done, and why

- **Exploitability and threat intelligence** (KEV, EPSS, exploit
  validation) have no data source in Hydra. Adding one is a provider
  decision, a Phase 09 qualification concern. Until then, both are
  reported as unknown on every classification.
- **Asset auto-classification** (guessing the environment from the
  hostname) would put guesses into a risk score. It stays out of the
  engine. A future phase could offer such guesses as *suggestions* for an
  owner to confirm.
