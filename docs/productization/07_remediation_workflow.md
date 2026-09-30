# Product Phase 07 — Remediation Workflow

Branch: `productization/07-remediation`. Base: `main` @ `a78f42c` (after
PR #104).

## Reconnaissance and the design decision

The roadmap describes the workflow as DISCOVER → UNDERSTAND → PRIORITIZE →
ASSIGN → REMEDIATE → VERIFY → CLOSE → REOPEN, and asks for a decision
between two models:

- workflow fields directly on the Exposure;
- a separate, auditable remediation object.

What already existed:

- **DISCOVER and UNDERSTAND:**
  - exposures, identified deterministically from verified findings;
  - their evidence, pointing back to the real detector result;
  - explainable risk (Phase 06);
  - explanations (v2).
- **CLOSE and REOPEN:** an explicit resolve with a reason (owner only), a
  manual reopen, and automatic reopening when the exposure is detected
  again.
  - An exposure never resolves just because it is absent from a scan.
  - `exposure_history` is append-only, and its event types are limited to
    `observed`, `reopened` and `resolved` by a CHECK constraint.
- **Roles:** only `owner` and `viewer`. Viewers can never change anything.

**Decision: a separate object.** Exposure status is *detection truth*: what
scanners observed, backed by evidence. Remediation state is a *human
decision*: who owns the work, whether the risk is accepted, whether someone
claims it is fixed. The two change for different reasons, and the roadmap
requires that accepting a risk never touches evidence.

Storing both on the exposure would let a workflow action overwrite
detection state. So the remediation data lives in two new tables:

- `exposure_remediation`: one row per exposure, holding the current human
  decision.
- `remediation_events`: an append-only log of every change and comment.

`exposures`, `exposure_evidence` and `exposure_history` are never written
by this phase. A test snapshots all three tables before and after accepting
a risk and marking a false positive, and checks they are identical.

## States and transitions

Stored states and the transitions a person may make (`core/remediation.py`):

| From | Allowed to |
|---|---|
| `triage` (default) | `in_progress`, `accepted_risk`, `false_positive` |
| `in_progress` | `triage`, `fixed_pending_verification`, `accepted_risk`, `false_positive` |
| `fixed_pending_verification` | `in_progress` |
| `accepted_risk` | `triage`, `in_progress` |
| `false_positive` | `triage` |

- `accepted_risk` requires a reason and an expiry (`accepted_until`), with a
  timezone and at most 365 days ahead.
- `false_positive` requires a reason.
- A disallowed move is a **409**. Invalid input (missing reason, bad or
  timezone-less timestamp, window too long) is a **422**.

### The effective state is derived on read

The state returned to a client accounts for what detection saw since the
decision. It is computed on every read, so no background job can drift
from it:

| Condition | Effective state |
|---|---|
| the exposure is resolved | `closed` |
| an accepted risk is past `accepted_until` | back to `triage` |
| claimed fixed, then **detected again after the claim** | back to `in_progress` (verification failed) |

`derived_reason` explains any difference from the stored state. Transitions
are validated against the effective state: a closed exposure can't be
moved until it is reopened, and an expired acceptance is treated as triage.

VERIFY works in one direction only. Re-detection after a fix claim proves
the fix didn't hold. Absence from a later scan proves nothing, so a claim
never closes an exposure. Closing remains the explicit, owner-only resolve.

## API

| Endpoint | Who |
|---|---|
| `GET /organizations/{org}/exposures/{id}/remediation` | member |
| `POST .../remediation/transition` `{to_state, reason?, accepted_until?}` | owner |
| `PATCH .../remediation` `{assignee_account_id?, due_at?, ticket_url?}` (only fields sent change; null clears) | owner |
| `POST .../remediation/comments` `{body}` | owner |
| `GET .../remediation/events` (append-only history, paginated) | member |
| `GET /organizations/{org}/remediation?state=&assignee_account_id=&overdue=` (worklist, soonest due first) | member |
| `POST /organizations/{org}/remediation/bulk` `{exposure_ids (≤100, unique), transition \| fields}` | owner |

**Validation:**

- **Assignee:** must be a member of the organization.
- **Ticket link:** must be an `https` URL with a host.
- **Due dates:** must include a timezone, and are stored in UTC.
- **Comments:** must not be blank.

**Due dates and SLA:** `due_at` defaults to a severity SLA counted from
first detection:

| Severity | Days to fix |
|---|---|
| critical | 7 |
| high | 30 |
| medium | 90 |
| low | 180 |

An explicit `due_at` overrides it. `overdue` is true only for triage and
in-progress work; accepted risks and false positives are never overdue.

**Worklist:** it filters and sorts on the **effective** state in SQL, so
paging stays bounded. Its query encodes the same rule as the Python code
(using `julianday` for timestamp comparisons) and the same SLA table. Two
tests keep them in lockstep:

- one compares the SQL and Python states across the derived cases;
- one checks the SQL's SLA values against the Python table.

**Bulk:** a bulk request is all or nothing, in one write-locked
transaction:

- any id outside the organization → 404;
- any disallowed transition → 409;
- in either case, nothing is changed.

As in Phase 06, every write takes the lock (`BEGIN IMMEDIATE`) before
reading the state it replaces.

**Access:** members read; only owners change anything; another
organization's ids return 404, including the per-exposure endpoints called
through the caller's own organization.

## Not done, and why

- **Assignees who can act on their own work.** With only `owner` and
  `viewer`, a viewer can be assigned an exposure but can't update it.
  Adding a role that can write remediation but not scope or members
  changes the authorization model. That belongs to Phase 11 (security and
  access), not here.
- **Per-organization SLA policy.** The defaults are fixed and documented,
  and `due_at` overrides them per exposure. A configurable policy is a
  later addition.
- **Remediation guidance text.** No provider supplies it today, and it
  won't be invented.
- **Notifications on assignment or overdue.** These belong to Phase 08's
  single event/outbox model, not a bespoke path.
