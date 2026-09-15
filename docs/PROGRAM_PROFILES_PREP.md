# Hydra — Program Profiles: preparatory findings (no system built here)

**This is not the Program Profiles system.** It is exactly what Task 3 of
this hardening round asked for: a search across the current codebase for
accidental coupling to one specific program/platform where a generic
mechanism should exist instead, with the trivial-and-safe cases already
fixed directly (see this branch's own commits) and the non-trivial cases
recorded here as architecture notes for whoever designs Program Profiles
later. Nothing in this document is implemented.

---

## What was already fixed directly (not documented here as "future work")

Two real, safe, trivial fixes landed in this round's own commits — listed
here only so a reader of this document knows not to re-discover them:

1. **HackerOne's actual header name was wrong.** `Settings.merged_headers()`
   sent `X-HackerOne-Researcher` (with a trailing "er"); HackerOne's own
   documented convention (verified against
   `docs.hackerone.com`'s Traffic Identification article) is
   `X-HackerOne-Research`. Fixed, with the log-redaction pattern updated
   to match both spellings and new regression tests.
2. **`.env.example` recommended the wrong option.** The "Bug Bounty
   Custom Headers" section labeled the HackerOne-only
   `X_HACKERONE_RESEARCHER` variable "Option 1 (recommended)", ahead of
   the fully generic `RESEARCHER_ATTRIBUTION_HEADER` mechanism that
   actually works for any program. Reordered so the generic mechanism is
   presented first and the HackerOne-specific variable is correctly
   framed as a convenience shortcut for that one platform.
3. **`compute_attribution_fingerprint` didn't know about
   `x_hackerone_researcher`.** Two runs differing only in that field
   collided on the same cache key and the same historical-cross-check
   fingerprint — the exact class of bug hardening round 1 fixed for the
   other two attribution fields. Fixed; see this branch's commit for the
   full reasoning on why touching that function was in scope for this
   round.

What follows is the coupling that either isn't safe to fix without more
design, or wasn't a bug at all — genuine architecture notes for later.

---

## Finding 1 — log redaction only knows HackerOne's header name, not the generic mechanism's

### The gap, demonstrated

`utils/security.py::_SECRET_PATTERNS` redacts a hardcoded, HackerOne-named
pattern (`x-hackerone-research(er)?`). `RESEARCHER_ATTRIBUTION_HEADER` —
the generic mechanism `.env.example` now correctly recommends first for
*any* program — has no equivalent generic protection. Reproduced directly:

```python
>>> from utils.security import sanitize_log_message
>>> sanitize_log_message("attribution header X-HackerOne-Research: myhandle123 attached")
'attribution header [REDACTED]'
>>> sanitize_log_message("attribution header X-Bugcrowd-Handle: myhandle123 attached")
'attribution header X-Bugcrowd-Handle: myhandle123 attached'   # NOT redacted
```

A researcher's handle for any program *other than* HackerOne — sent via
the exact mechanism this codebase's own documentation now recommends as
the primary option — can reach a log line unredacted, in any context that
isn't already covered by the separate, generic `-H <header>`
subprocess-argument pattern (`sanitize_log_message`'s own regex for
`Executing: httpx -H "..."`-style lines, which *is* name-agnostic and
already catches this specific case when the value flows through a logged
subprocess command).

### Why this isn't a trivial fix

A regex can't redact an arbitrary, not-yet-known header *name* safely:
matching by structure (`X-[A-Za-z-]+:\s*.+`) would either over-redact
(catch ordinary, non-secret custom headers a program's WAF-bypass testing
might use) or stay guessing at naming conventions program by program —
exactly the coupling this task exists to remove, not extend to more
platforms one at a time.

### The direction that generalizes correctly

`sanitize_log_message` already has a working precedent for this exact
shape of problem: it redacts `Path.home()`'s literal string wherever it
appears, generically, because the value (not a naming pattern) is known
at runtime to be sensitive. The same approach applies here: once a
`Settings` instance has a real `researcher_attribution_header` value (or
`x_hackerone_researcher`) configured, *that specific value* is known to
be sensitive for the rest of the process's life — a value-based
redaction registered at `Settings` construction time, extending
`sanitize_log_message`/`SecretRedactingFilter` to consult a small
registered set of "known sensitive values for this run" in addition to
its static patterns, would close this gap for any program's header name
without guessing at conventions. Implementing that is a real design
task (thread-safety of a mutable registered-value set across concurrent
runs in the same process, whether it belongs on the filter or the
formatter, whether to redact substrings or whole matched header lines) —
appropriate for whoever designs Program Profiles' broader "what does this
program need configured" surface, not a one-line fix here.

---

## Finding 2 — `x_hackerone_researcher`'s long-term place, now that it's correct

`X_HACKERONE_RESEARCHER` (fixed this round to send the right header) is
structurally a special case of what `RESEARCHER_ATTRIBUTION_HEADER`
already expresses generically — `config/settings.py`'s own comment on the
generic field says as much: *"unlike x_hackerone_researcher above (a
fixed header name), this supports any program's required header name/value
pair."* Both are read, both flow into `merged_headers()`, both now
correctly participate in the attribution fingerprint (this round's fix).
Nothing is broken; the question is only whether Hydra should keep
maintaining two configuration paths to the identical outcome once Program
Profiles exists.

**Not resolved here, on purpose**: removing `X_HACKERONE_RESEARCHER`
outright would break any operator's existing `.env` that already sets it
— not a "trivial and safe" change by this round's own standard, and not
this task's call to make unilaterally. Two reasonable directions for a
future Program Profiles design to choose between, neither implemented
here:

- **Keep it as a named convenience shortcut** for the one platform common
  enough to warrant one, the same way `ATTRIBUTION_USER_AGENT`'s own
  comment already treats Bugcrowd's UA convention as worth naming
  specifically while staying generic underneath.
- **Fold it into a `Program Profile` for HackerOne specifically** (a
  profile that pre-fills `RESEARCHER_ATTRIBUTION_HEADER=X-HackerOne-Research: <handle>`
  from a simpler `PROGRAM=hackerone` + handle input) — at which point the
  standalone `X_HACKERONE_RESEARCHER` variable becomes redundant with the
  profile system itself and could be deprecated with a real migration
  path, not a silent removal.

---

## What was checked and found to already be genuinely generic (no finding)

Recorded so a future search doesn't re-derive the same ground:

- **`core/external_mode.py`** (`classify_run`, `EXTERNAL_MODE_GATED_FLAGS`,
  `format_scope_summary`): classification is driven entirely by
  `OWNED_DOMAINS`/`EXTERNAL_TARGET_MODE`, never a named platform. The
  three gated flags (`enable_param_fuzz`, `enable_cloud_bucket_enum`,
  `enable_browser_probe`) are chosen by *what a module does* (sends active
  traffic directly at the target), not which program is running.
- **`Settings.apply_external_target_mode_defaults()`**: the conservative
  rate/delay overrides for an external target apply uniformly; nothing
  here reads or branches on `program_platform`.
- **`core/scope.py::load_scope_patterns`**: a plain wildcard/exclusion
  text format, deliberately not tied to any platform's own scope-export
  shape (not HackerOne's structured scope API, not Bugcrowd's CSV) — an
  operator curates one plain file regardless of platform. This is the
  correct design already; nothing to change.
- **`program_name`/`program_platform` (`config/settings.py`)**: free-form
  strings, used only for report metadata display
  (`core/reporter.py`, `ui/dashboard.py`) — never drive any behavioral
  branch. Confirmed by grep: no `if program_platform == "..."` exists
  anywhere in the codebase.
- **`modules/browser_probe.py`'s Bugcrowd/HackerOne comments**: illustrative
  examples in docstrings only (`"e.g. Bugcrowd's ... "`) — the actual
  mechanism used (`extra_headers`/`Settings.merged_headers()`,
  `attribution_user_agent_suffix()`) is already fully generic.

---

## Summary for whoever builds Program Profiles next

The generic mechanisms (`RESEARCHER_ATTRIBUTION_HEADER`,
`ATTRIBUTION_USER_AGENT`, `OWNED_DOMAINS`/`EXTERNAL_TARGET_MODE`,
`SCOPE_FILE`) were already built correctly platform-agnostic — a Program
Profile system has real, solid ground to build on rather than needing to
first unwind program-specific logic scattered through the collection
path. The two real gaps found are narrower than "the architecture assumes
one program's shape": one is a one-field omission from a fingerprint
function (fixed), and the other is a log-redaction mechanism that hasn't
caught up to the fact that a generic attribution mechanism now exists and
is the recommended path. Both are legitimate inputs to a future Program
Profiles design (a profile should probably be the thing that registers
"these values are sensitive, redact them" at load time, closing Finding 1
as a side effect of the profile system's own existence) rather than
problems that need solving before that design starts.
