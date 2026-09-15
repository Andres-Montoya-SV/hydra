# Hydra — GitHub repository presentation metadata

**Status: recommended values for manual application, not applied.**
`gh` CLI is installed in this environment (`/opt/homebrew/bin/gh`) but not
authenticated (`gh auth status` → "You are not logged into any GitHub
hosts"), and no `GH_TOKEN`/`GITHUB_TOKEN` is set in the environment. No
attempt was made to apply these via the API without real credentials —
confirmed via a read-only, unauthenticated call to
`https://api.github.com/repos/Andres-Montoya-SV/hydra` that the repository
currently has **no description and no topics set at all**
(`"description": null, "topics": []`), so this is genuinely unset, not a
redundant re-proposal of something already there.

## How to apply

Either from the repo's GitHub page (`Settings` → the pencil icon next to
the description on the main repo page for both description and topics),
or once authenticated locally:

```bash
gh auth login
gh repo edit Andres-Montoya-SV/hydra \
  --description "Scope-gated bug bounty recon: an evidence-based correlation engine, a verification agent, and optional LLM reportability triage, all confinement-proxied and SQLite-backed." \
  --add-topic security \
  --add-topic reconnaissance \
  --add-topic bug-bounty \
  --add-topic attack-surface-management \
  --add-topic osint \
  --add-topic python \
  --add-topic docker \
  --add-topic llm
```

## Description

> Scope-gated bug bounty recon: an evidence-based correlation engine, a verification agent, and optional LLM reportability triage, all confinement-proxied and SQLite-backed.

Checked directly against `README.md`'s own "What Hydra is" section before
proposing this, to avoid contradicting or overstating it:

- "Scope-gated" / "confinement-proxied" — the README's own framing
  ("gated end-to-end by a real scope/authorization layer and a live
  confinement proxy that routes every tool-issued connection ... through
  an authorization check before it reaches the network").
- "evidence-based correlation engine" — the README's "OSINT correlation
  engine that turns shared certificates/IPs into evidence-backed
  relationships (never attribution)".
- "a verification agent" — the README's "deterministic verification
  agent that doubts Hydra's own results before they reach a report".
- "optional LLM reportability triage" — the README's "LLM-backed
  reportability agent ... that triages whether a finding is likely
  eligible under a program's own bounty rules — never authoritative ...
  always a standalone, opt-in step".
- "SQLite-backed" — "Everything persists to SQLite with real, enforced
  foreign keys."
- Deliberately **not** in the description: a tool count, a test count, a
  readiness claim, or any of the ~25 individual plugin names — those
  belong in the README body, and `docs/PRODUCTION_READINESS.md`'s actual
  verdict is `READY WITH KNOWN LIMITATIONS`, a nuance a one-line
  description cannot carry honestly, so the description makes no
  readiness claim at all rather than an inflated or an incomplete one.

## Topics

| Topic | Why it applies, checked against real code/docs |
|---|---|
| `security` | The project's entire purpose and `AUTHORIZED_USE.md`'s existence. |
| `reconnaissance` | The README's own title ("scope-aware reconnaissance") and the ~25 tool-plugin pipeline itself. |
| `bug-bounty` | `AUTHORIZED_USE.md`, the README's "Why it exists" section, and the reportability agent's own stated purpose ("eligible under a program's own bounty rules") all frame the project around bug bounty engagements specifically, not generic pentesting. |
| `attack-surface-management` | The correlation engine + subdomain/asset discovery pipeline is exactly what this term denotes industry-wide; matches `core/intel/engine.py`'s actual relationship/entity model. |
| `osint` | The README's own words: "OSINT correlation engine" — certificates, ASN, WHOIS, passive DNS (`core/intel/correlate.py`, `modules/passive_dns.py`, `modules/whois.py`, `modules/ctlogs.py`). |
| `python` | Implementation language (confirmed: `requires-python = ">=3.10"` in `pyproject.toml`). |
| `docker` | A real, hardened, non-root image with a minimally-scoped Linux capability set — verified with fresh evidence in `docs/PRODUCTION_READINESS.md` Part 3, not just present as an incidental `Dockerfile`. |
| `llm` | The reportability agent makes real Claude/OpenAI API calls (`core/reportability/`) — a genuine, tested integration, not an incidental mention. |

Considered and deliberately **left out**: generic buzzwords
(`pentest`, `hacking`, `cybersecurity`) that would apply to nearly any
security tool without saying anything specific about what Hydra actually
does; `sqlite` as its own topic (a real, emphasized implementation detail
of the project, but a weaker discovery term than the others above —
people search GitHub by `attack-surface-management`/`osint`/`bug-bounty`,
rarely by a project's storage engine).

## Confirmation

**Not applied.** No real GitHub credentials were available in this
environment to run `gh repo edit` for real, and none were assumed or
faked. The values above are ready for the operator to apply by hand
(via the GitHub UI or `gh auth login` followed by the command above) —
whichever is more convenient.
