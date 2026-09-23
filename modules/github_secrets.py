"""Leaked-secrets detection in public GitHub repositories (opt-in, passive
with respect to the TARGET — never connects to the target's own
infrastructure at all).

WHAT THIS DOES AND DOES NOT TOUCH
------------------------------------
This module never sends a request to the target organization's own
domains/hosts/IPs — it only ever talks to GitHub's own public API and
clones/scans GitHub's own public repository content. It needs no
`CollectionScope`/`AuthorizedCollectionTarget`/`ScopeEnforcingProxy` for
that reason, the same as `modules/ctlogs.py` (a real, third-party API
integration with its own rate limits and terms of use, but passive with
respect to the target). It only ever scans **public** repositories: every
repository this module clones is filtered to `private == false` before
it is ever cloned, even if a supplied `GITHUB_TOKEN` happens to have
private-repo read access — a hard rule, not a default that a token could
accidentally widen.

REPOSITORY DISCOVERY
------------------------
Two independent paths, and an operator-supplied org is ALWAYS preferred
when given — automatic discovery is inherently best-effort and can have
both false positives (an unrelated org/repo that happens to mention the
domain) and false negatives (the real org's repos never mention the
domain literally):

1. `Settings.github_org` (env `GITHUB_ORG`) explicitly names the GitHub
   organization/user to scan. Its public repos are listed via GitHub's
   plain REST API (`GET /orgs/{org}/repos`), which — confirmed directly
   against a real, live, unauthenticated request during this module's
   own development — works with NO token at all (60 req/hour
   unauthenticated; a configured `GITHUB_TOKEN` raises that ceiling but
   is not required for this path).
2. Without an explicit org, GitHub's code-search API
   (`GET /search/code?q=<domain>`) is used as a best-effort fallback,
   matching repositories whose default-branch content mentions the
   target domain. **Confirmed against GitHub's real, current REST API
   docs, not memory** (their code-search auth/rate-limit model has
   changed more than once): this endpoint requires authentication even
   for public code — there is no unauthenticated path at all — and even
   authenticated it is capped at 10 requests/minute, far stricter than
   GitHub's other search endpoints. Without `GITHUB_TOKEN` configured,
   this fallback is skipped entirely (the plugin still runs the
   org-listing path if `GITHUB_ORG` is set) with a clear warning, never a
   silent empty result presented as "nothing found."

SECRET SCANNING: WRAPPING `gitleaks`, NOT REIMPLEMENTING IT
----------------------------------------------------------------
Each eligible repository (public, and excluded if it's a fork unless
`GITHUB_SECRETS_INCLUDE_FORKS=true`) is cloned into an ephemeral
temporary directory — never into `context.output_dir`, since a clone's
full history can contain a real plaintext secret in an old commit, and a
persisted run-output directory is exactly the kind of place that must
never hold one — with `git clone --depth <N>` (bounded; a full,
unbounded history clone of an old, large repo could be arbitrarily
expensive, a real, explicitly documented tradeoff against completeness
of historical-commit coverage, not a hidden limitation).

**Confirmed against the real, current `gitleaks` 8.30.1 CLI, not assumed**
(installed and run for real against constructed test repositories during
this module's own development):

- The `detect` command from older gitleaks docs/tutorials is deprecated;
  the current subcommands are `gitleaks git <path>` (scans full history
  via `git log -p`) and `gitleaks dir <path>` (scans only the current
  working tree, no history at all) — confirmed each has a distinct real
  JSON report shape (`git` mode's `Fingerprint` is
  `<commit>:<file>:<rule>:<line>`; `dir` mode's is `<file>:<rule>:<line>`,
  with `Commit`/`Author`/`Email`/`Date`/`Message` all empty strings).
- **A real go-install gotcha, confirmed by actually running it**: the
  project moved from the `zricethezav` GitHub user to the `gitleaks` org,
  but its `go.mod` still declares the OLD module path —
  `go install github.com/gitleaks/gitleaks/v8@...` fails with a "version
  constraints conflict" error; the real, current working install path is
  still `go install github.com/zricethezav/gitleaks/v8@...` (see
  `core/dependencies/registry.py`).
- `gitleaks` ships its own default ruleset with allowlists for common
  false-positive patterns (confirmed live: AWS's own documented example
  key, `AKIAIOSFODNN7EXAMPLE`, used verbatim in a real test commit, was
  correctly NOT flagged — gitleaks' own allowlist recognized it). This
  module never re-implements or second-guesses that allowlisting; it
  trusts `gitleaks`' own JSON report as the full set of real candidates,
  exactly the task's own "respect the tool's rule metadata" instruction.

CURRENT-HEAD VS. HISTORICAL-ONLY
-------------------------------------
This module runs BOTH `gitleaks git` (the canonical, full-history finding
source — since scanning every commit's diff already includes the latest
commit's own content, `git` mode alone is a strict superset) and
`gitleaks dir` (current working tree only) against the same clone.
`_is_in_current_head` looks up each `git`-mode finding by exact
`(File, RuleID, StartLine)` against the set of `dir`-mode findings from
the *same* clone first; if that exact match fails (a historical commit's
line numbers can drift from the current file), it falls back to
`(File, RuleID)` alone — but ONLY when exactly one `dir`-mode entry
shares that pair. A real bug, caught by this module's own test suite:
an earlier version used the loose fallback unconditionally, which
silently mismatched two DIFFERENT secrets sharing the same rule in the
same file (a rotated secret and a separate, still-present one both
flagged `generic-api-key` in `config.py`) — the rotated one was wrongly
reported as still current. Requiring the fallback to be unambiguous is
the safer failure mode: under-reporting "current" is far less harmful
than over-reporting it, given the severity jump involved. A match means
the secret is still present in the repository's current default branch
(`in_current_head=True`, severity `critical`); no match means it was
found only somewhere in history and may already have been rotated
(`in_current_head=False`, severity `medium`) — exactly the distinction
this task asked for, built from two real tool invocations rather than
guessed from commit dates.

**A real correlation bug, caught only by testing an actual still-present
secret, not just a rotated one**: `gitleaks dir <path>`'s `File` field is
relative to whatever path FORM is given as `<path>` — an absolute path
argument produces an absolute `File` value — while `gitleaks git
<path>`'s `File` field is always relative to the repo root regardless of
the path form given. Passing the clone's absolute path to `dir` mode
silently broke every correlation (every finding came back
`in_current_head=False`, even ones confirmed still present) until this
was caught; the fix is invoking `gitleaks dir .` with `cwd` set to the
clone directory, matching `git` mode's always-relative paths. See
`_scan_repo`'s own comment at that call site.

REDACTION — A HARD RULE, NOT A STYLE PREFERENCE
------------------------------------------------------
`gitleaks` is ALWAYS invoked with a bare `--redact` flag (its own
`uint[=100]` default is full redaction), confirmed by real invocation to
replace both the `Secret` and `Match` JSON fields with the literal string
`"REDACTED"` — so the real secret value never even reaches disk in
`gitleaks`' own report file in the first place. On top of that, as
defense in depth against relying solely on the external tool's own
redaction correctness, **this module's own Python code never reads the
`Secret` or `Match` JSON keys at all** — see `_finding_from_gitleaks_row`
below, which only ever extracts `RuleID`, `Description`, `File`,
`StartLine`, `Commit`, `Author`, `Email`, `Date`. Hydra's own stored
finding record is built entirely from that safe metadata — no truncated
or partial preview of the secret value is stored either, since even a
short prefix of a live credential is still live credential material and
`RuleID` + file + line + commit is already fully actionable for a human
to go rotate it. `tests/test_github_secrets.py`'s redaction test proves
this holds even when a realistic (fake) live-looking secret value is
deliberately planted in the `Secret`/`Match` fields of a crafted fixture.

NEVER VALIDATES OR USES A DISCOVERED CREDENTIAL
------------------------------------------------------
This module detects and reports. It never attempts to authenticate with,
call, or otherwise exercise any secret it finds — trying a discovered AWS
key, for instance, would cross from passive discovery into active use of
someone else's credentials, a different authorization question entirely
and out of scope for an automated, unattended pipeline. There is no code
path here that reads a secret value and makes a second network call with
it — confirmed by the same fact that drives the redaction guarantee
above: this module's code never has the real secret value in memory to
begin with.

NON-GOALS
------------
GitLab/Bitbucket/other forges (GitHub only this pass — a real, plausible
follow-up, not half-built here); any validation/use of a discovered
credential; scanning a private repository under any circumstance, even
if a supplied token happens to have access.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.subprocess import run_command

_GITHUB_API = "https://api.github.com"
_ORG_REPOS_PAGE_SIZE = 100
_ORG_REPOS_MAX_PAGES = 3
_SEARCH_CODE_TIMEOUT = 20


@dataclass(frozen=True)
class _Repo:
    full_name: str
    clone_url: str
    html_url: str
    private: bool
    fork: bool


def _github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_org_repos(
    org: str,
    token: str | None,
    timeout: int,
    user_agent: str,
    proxy_url: str | None,
) -> list[_Repo]:
    import urllib.parse
    import urllib.request

    from utils.network import open_url

    repos: list[_Repo] = []
    for page in range(1, _ORG_REPOS_MAX_PAGES + 1):
        query = urllib.parse.urlencode(
            {"type": "public", "sort": "updated", "per_page": _ORG_REPOS_PAGE_SIZE, "page": page}
        )
        request = urllib.request.Request(
            f"{_GITHUB_API}/orgs/{urllib.parse.quote(org)}/repos?{query}",
            headers={**_github_headers(token), "User-Agent": user_agent or "hydra/1.0"},
        )
        with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
            payload = response.read(5 * 1024 * 1024)
        data = json.loads(payload.decode("utf-8", errors="replace"))
        if not isinstance(data, list) or not data:
            break
        repos.extend(_repo_from_api(item) for item in data if isinstance(item, dict))
        if len(data) < _ORG_REPOS_PAGE_SIZE:
            break
    return repos


def _fetch_search_code_repos(
    domain: str,
    token: str,
    timeout: int,
    user_agent: str,
    proxy_url: str | None,
) -> list[_Repo]:
    import urllib.parse
    import urllib.request

    from utils.network import open_url

    query = urllib.parse.urlencode({"q": f"{domain} in:file", "per_page": _ORG_REPOS_PAGE_SIZE})
    request = urllib.request.Request(
        f"{_GITHUB_API}/search/code?{query}",
        headers={**_github_headers(token), "User-Agent": user_agent or "hydra/1.0"},
    )
    with open_url(request, timeout=timeout, proxy_url=proxy_url) as response:
        payload = response.read(5 * 1024 * 1024)
    data = json.loads(payload.decode("utf-8", errors="replace"))
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    seen: dict[str, _Repo] = {}
    for item in items:
        repo_data = item.get("repository") if isinstance(item, dict) else None
        if not isinstance(repo_data, dict):
            continue
        repo = _repo_from_api(repo_data)
        seen.setdefault(repo.full_name, repo)
    return list(seen.values())


def _repo_from_api(data: dict[str, object]) -> _Repo:
    return _Repo(
        full_name=str(data.get("full_name") or ""),
        clone_url=str(data.get("clone_url") or ""),
        html_url=str(data.get("html_url") or ""),
        private=bool(data.get("private")),
        fork=bool(data.get("fork")),
    )


def _eligible(repo: _Repo, *, include_forks: bool) -> bool:
    # Hard rule, never overridden by any setting: only genuinely public
    # repositories are ever cloned, regardless of what a configured
    # GITHUB_TOKEN might otherwise be able to see.
    if repo.private:
        return False
    if repo.fork and not include_forks:
        return False
    return bool(repo.clone_url and repo.full_name)


def _read_gitleaks_json(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _dir_mode_keys(dir_rows: list[dict[str, object]]) -> set[tuple[str, str, int]]:
    keys: set[tuple[str, str, int]] = set()
    for row in dir_rows:
        keys.add(
            (
                str(row.get("File") or ""),
                str(row.get("RuleID") or ""),
                int(row.get("StartLine") or 0),
            )
        )
    return keys


def _is_in_current_head(key: tuple[str, str, int], dir_keys: set[tuple[str, str, int]]) -> bool:
    """Exact (File, RuleID, StartLine) match first. If that fails, fall
    back to (File, RuleID) alone ONLY when exactly one `dir` mode entry
    shares that pair — a real, testing-confirmed gap: when a file has
    TWO DIFFERENT secrets under the SAME rule (e.g. two generic-api-key
    matches in one file, one rotated and one still present), a loose
    (File, RuleID)-only fallback cannot tell them apart and would
    wrongly mark a rotated secret as still current. Requiring the
    fallback to be unambiguous (exactly one candidate) is the safer
    failure mode — under-reporting "current" is far less harmful than
    over-reporting it, given the severity jump involved."""
    if key in dir_keys:
        return True
    file_path, rule_id, _line = key
    same_file_and_rule = [k for k in dir_keys if k[0] == file_path and k[1] == rule_id]
    return len(same_file_and_rule) == 1


def _finding_from_gitleaks_row(
    row: dict[str, object],
    repo: _Repo,
    *,
    in_current_head: bool,
) -> dict[str, object]:
    """Builds Hydra's own finding record from a real `gitleaks git` JSON
    row. Deliberately reads ONLY safe metadata fields — `Secret`/`Match`
    are never accessed here, by construction, not by a redaction step
    applied afterward. See module docstring's REDACTION section."""
    file_path = str(row.get("File") or "")
    line = int(row.get("StartLine") or 0)
    commit = str(row.get("Commit") or "")
    rule_id = str(row.get("RuleID") or "unknown")
    url = (
        f"{repo.html_url}/blob/{commit}/{file_path}#L{line}"
        if commit and file_path
        else repo.html_url
    )
    severity = "critical" if in_current_head else "medium"
    confidence = 90 if in_current_head else 60
    status_text = (
        "still present in the repository's current default branch"
        if in_current_head
        else "found only in historical commit content — may already be rotated/removed"
    )
    return {
        "repo": repo.full_name,
        "repo_url": repo.html_url,
        "file": file_path,
        "line": line,
        "rule_id": rule_id,
        "description": str(row.get("Description") or rule_id),
        "commit": commit or None,
        "author": str(row.get("Author") or "") or None,
        "email": str(row.get("Email") or "") or None,
        "date": str(row.get("Date") or "") or None,
        "in_current_head": in_current_head,
        "severity": severity,
        "confidence_score": confidence,
        "url": url,
        "template_id": "leaked-secret",
        "name": f"Leaked secret ({rule_id}) in {repo.full_name}",
        "description_full": (
            f"gitleaks matched rule '{rule_id}' in {repo.full_name}:{file_path}"
            f" (line {line}) — {status_text}. The secret value itself is never "
            "stored; see file/line/commit above to locate and rotate it."
        ),
        "raw_artifact": "github_secrets.jsonl",
    }


class GithubSecretsPlugin(BaseToolPlugin):
    """Discovers GitHub repos plausibly tied to the target and scans them
    (via `gitleaks`) for leaked secrets — never touches the target's own
    infrastructure. See module docstring for the full design."""

    name = "github_secrets"
    display_name = "GitHub Leaked Secrets"
    required = False
    stage_order = 15
    produces = ("leaked_secrets",)
    capability = "leaked_secrets_scanning"
    active_collection = False
    install_hint_macos = "brew install gitleaks"
    install_hint_linux = "go install github.com/zricethezav/gitleaks/v8@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_github_secrets

    def get_binary_path(self) -> Path:
        return self.settings.gitleaks_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        repos = await self._discover_repos(context)
        if not repos:
            return self._skip("No eligible public GitHub repositories discovered")

        max_repos = max(1, self.settings.github_secrets_max_repos)
        repos = repos[:max_repos]

        # Findings attach to the engagement's own target domain — there is
        # no separate Hydra `Host` concept for "a GitHub repo," and every
        # report is organized per-Host; the first target domain is the
        # correct, unambiguous choice even when repos come from a whole-org
        # listing that isn't itself tied to one specific domain.
        target_domain = context.targets[0].domain if context.targets else ""

        self.update_status(context, ToolStatus.RUNNING)
        all_findings: list[dict[str, object]] = []
        scanned = 0
        for repo in repos:
            try:
                findings = await self._scan_repo(repo)
            except Exception as exc:
                context.add_warning(f"github_secrets: {repo.full_name} scan failed: {exc}")
                continue
            scanned += 1
            for finding in findings:
                finding["host"] = target_domain
            all_findings.extend(findings)

        output_path = self._output_path(context, "github_secrets.jsonl")
        count = write_jsonl(output_path, all_findings, base_dir=context.output_dir)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"github_secrets: {count} leaked-secret finding(s) across "
                f"{scanned}/{len(repos)} scanned repositor{'y' if scanned == 1 else 'ies'}"
            ),
        )

    async def _discover_repos(self, context: PipelineContext) -> list[_Repo]:
        import asyncio

        timeout = self.settings.gitleaks_timeout
        user_agent = self.settings.effective_user_agent()
        proxy_url = self.settings.outbound_proxy_url
        include_forks = self.settings.github_secrets_include_forks

        if self.settings.github_org:
            try:
                repos = await asyncio.to_thread(
                    _fetch_org_repos,
                    self.settings.github_org,
                    self.settings.github_token,
                    timeout,
                    user_agent,
                    proxy_url,
                )
            except Exception as exc:
                context.add_warning(f"github_secrets: org lookup failed: {exc}")
                return []
            return [r for r in repos if _eligible(r, include_forks=include_forks)]

        if not self.settings.github_token:
            context.add_warning(
                "github_secrets: no GITHUB_ORG and no GITHUB_TOKEN configured — GitHub's "
                "code-search API requires authentication even for public code (confirmed "
                "against GitHub's own current REST API docs), so automatic repository "
                "discovery is skipped. Set GITHUB_ORG for a reliable, explicit target, or "
                "GITHUB_TOKEN to enable best-effort code-search discovery."
            )
            return []

        found: dict[str, _Repo] = {}
        for target in context.targets:
            try:
                repos = await asyncio.to_thread(
                    _fetch_search_code_repos,
                    target.domain,
                    self.settings.github_token,
                    _SEARCH_CODE_TIMEOUT,
                    user_agent,
                    proxy_url,
                )
            except Exception as exc:
                context.add_warning(
                    f"github_secrets: code search failed for {target.domain}: {exc}"
                )
                continue
            for repo in repos:
                if _eligible(repo, include_forks=include_forks):
                    found.setdefault(repo.full_name, repo)
        return list(found.values())

    async def _scan_repo(self, repo: _Repo) -> list[dict[str, object]]:
        tmpdir = tempfile.mkdtemp(prefix="hydra_github_secrets_")
        try:
            clone_dir = Path(tmpdir) / "repo"
            depth = max(1, self.settings.github_secrets_clone_depth)
            clone_args = [
                "git",
                "clone",
                "--quiet",
                "--depth",
                str(depth),
                repo.clone_url,
                str(clone_dir),
            ]
            return_code, _stdout, stderr = await run_command(
                clone_args, timeout=self.settings.gitleaks_timeout, tool_name="git"
            )
            if return_code != 0 or not clone_dir.exists():
                raise RuntimeError(f"git clone failed: {stderr.strip()[:200] or 'unknown error'}")

            git_report = Path(tmpdir) / "gitleaks_git.json"
            dir_report = Path(tmpdir) / "gitleaks_dir.json"
            binary = str(self.get_binary_path())

            await run_command(
                [
                    binary,
                    "git",
                    str(clone_dir),
                    "--report-format=json",
                    f"--report-path={git_report}",
                    "--redact",
                    "--exit-code=0",
                    "--no-banner",
                ],
                timeout=self.settings.gitleaks_timeout,
                tool_name="gitleaks",
            )
            # `.` + cwd=clone_dir, NOT the absolute clone_dir path: a real,
            # confirmed-by-testing gotcha — `gitleaks dir <path>` reports
            # `File` relative to whatever path FORM was passed (absolute
            # path in -> absolute path in the report's `File` field), while
            # `gitleaks git <path>` always reports `File` relative to the
            # repo root regardless of the path form given. Passing the
            # absolute path here silently broke the (File, RuleID)
            # correlation with `git` mode's always-relative paths during
            # this module's own development — every finding came back
            # `in_current_head=False` even for a secret confirmed still
            # present, until this was caught and fixed.
            await run_command(
                [
                    binary,
                    "dir",
                    ".",
                    "--report-format=json",
                    f"--report-path={dir_report}",
                    "--redact",
                    "--exit-code=0",
                    "--no-banner",
                ],
                timeout=self.settings.gitleaks_timeout,
                tool_name="gitleaks",
                cwd=clone_dir,
            )

            git_rows = _read_gitleaks_json(git_report)
            dir_keys = _dir_mode_keys(_read_gitleaks_json(dir_report))
            findings: list[dict[str, object]] = []
            for row in git_rows:
                key = (
                    str(row.get("File") or ""),
                    str(row.get("RuleID") or ""),
                    int(row.get("StartLine") or 0),
                )
                in_head = _is_in_current_head(key, dir_keys)
                findings.append(_finding_from_gitleaks_row(row, repo, in_current_head=in_head))
            return findings
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
