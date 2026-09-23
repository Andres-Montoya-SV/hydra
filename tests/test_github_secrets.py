"""`modules/github_secrets.py` — leaked-secrets detection in public
GitHub repositories.

`tests/fixtures/gitleaks_git_real_output.json` and
`gitleaks_dir_real_output.json` are REAL captures from actually running
`gitleaks git`/`gitleaks dir` 8.30.1 against a real, constructed test git
repository during this module's own development — not invented shapes.
That repo had a fake (non-live) `AKIA...` key rotated out of a later
commit and a fake Stripe-shaped key left in the current HEAD; gitleaks'
own real behavior against it is what these fixtures capture, including
the real correlation bug this module's own docstring documents (an
absolute vs. relative `File` path mismatch between `git` and `dir` mode
that silently broke `in_current_head` detection until caught by testing
a genuinely-still-present secret, not just a rotated one).
"""

from __future__ import annotations

import ast
import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from config.settings import Settings
from core.models import DomainTarget, PipelineContext
from modules.github_secrets import (
    GithubSecretsPlugin,
    _dir_mode_keys,
    _eligible,
    _finding_from_gitleaks_row,
    _is_in_current_head,
    _read_gitleaks_json,
    _Repo,
    _repo_from_api,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
_MODULE_SOURCE = Path(__file__).parent.parent / "modules" / "github_secrets.py"


def _real_repo() -> _Repo:
    return _Repo(
        full_name="acme/webapp",
        clone_url="https://github.com/acme/webapp.git",
        html_url="https://github.com/acme/webapp",
        private=False,
        fork=False,
    )


def _real_git_rows() -> list[dict[str, object]]:
    return _read_gitleaks_json(FIXTURES_DIR / "gitleaks_git_real_output.json")


def _real_dir_rows() -> list[dict[str, object]]:
    return _read_gitleaks_json(FIXTURES_DIR / "gitleaks_dir_real_output.json")


class TestRealFixtureCorrelation:
    """`_is_in_current_head`, `_scan_repo`'s exact correlation logic,
    against real captured gitleaks output — proves it correctly
    distinguishes the rotated key from the still-present one."""

    def test_rotated_key_is_historical_only(self) -> None:
        git_rows = _real_git_rows()
        dir_keys = _dir_mode_keys(_real_dir_rows())
        rotated = next(r for r in git_rows if r["RuleID"] == "generic-api-key")
        key = (rotated["File"], rotated["RuleID"], rotated["StartLine"])
        assert _is_in_current_head(key, dir_keys) is False

    def test_still_present_key_is_in_current_head(self) -> None:
        git_rows = _real_git_rows()
        dir_keys = _dir_mode_keys(_real_dir_rows())
        present = next(r for r in git_rows if r["RuleID"] == "stripe-access-token")
        key = (present["File"], present["RuleID"], present["StartLine"])
        assert _is_in_current_head(key, dir_keys) is True


class TestIsInCurrentHeadAmbiguityGuard:
    """Regression test for a real bug this module's own test suite
    caught: when two DIFFERENT secrets in the same file share the same
    RuleID, a loose (File, RuleID)-only fallback (ignoring StartLine)
    cannot tell them apart and would wrongly mark a rotated one as still
    current. The fix requires the fallback to be unambiguous."""

    def test_exact_line_match_wins_even_with_other_same_rule_entries(self) -> None:
        dir_keys = {("config.py", "generic-api-key", 2)}
        assert _is_in_current_head(("config.py", "generic-api-key", 2), dir_keys) is True

    def test_ambiguous_same_file_and_rule_without_line_match_is_not_current(self) -> None:
        """Two dir-mode entries share (File, RuleID) — the exact bug: a
        rotated secret at line 1 must NOT be matched against a different,
        still-present secret at line 2 just because they share a rule."""
        dir_keys = {
            ("config.py", "generic-api-key", 2),
            ("config.py", "generic-api-key", 5),
        }
        assert _is_in_current_head(("config.py", "generic-api-key", 1), dir_keys) is False

    def test_unambiguous_single_candidate_line_drift_still_matches(self) -> None:
        """Exactly one dir-mode candidate for (File, RuleID) — safe to
        assume it's the same secret even if its line number drifted."""
        dir_keys = {("config.py", "generic-api-key", 7)}
        assert _is_in_current_head(("config.py", "generic-api-key", 1), dir_keys) is True

    def test_no_candidate_at_all_is_not_current(self) -> None:
        dir_keys: set[tuple[str, str, int]] = set()
        assert _is_in_current_head(("config.py", "generic-api-key", 1), dir_keys) is False


class TestFindingFromGitleaksRow:
    def test_current_head_finding_is_critical_high_confidence(self) -> None:
        row = next(r for r in _real_git_rows() if r["RuleID"] == "stripe-access-token")
        finding = _finding_from_gitleaks_row(row, _real_repo(), in_current_head=True)
        assert finding["severity"] == "critical"
        assert finding["confidence_score"] == 90
        assert finding["in_current_head"] is True
        assert finding["commit"] == row["Commit"]
        assert finding["url"] == (
            f"https://github.com/acme/webapp/blob/{row['Commit']}/config.py#L2"
        )

    def test_historical_only_finding_is_medium_lower_confidence(self) -> None:
        row = next(r for r in _real_git_rows() if r["RuleID"] == "generic-api-key")
        finding = _finding_from_gitleaks_row(row, _real_repo(), in_current_head=False)
        assert finding["severity"] == "medium"
        assert finding["confidence_score"] == 60
        assert finding["in_current_head"] is False
        assert "may already be rotated" in finding["description_full"]


class TestRedactionGuarantee:
    """The single most important test in this module. Proves the raw
    secret value never appears anywhere in Hydra's own stored finding,
    even when a crafted, realistic-looking (fake) secret value is
    deliberately present in the raw gitleaks row's `Secret`/`Match`
    fields — not merely when they're already "REDACTED"."""

    # Deliberately NOT shaped like any real vendor's key format (no
    # "sk_live_"/"ghp_"/etc. prefix or checksum) — a realistic-entropy
    # placeholder is enough to prove the redaction guarantee, and a
    # vendor-shaped string here would itself trip GitHub's own push-
    # protection secret scanner on this very commit (confirmed the hard
    # way: an earlier version of this fixture using a Stripe-key-shaped
    # value was rejected by `git push` for exactly that reason).
    _FAKE_LIVE_SECRET = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"  # noqa: S105

    def _unredacted_row(self) -> dict[str, object]:
        return {
            "RuleID": "generic-api-key",
            "Description": "Detected a Generic API Key",
            "StartLine": 2,
            "EndLine": 2,
            "Match": f"SECRET_KEY = '{self._FAKE_LIVE_SECRET}'",
            "Secret": self._FAKE_LIVE_SECRET,
            "File": "config.py",
            "Commit": "58dd9c9f672e90991431b7998d213020e7fa3fae",
            "Author": "Test User",
            "Email": "test@example.com",
            "Date": "2026-09-23T13:25:04Z",
        }

    def test_the_fake_secret_never_appears_in_the_finding_record(self) -> None:
        finding = _finding_from_gitleaks_row(
            self._unredacted_row(), _real_repo(), in_current_head=True
        )
        serialized = json.dumps(finding)
        assert self._FAKE_LIVE_SECRET not in serialized

    def test_the_fake_secret_never_appears_in_the_written_jsonl_file(self, tmp_path: Path) -> None:
        from utils.files import write_jsonl

        finding = _finding_from_gitleaks_row(
            self._unredacted_row(), _real_repo(), in_current_head=True
        )
        output_path = tmp_path / "github_secrets.jsonl"
        write_jsonl(output_path, [finding], base_dir=tmp_path)
        written = output_path.read_text(encoding="utf-8")
        assert self._FAKE_LIVE_SECRET not in written

    def test_module_source_never_accesses_the_secret_or_match_keys(self) -> None:
        """Structural proof, not just a behavioral one: parses this
        module's own AST and asserts no `dict["Secret"]`/`dict.get("Secret")`
        (or `"Match"`) access exists anywhere in the file. A future edit
        that reintroduces reading the raw secret would fail this test even
        if its behavioral effect were otherwise masked by other logic —
        immune to the docstring itself mentioning "Secret"/"Match" as
        words, since this only inspects real subscript/`.get()` AST nodes."""
        tree = ast.parse(_MODULE_SOURCE.read_text(encoding="utf-8"))
        forbidden = {"Secret", "Match"}
        offenders: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                key_node = node.slice
                if isinstance(key_node, ast.Constant) and key_node.value in forbidden:
                    offenders.append(f"subscript access to {key_node.value!r}")
            elif isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "get"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value in forbidden
                ):
                    offenders.append(f".get({node.args[0].value!r})")

        assert offenders == [], f"module reads a forbidden key: {offenders}"


class TestNoCredentialValidationOrUse:
    def test_no_authentication_related_calls_against_a_discovered_secret(self) -> None:
        """Grep-level guard: this module must never construct an HTTP
        request, boto3/cloud SDK call, or similar authenticated action
        using a value read from a gitleaks row. Combined with the AST
        test above (the row's Secret/Match are never even read), this
        makes such a call structurally impossible, but this test also
        guards against a future contributor adding a *new* credential
        field (e.g. a hypothetical future gitleaks field) and wiring it
        into a validation call without updating the AST guard above."""
        source = _MODULE_SOURCE.read_text(encoding="utf-8")
        forbidden_signals = ("boto3", "requests.", "validate_credential", "test_credential")
        for signal in forbidden_signals:
            assert signal not in source


class TestEligibility:
    def test_private_repo_is_never_eligible_even_with_forks_allowed(self) -> None:
        repo = _Repo(
            full_name="acme/secret-repo",
            clone_url="https://x",
            html_url="https://x",
            private=True,
            fork=False,
        )
        assert _eligible(repo, include_forks=True) is False

    def test_fork_excluded_by_default(self) -> None:
        repo = _Repo(
            full_name="acme/forked",
            clone_url="https://x",
            html_url="https://x",
            private=False,
            fork=True,
        )
        assert _eligible(repo, include_forks=False) is False

    def test_fork_included_when_opted_in(self) -> None:
        repo = _Repo(
            full_name="acme/forked",
            clone_url="https://x",
            html_url="https://x",
            private=False,
            fork=True,
        )
        assert _eligible(repo, include_forks=True) is True

    def test_public_non_fork_is_eligible(self) -> None:
        repo = _Repo(
            full_name="acme/webapp",
            clone_url="https://x",
            html_url="https://x",
            private=False,
            fork=False,
        )
        assert _eligible(repo, include_forks=False) is True

    def test_missing_clone_url_is_not_eligible(self) -> None:
        repo = _Repo(
            full_name="acme/webapp", clone_url="", html_url="https://x", private=False, fork=False
        )
        assert _eligible(repo, include_forks=False) is False


class TestRepoFromApi:
    def test_parses_a_realistic_github_api_repo_object(self) -> None:
        data = {
            "full_name": "acme/webapp",
            "clone_url": "https://github.com/acme/webapp.git",
            "html_url": "https://github.com/acme/webapp",
            "private": False,
            "fork": False,
        }
        repo = _repo_from_api(data)
        assert repo.full_name == "acme/webapp"
        assert repo.private is False
        assert repo.fork is False

    def test_private_flag_is_read_correctly(self) -> None:
        repo = _repo_from_api({"full_name": "acme/internal", "private": True})
        assert repo.private is True


class TestNeverTouchesTargetInfrastructure:
    def test_active_collection_is_false(self) -> None:
        """Never gated on CollectionScope/AuthorizedCollectionTarget — it
        never connects to the target's own infrastructure at all, only
        to GitHub's own API and GitHub-hosted repository content."""
        assert GithubSecretsPlugin.active_collection is False


class TestRepoDiscovery:
    """`_discover_repos`'s three real paths: explicit org (always
    preferred), token-gated code-search fallback, and the honest
    skip-with-warning when neither is configured."""

    def _context(self, tmp_path: Path) -> PipelineContext:
        return PipelineContext(targets=[DomainTarget(domain="example.com")], output_dir=tmp_path)

    @pytest.mark.asyncio
    async def test_explicit_org_is_always_preferred_over_search(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import modules.github_secrets as gs

        settings = Settings(
            project_root=tmp_path,
            enable_github_secrets=True,
            github_org="acme",
            github_token="fake-token",  # noqa: S106
        )
        plugin = GithubSecretsPlugin(settings)
        org_repo = _Repo(
            full_name="acme/one",
            clone_url="https://x",
            html_url="https://x",
            private=False,
            fork=False,
        )
        search_called = False

        def fake_org(*args: object, **kwargs: object) -> list[_Repo]:
            return [org_repo]

        def fake_search(*args: object, **kwargs: object) -> list[_Repo]:
            nonlocal search_called
            search_called = True
            return []

        monkeypatch.setattr(gs, "_fetch_org_repos", fake_org)
        monkeypatch.setattr(gs, "_fetch_search_code_repos", fake_search)

        repos = await plugin._discover_repos(self._context(tmp_path))
        assert repos == [org_repo]
        assert search_called is False

    @pytest.mark.asyncio
    async def test_org_results_are_filtered_for_eligibility(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import modules.github_secrets as gs

        settings = Settings(project_root=tmp_path, enable_github_secrets=True, github_org="acme")
        plugin = GithubSecretsPlugin(settings)
        public_repo = _Repo(
            full_name="acme/public",
            clone_url="https://x",
            html_url="https://x",
            private=False,
            fork=False,
        )
        private_repo = _Repo(
            full_name="acme/private",
            clone_url="https://x",
            html_url="https://x",
            private=True,
            fork=False,
        )

        monkeypatch.setattr(gs, "_fetch_org_repos", lambda *a, **k: [public_repo, private_repo])

        repos = await plugin._discover_repos(self._context(tmp_path))
        assert repos == [public_repo]

    @pytest.mark.asyncio
    async def test_no_org_no_token_skips_with_a_warning_not_silently(self, tmp_path: Path) -> None:
        settings = Settings(project_root=tmp_path, enable_github_secrets=True)
        plugin = GithubSecretsPlugin(settings)
        context = self._context(tmp_path)

        repos = await plugin._discover_repos(context)
        assert repos == []
        assert any("GITHUB_ORG" in w or "GITHUB_TOKEN" in w for w in context.warnings)

    @pytest.mark.asyncio
    async def test_token_without_org_falls_back_to_code_search(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import modules.github_secrets as gs

        settings = Settings(
            project_root=tmp_path,
            enable_github_secrets=True,
            github_token="fake-token",  # noqa: S106
        )
        plugin = GithubSecretsPlugin(settings)
        found_repo = _Repo(
            full_name="acme/found",
            clone_url="https://x",
            html_url="https://x",
            private=False,
            fork=False,
        )
        seen_domains: list[str] = []

        def fake_search(domain: str, *args: object, **kwargs: object) -> list[_Repo]:
            seen_domains.append(domain)
            return [found_repo]

        monkeypatch.setattr(gs, "_fetch_search_code_repos", fake_search)

        repos = await plugin._discover_repos(self._context(tmp_path))
        assert repos == [found_repo]
        assert seen_domains == ["example.com"]


_GITLEAKS_AVAILABLE = shutil.which("gitleaks") is not None and shutil.which("git") is not None


@pytest.mark.skipif(
    not _GITLEAKS_AVAILABLE, reason="requires real git and gitleaks binaries on PATH"
)
class TestRealEndToEndScan:
    """Builds a real local git repository (a fake, rotated-then-replaced
    credential, and a second, still-present fake credential), then runs
    the actual `_scan_repo` method against it — real `git clone`, real
    `gitleaks git`/`gitleaks dir` subprocesses, no mocking. Proves the
    whole pipeline end to end, not just its individual pieces."""

    def _build_test_repo(self, path: Path) -> None:
        def git(*args: str) -> None:
            subprocess.run(  # noqa: S603
                ["git", *args], cwd=path, check=True, capture_output=True  # noqa: S607
            )

        path.mkdir()
        git("init", "-q")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Test User")

        (path / "config.py").write_text("AWS_KEY = 'AKIAZQ7X9ZK2M4P8WRTY'\n")
        git("add", "config.py")
        git("commit", "-q", "-m", "initial config with key")

        (path / "config.py").write_text("AWS_KEY = os.environ['AWS_KEY']\n")
        git("add", "config.py")
        git("commit", "-q", "-m", "rotate key, read from env")

        # A second, still-present fake credential in a SEPARATE file —
        # deliberately a plain sequential-alphanumeric value with no
        # recognizable vendor prefix or checksum (not "sk_live_..."/
        # "ghp_..."/etc.), so it still trips gitleaks' own generic-api-key
        # rule without also tripping GitHub's own push-protection secret
        # scanner on this very test file (a vendor-shaped fake Stripe key
        # in an earlier version of this fixture was rejected by `git push`
        # for exactly that reason). A separate file, not a second line in
        # config.py, deliberately avoids a DIFFERENT real limitation this
        # module's own docstring documents: two distinct secrets sharing
        # both File and RuleID cannot be told apart by the (File, RuleID)
        # fallback once their exact line match fails.
        (path / "settings.py").write_text(
            "SECRET_KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'\n"
        )
        git("add", "settings.py")
        git("commit", "-q", "-m", "add secret key")

    def test_real_scan_distinguishes_rotated_from_current(self, tmp_path: Path) -> None:
        repo_path = tmp_path / "source_repo"
        self._build_test_repo(repo_path)

        settings = Settings(project_root=tmp_path, enable_github_secrets=True)
        plugin = GithubSecretsPlugin(settings)
        repo = _Repo(
            full_name="test/real-e2e",
            clone_url=f"file://{repo_path}",
            html_url="https://github.com/test/real-e2e",
            private=False,
            fork=False,
        )

        findings = asyncio.run(plugin._scan_repo(repo))
        assert len(findings) == 2
        by_file = {f["file"]: f for f in findings}

        assert by_file["config.py"]["in_current_head"] is False
        assert by_file["config.py"]["severity"] == "medium"
        assert by_file["settings.py"]["in_current_head"] is True
        assert by_file["settings.py"]["severity"] == "critical"

        # The real worked example this task asked to see in the PR:
        serialized = json.dumps(findings, indent=2)
        print("\n--- real worked example (redacted, stored shape) ---")
        print(serialized)
        assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0" not in serialized
        assert "AKIAZQ7X9ZK2M4P8WRTY" not in serialized
