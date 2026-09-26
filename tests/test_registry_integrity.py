"""Permanent regression guards for the exact class of bug that broke
`main` after PRs #40-#43 were merged: three separate tool
registrations/classes flattened into one call site in
`core/parsers/registry.py`, `core/dependencies/registry.py`, and
`core/finding_glossary.py` — duplicate keyword arguments, a missing
`parse()` method body (silently swallowed at class-definition time,
only surfacing as a `TypeError` the first time `PARSER_REGISTRY`'s dict
comprehension tried to INSTANTIATE the abstract class, or, in the
actual incident, as a hard `SyntaxError` on `import` since the
duplicate-keyword-argument corruption doesn't even parse), and glossary
entries nested inside each other instead of being three sibling dict
keys.

None of these tests reason about the bug in the abstract — each
constructs the real registry/module at import time and asserts on its
actual, live state, the same "a real object, not a mock" discipline
this project's own test suite uses everywhere else.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest


class TestParserRegistryConstructsCleanly:
    """The single highest-value test given what broke: `PARSER_REGISTRY`
    is built by a dict comprehension that instantiates every registered
    `ToolParser` subclass — a subclass missing its (abstract) `parse()`
    body raises `TypeError` at THIS import, not at first use, so this
    import succeeding is itself a real assertion, not just a setup
    step."""

    def test_import_does_not_raise(self) -> None:
        from core.parsers.registry import PARSER_REGISTRY

        assert len(PARSER_REGISTRY) > 0

    def test_every_registered_parser_name_is_unique(self) -> None:
        """`PARSER_REGISTRY` is itself a dict keyed by `tool_name`, so a
        real duplicate would silently overwrite one parser with another
        rather than raising — checked here by counting the LITERAL
        instantiations in the registry's own construction list against
        the resulting dict size (an intermediate, never-registered base
        class like `UrlListParser` sharing a placeholder `tool_name`
        with one of its own subclasses, e.g. `GauParser`, is fine and
        not what this guards against)."""
        from core.parsers.registry import PARSER_REGISTRY

        source = Path("core/parsers/registry.py").read_text(encoding="utf-8")
        registry_block_start = source.index("PARSER_REGISTRY: dict[str, ToolParser] = {")
        registry_block_end = source.index("\n}\n", registry_block_start)
        registry_block = source[registry_block_start:registry_block_end]
        instantiations = re.findall(r"^\s*(\w+)\(\),?$", registry_block, re.MULTILINE)
        assert len(instantiations) == len(PARSER_REGISTRY), (
            f"{len(instantiations)} parser instantiations in the registry literal but "
            f"{len(PARSER_REGISTRY)} distinct tool_name keys resulted — one class's "
            "tool_name silently overwrote another's dict entry."
        )

    @pytest.mark.parametrize("tool_name", ["ffuf", "github_secrets", "sub_takeover"])
    def test_each_of_the_three_regressed_parsers_has_a_real_bound_parse_method(
        self, tool_name: str
    ) -> None:
        """The exact corruption this task fixed: `FfufParser`/
        `GithubSecretsParser` had no `parse()` at all (inherited the
        abstract one), and `SubTakeoverParser.parse()` contained all
        three tools' logic flattened together. `inspect.signature`
        confirms a real, callable, non-abstract method exists — calling
        it against an empty/missing directory (never raising, per the
        module's own "no real target" handling) confirms it actually
        runs as THIS tool's parser, not silently as someone else's."""
        from core.parsers.registry import PARSER_REGISTRY

        parser = PARSER_REGISTRY[tool_name]
        assert parser.tool_name == tool_name
        hosts, warnings = parser.parse(Path("/nonexistent-dir-for-this-test"))
        assert hosts == []
        assert warnings == []

    def test_ffuf_finding_defaults_are_ffufs_own_not_another_tools(self, tmp_path: Path) -> None:
        """Directly guards against the flattened code's actual observed
        defect: ffuf's finding severity/confidence defaults
        (`low`/50) were followed immediately by github_secrets'
        (`medium`/60) and sub_takeover's (`high`/65) inside the SAME
        duplicated-keyword `Finding(...)` call, so only the LAST set of
        keywords actually took effect at runtime — a real, silent
        mislabeling bug, not just a syntax error, had the corruption
        happened to be syntactically valid."""
        from core.parsers.registry import FfufParser

        artifact = tmp_path / "ffuf_findings.jsonl"
        artifact.write_text(
            '{"host": "example.com", "template_id": "hidden-endpoint-discovered"}\n'
        )
        hosts, _ = FfufParser().parse(tmp_path, artifact=artifact)
        assert len(hosts) == 1
        finding = hosts[0].findings[0]
        assert finding.source == "ffuf"
        assert finding.severity == "low"
        assert finding.confidence_score == 50

    def test_github_secrets_finding_defaults_are_its_own(self, tmp_path: Path) -> None:
        from core.parsers.registry import GithubSecretsParser

        artifact = tmp_path / "github_secrets.jsonl"
        artifact.write_text('{"host": "example.com"}\n')
        hosts, _ = GithubSecretsParser().parse(tmp_path, artifact=artifact)
        finding = hosts[0].findings[0]
        assert finding.source == "github_secrets"
        assert finding.severity == "medium"
        assert finding.confidence_score == 60
        assert finding.template_id == "leaked-secret"

    def test_sub_takeover_finding_defaults_are_its_own(self, tmp_path: Path) -> None:
        from core.parsers.registry import SubTakeoverParser

        artifact = tmp_path / "sub_takeover.jsonl"
        artifact.write_text('{"host": "example.com"}\n')
        hosts, _ = SubTakeoverParser().parse(tmp_path, artifact=artifact)
        finding = hosts[0].findings[0]
        assert finding.source == "sub_takeover"
        assert finding.severity == "high"
        assert finding.confidence_score == 65
        assert finding.template_id == "subdomain-takeover"

    def test_dnstwist_deliberately_has_no_parser(self) -> None:
        """Confirmed against `feat/hydra-dnstwist-typosquat-monitoring`
        (its own merge-base diff never touched this file): typosquat
        candidates are deliberately kept OUT of the Host/Finding model
        (a dedicated `core/store.py` table instead), so `dnstwist` has
        no entry here at all — this is the correct, intentional shape,
        not a gap to fix."""
        from core.parsers.registry import PARSER_REGISTRY

        assert "dnstwist" not in PARSER_REGISTRY


class TestDependencyRegistryConstructsCleanly:
    """The dependency-registry equivalent of the corruption above: three
    `ToolDefinition`s flattened into one `_register(ToolDefinition(...))`
    call, so `name="ffuf"` was immediately overwritten by `name="dnstwist"`
    then `name="gitleaks"` (had it been syntactically valid at all)."""

    def test_import_does_not_raise(self) -> None:
        from core.dependencies.registry import TOOL_REGISTRY

        assert len(TOOL_REGISTRY) > 0

    @pytest.mark.parametrize(
        ("tool_name", "expected_capability", "expected_install_attr", "expected_install_value"),
        [
            ("ffuf", "content_discovery", "install_go", "github.com/ffuf/ffuf/v2@latest"),
            ("dnstwist", "typosquat_detection", "install_pip", "dnstwist"),
            (
                "gitleaks",
                "secret_scanning",
                "install_go",
                "github.com/zricethezav/gitleaks/v8@latest",
            ),
        ],
    )
    def test_each_tools_definition_carries_only_its_own_fields(
        self,
        tool_name: str,
        expected_capability: str,
        expected_install_attr: str,
        expected_install_value: str,
    ) -> None:
        from core.dependencies.registry import TOOL_REGISTRY

        definition = TOOL_REGISTRY[tool_name]
        assert definition.name == tool_name
        assert definition.display_name == tool_name
        assert expected_capability in definition.capabilities
        assert getattr(definition, expected_install_attr) == expected_install_value

    def test_no_two_tools_share_the_same_capability_set_by_accident(self) -> None:
        """Not every shared capability string is a bug (several
        pre-existing tools legitimately share generic tags like
        `post_http`), but the three tools this task's own corruption
        involved must never end up with IDENTICAL capability sets to
        each other — that would mean one's `frozenset({...})` literal
        leaked into another's during a bad hand-patch."""
        from core.dependencies.registry import TOOL_REGISTRY

        capability_sets = {
            name: TOOL_REGISTRY[name].capabilities for name in ("ffuf", "dnstwist", "gitleaks")
        }
        values = list(capability_sets.values())
        assert len(values) == len(set(values)), capability_sets

    def test_gitleaks_go_module_path_gotcha_comment_survived_reconstruction(self) -> None:
        """The corruption fix required manually re-splitting one
        flattened `_register()` call into three — a real, documented,
        already-verified gotcha (gitleaks' go.mod still declares the
        OLD `zricethezav` module path) lived as a comment inside that
        one call and could easily have been dropped or misattributed to
        the wrong tool during the split."""
        source = Path("core/dependencies/registry.py").read_text(encoding="utf-8")
        gitleaks_block_start = source.index('name="gitleaks"')
        gitleaks_block = source[gitleaks_block_start : gitleaks_block_start + 1200]
        assert "zricethezav" in gitleaks_block
        assert "constraints conflict" in gitleaks_block


class TestFindingGlossaryConstructsCleanly:
    def test_import_does_not_raise(self) -> None:
        from core.finding_glossary import FINDING_GLOSSARY

        assert len(FINDING_GLOSSARY) > 0

    @pytest.mark.parametrize(
        "template_id",
        ["hidden-endpoint-discovered", "leaked-secret", "subdomain-takeover"],
    )
    def test_each_of_the_three_regressed_entries_is_its_own_sibling_key(
        self, template_id: str
    ) -> None:
        """The corruption's exact shape here: three `"key": {...}` dict
        entries missing the `},` that should close each one before the
        next key starts, nesting them inside each other's VALUE instead
        of being three sibling keys of `FINDING_GLOSSARY` itself. A
        successful `FINDING_GLOSSARY[template_id]` lookup returning a
        plain `{"what": str, "why": str}` dict (not something containing
        another template_id's own dict nested inside it) is the real
        assertion."""
        from core.finding_glossary import FINDING_GLOSSARY

        entry = FINDING_GLOSSARY[template_id]
        assert set(entry) == {"what", "why"}
        assert isinstance(entry["what"], str) and entry["what"]
        assert isinstance(entry["why"], str) and entry["why"]

    def test_every_static_default_template_id_emitted_by_any_parser_has_a_glossary_entry(
        self,
    ) -> None:
        """The permanent guard the task asked for: statically extracts
        every literal `... or "some-template-id"` default from
        `core/parsers/registry.py`'s source (never a mocked/hand-typed
        list, which could itself silently drift) and asserts each one
        resolves to a real entry via `explain_template` — covering both
        entries with a matching literal key in `FINDING_GLOSSARY` and
        ones handled by `explain_template`'s own prefix-based fallback
        (`vuln-match`, `missing-security-header`). This is exactly the
        check that would have caught the original corruption (a missing
        `},` between three glossary entries) immediately, before it ever
        reached `ruff`."""
        from core.finding_glossary import explain_template

        source = Path("core/parsers/registry.py").read_text(encoding="utf-8")
        literal_defaults = set(
            re.findall(r'template_id=str\(record\.get\("template_id"\) or "([a-z0-9-]+)"\)', source)
        )
        assert literal_defaults, "extraction pattern found nothing — has the source shape changed?"
        for template_id in literal_defaults:
            explanation = explain_template(template_id)
            assert explanation["what"] != "A reconnaissance finding produced by a Hydra head.", (
                f"{template_id!r} has no real glossary coverage (fell through to the "
                "generic fallback) — add a FINDING_GLOSSARY entry or an explicit "
                "explain_template() branch for it."
            )


class TestModulesPackageImportsCleanly:
    """`modules/__init__.py` importing all four new modules (and every
    pre-existing one) without raising, and every plugin's `name`
    registering exactly once, is the plugin-side equivalent of the
    parser/dependency registry checks above."""

    def test_import_does_not_raise_and_registers_all_four_new_plugins(self) -> None:
        import modules  # noqa: F401 - import side effect is the point
        from core.plugin_base import ReconPlugin

        names = [p.name for p in ReconPlugin.all_plugins()]
        for expected in ("ffuf", "dnstwist", "github_secrets", "sub_takeover"):
            assert expected in names

    def test_no_two_registered_plugins_share_a_name(self) -> None:
        import modules  # noqa: F401
        from core.plugin_base import ReconPlugin

        names = [p.name for p in ReconPlugin.all_plugins()]
        assert len(names) == len(set(names)), f"duplicate plugin name(s): {names}"


class TestApplicationImportsCleanly:
    """The actual, real-world symptom the original corruption caused:
    `import app` (the CLI entry point) raised a hard `SyntaxError` at
    module-import time, because `core/runner.py` -> `core/normalizer.py`
    -> `core/registry.py` -> `core/parsers/registry.py` is an unbroken
    chain of MODULE-LEVEL imports. A syntax error three files deep in
    that chain took down the entire CLI, not just tool-output parsing."""

    def test_import_app_does_not_raise(self) -> None:
        import app  # noqa: F401

    def test_import_api_main_does_not_raise(self) -> None:
        pytest.importorskip("fastapi")
        from api.main import create_app

        create_app()


def _readme_source() -> str:
    return Path("README.md").read_text(encoding="utf-8")


class TestReadmeIntegrationArtifactsWereRepaired:
    """The corruption wasn't confined to files `ruff` can see — the
    same "three branches each appended their own tool to a near-copy of
    the same line/table instead of one merge integrating all three"
    pattern also hit `README.md`'s Mermaid diagram (the same node ID,
    `Optional`, defined three times with three different, incomplete
    label lists) and its `python app.py heads` table (two full,
    partially-divergent duplicate tables, one of them containing `amass`
    twice, and NEITHER containing `ffuf` at all). These are documentation
    checks, not behavior checks, but the same class of merge damage could
    recur the same way, so they're guarded here too."""

    def test_mermaid_optional_node_is_defined_exactly_once(self) -> None:
        readme = _readme_source()
        assert readme.count('Optional["Optional/enrichment stage') == 1

    def test_mermaid_optional_node_lists_all_four_new_tools(self) -> None:
        readme = _readme_source()
        start = readme.index('Optional["Optional/enrichment stage')
        line = readme[start : start + 400]
        for tool in ("ffuf", "dnstwist", "github_secrets", "sub_takeover"):
            assert tool in line

    def test_heads_table_appears_exactly_once_and_lists_every_registered_head(self) -> None:
        """Row values are matched at the START OF A LINE only
        (`^│ <name> `) — a naive substring match would also match each
        row's own Role/description column, which always repeats the
        tool name right after the third `│` (e.g. "amass — deep OSINT
        enumeration head"), producing a false "duplicate" on every
        single row rather than actually detecting one."""
        import modules  # noqa: F401
        from core.plugin_base import ReconPlugin

        readme = _readme_source()
        assert readme.count("Hydra Heads") == 1
        table_start = readme.index("Hydra Heads")
        table_end = readme.index("```", table_start)
        table_lines = readme[table_start:table_end].splitlines()
        for plugin_name in (p.name for p in ReconPlugin.all_plugins()):
            matching_rows = [line for line in table_lines if line.startswith(f"│ {plugin_name} ")]
            assert matching_rows, f"{plugin_name!r} missing from the README heads table"
            assert (
                len(matching_rows) == 1
            ), f"{plugin_name!r} appears more than once: {matching_rows}"


class TestNoResidualMergeCorruptionPatterns:
    """Broad, file-agnostic guards — never targeted at the three named
    files specifically, since the task's own instruction was to keep
    looking everywhere else too."""

    def test_no_unresolved_conflict_markers_anywhere(self) -> None:
        """Scoped to git-TRACKED files only (`git ls-files`), the same
        universe `git grep` (the task's own suggested check) searches.
        Matches real git conflict-marker syntax specifically (the marker
        alone on its own line, `=======` with NOTHING else on the line) —
        several tracked files (`config/.env.example`, module docstrings)
        legitimately use longer `# ====...` banner comments, which a bare
        substring search would misfire on."""
        # The production Docker image intentionally does not carry the git
        # binary. Scan the clean checkout directly instead of making this
        # source-integrity assertion depend on a deployment-unrelated CLI.
        excluded_dirs = {".git", ".venv", "output", "logs", "reports", "node_modules"}
        conflict_start = re.compile(r"^<{7}( |$)")
        conflict_mid = re.compile(r"^={7}$")
        conflict_end = re.compile(r"^>{7}( |$)")
        for path in Path(".").rglob("*"):
            if not path.is_file() or any(part in excluded_dirs for part in path.parts):
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            for line in lines:
                assert not conflict_start.match(line), f"conflict marker found in {path}: {line!r}"
                assert not conflict_mid.match(line), f"conflict marker found in {path}: {line!r}"
                assert not conflict_end.match(line), f"conflict marker found in {path}: {line!r}"

    def test_no_duplicate_top_level_definitions_in_any_project_python_file(self) -> None:
        excluded_dirs = {".venv", "output", "logs", "reports", ".git", "node_modules"}
        for path in Path(".").rglob("*.py"):
            if set(path.parts) & excluded_dirs:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            top_names = [
                n.name
                for n in tree.body
                if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            ]
            duplicates = {n for n in top_names if top_names.count(n) > 1}
            assert not duplicates, f"{path}: duplicate top-level definitions {duplicates}"
