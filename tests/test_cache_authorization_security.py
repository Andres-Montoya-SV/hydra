"""Security audit (hardening round 1, Tasks 1-2): the result_cache
(`ENABLE_CACHE`) never becomes a source of authorization, and cached data
can never reach active collection / follow-up without re-validating
against the *current* scope.

`result_cache` (core/store.py) is a deliberately global, cross-run table —
no `run_id` column at all (confirmed by reading the schema). Its cache_key
(`PipelineRunner._cache_key`) is therefore the entire security boundary:
anything that changes whether a cached artifact should be reused MUST
change the key, or it will be silently reused across an incompatible
context. This file proves, with real components (not mocks of the
authorization layer itself), that the key includes everything it needs to.
"""

from __future__ import annotations

from pathlib import Path

from config.settings import Settings
from core.collectors import plugin_classes
from core.intel.authorize import authorize_active_indicator
from core.intel.scope import CollectionScope
from core.models import PipelineContext
from core.runner import PipelineRunner
from core.store import AssetStore
from modules.whois import WhoisPlugin


def _settings(project_root: Path, **overrides: object) -> Settings:
    kwargs: dict[str, object] = {"project_root": project_root}
    kwargs.update(overrides)
    return Settings(**kwargs)


def _seed_cache_entry(runner: PipelineRunner, plugin, input_path: Path) -> None:
    cache_key, input_hash = runner._cache_key(plugin, input_path)  # noqa: SLF001
    runner._store.set_cache_entry(  # noqa: SLF001
        cache_key,
        tool=plugin.name,
        input_hash=input_hash,
        artifact_path=str(input_path),
        lines_produced=1,
        ttl_seconds=3600,
    )


class TestCacheKeyIncludesScopeAndAttributionIdentity:
    """Task 1: the cache key must change whenever the *authorization
    context* changes, even when the filtered input file's bytes happen to
    be identical — otherwise two different SCOPE_FILEs (two different
    programs/engagements) that happen to authorize the same literal
    hostname would silently share one cached artifact, including whatever
    researcher attribution header/UA it was actually fetched under
    (invariant 10: historical data must never cross incompatible scopes).
    """

    def test_same_settings_same_input_is_a_stable_key(
        self, project_root: Path, targets_file: Path
    ) -> None:
        settings = _settings(project_root)
        runner = PipelineRunner(settings)
        whois = WhoisPlugin(settings)
        key1, _ = runner._cache_key(whois, targets_file)  # noqa: SLF001
        key2, _ = runner._cache_key(whois, targets_file)  # noqa: SLF001
        assert key1 == key2

    def test_different_scope_file_changes_the_key_even_with_identical_input_bytes(
        self, project_root: Path, targets_file: Path
    ) -> None:
        """The exact scenario the audit asked to prove: scope=ejemplo.com
        vs scope=otro.com over the same cached target must never collide,
        even in the worst case where the filtered input file is
        byte-for-byte identical between the two runs."""
        scope_a = project_root / "scope_a.txt"
        scope_a.write_text("*.ejemplo.com\n", encoding="utf-8")
        scope_b = project_root / "scope_b.txt"
        scope_b.write_text("*.otro.com\n", encoding="utf-8")

        settings_a = _settings(project_root, scope_file=scope_a)
        settings_b = _settings(project_root, scope_file=scope_b)
        whois = WhoisPlugin(settings_a)

        key_a, _ = PipelineRunner(settings_a)._cache_key(whois, targets_file)  # noqa: SLF001
        key_b, _ = PipelineRunner(settings_b)._cache_key(whois, targets_file)  # noqa: SLF001
        assert key_a != key_b

    def test_no_scope_file_vs_a_scope_file_changes_the_key(
        self, project_root: Path, targets_file: Path
    ) -> None:
        scope_a = project_root / "scope.txt"
        scope_a.write_text("*.ejemplo.com\n", encoding="utf-8")
        settings_none = _settings(project_root)
        settings_with = _settings(project_root, scope_file=scope_a)
        whois = WhoisPlugin(settings_none)

        key_none, _ = PipelineRunner(settings_none)._cache_key(whois, targets_file)  # noqa: SLF001
        key_with, _ = PipelineRunner(settings_with)._cache_key(whois, targets_file)  # noqa: SLF001
        assert key_none != key_with

    def test_different_researcher_attribution_header_changes_the_key(
        self, project_root: Path, targets_file: Path
    ) -> None:
        """Two different researchers/programs (X-HackerOne-Research:
        alice vs. bob) must never silently share a cached artifact fetched
        under the other's identity."""
        settings_alice = _settings(
            project_root,
            researcher_attribution_header={"X-HackerOne-Research": "alice_h1"},
        )
        settings_bob = _settings(
            project_root,
            researcher_attribution_header={"X-HackerOne-Research": "bob_h1"},
        )
        whois = WhoisPlugin(settings_alice)

        key_alice, _ = PipelineRunner(settings_alice)._cache_key(
            whois, targets_file
        )  # noqa: SLF001
        key_bob, _ = PipelineRunner(settings_bob)._cache_key(whois, targets_file)  # noqa: SLF001
        assert key_alice != key_bob

    def test_different_attribution_user_agent_changes_the_key(
        self, project_root: Path, targets_file: Path
    ) -> None:
        settings_a = _settings(project_root, attribution_user_agent="bugcrowd; researcher_a")
        settings_b = _settings(project_root, attribution_user_agent="bugcrowd; researcher_b")
        whois = WhoisPlugin(settings_a)

        key_a, _ = PipelineRunner(settings_a)._cache_key(whois, targets_file)  # noqa: SLF001
        key_b, _ = PipelineRunner(settings_b)._cache_key(whois, targets_file)  # noqa: SLF001
        assert key_a != key_b

    def test_strict_opsec_and_proxy_mode_change_the_key(
        self, project_root: Path, targets_file: Path
    ) -> None:
        """Already-existing protection, re-confirmed with an explicit
        regression test (none existed naming this specific invariant
        before this audit)."""
        settings_direct = _settings(project_root)
        settings_strict = _settings(
            project_root, strict_opsec=True, outbound_proxy_url="http://proxy.example:8080"
        )
        whois = WhoisPlugin(settings_direct)

        key_direct, _ = PipelineRunner(settings_direct)._cache_key(
            whois, targets_file
        )  # noqa: SLF001
        key_strict, _ = PipelineRunner(settings_strict)._cache_key(
            whois, targets_file
        )  # noqa: SLF001
        assert key_direct != key_strict

    def test_different_proxy_url_under_strict_opsec_changes_the_key(
        self, project_root: Path, targets_file: Path
    ) -> None:
        settings_proxy_a = _settings(
            project_root, strict_opsec=True, outbound_proxy_url="http://proxy-a.example:8080"
        )
        settings_proxy_b = _settings(
            project_root, strict_opsec=True, outbound_proxy_url="http://proxy-b.example:8080"
        )
        whois = WhoisPlugin(settings_proxy_a)

        key_a, _ = PipelineRunner(settings_proxy_a)._cache_key(whois, targets_file)  # noqa: SLF001
        key_b, _ = PipelineRunner(settings_proxy_b)._cache_key(whois, targets_file)  # noqa: SLF001
        assert key_a != key_b


class TestCacheNeverServesAStaleAuthorizationDecision:
    """Task 1 (continued): a target authorized in a prior run but excluded
    today must never be served from cache — proven end to end through the
    real scope-filtering step (`authorize_plugin_input`), not just at the
    cache-key level.
    """

    def test_input_filtering_runs_before_cache_key_computation_so_an_excluded_host_never_enters_the_hash(
        self, project_root: Path
    ) -> None:
        from core.intel.scope import authorize_plugin_input

        # Separate output dirs, matching how the real pipeline gives every
        # run_id its own directory — authorize_plugin_input writes to a
        # fixed `authorized_<plugin>_<input name>` filename, so sharing one
        # directory between "run A" and "run B" in this test would let B's
        # write silently clobber A's file before A's content is read below.
        output_dir_a = project_root / "output" / "run_a"
        output_dir_a.mkdir(parents=True)
        output_dir_b = project_root / "output" / "run_b"
        output_dir_b.mkdir(parents=True)
        raw_input_a = output_dir_a / "resolved.txt"
        raw_input_a.write_text("admin.example.com\nwww.example.com\n", encoding="utf-8")
        raw_input_b = output_dir_b / "resolved.txt"
        raw_input_b.write_text("admin.example.com\nwww.example.com\n", encoding="utf-8")

        # Run A: both hosts authorized.
        scope_a = CollectionScope.from_seeds(["example.com"], patterns=["*.example.com"])
        context_a = PipelineContext(output_dir=output_dir_a, collection_scope=scope_a)
        filtered_a = authorize_plugin_input(
            context_a, raw_input_a, "httpx", capability="http_probe"
        )
        assert "admin.example.com" in filtered_a.read_text()

        # Run B: a fresh SCOPE_FILE exclusion now carves out admin.example.com
        # specifically — the exact "scope changed, exclusion added" case.
        scope_b = CollectionScope.from_seeds(
            ["example.com"], patterns=["*.example.com", "!admin.example.com"]
        )
        context_b = PipelineContext(output_dir=output_dir_b, collection_scope=scope_b)
        filtered_b = authorize_plugin_input(
            context_b, raw_input_b, "httpx", capability="http_probe"
        )
        content_b = filtered_b.read_text()
        assert "admin.example.com" not in content_b
        assert "www.example.com" in content_b

        # The filtered files differ, so a runner cache-keyed on the
        # filtered file's own bytes can never collide between A and B —
        # confirmed directly, not just inferred from the content differing.
        settings = _settings(project_root)
        runner = PipelineRunner(settings)
        whois = WhoisPlugin(settings)  # any cacheable plugin; key logic is generic
        key_a, _ = runner._cache_key(whois, filtered_a)  # noqa: SLF001
        key_b, _ = runner._cache_key(whois, filtered_b)  # noqa: SLF001
        assert key_a != key_b

    def test_previously_cached_artifact_for_a_now_excluded_host_is_never_looked_up(
        self, project_root: Path
    ) -> None:
        """End-to-end through the real runner cache API: cache a result
        keyed on the authorized-when-fetched filtered input, then prove a
        later, stricter scope's own filtered input never produces a
        matching key."""
        settings = _settings(project_root)
        runner = PipelineRunner(settings)
        runner._store = AssetStore(project_root / "output" / "recon.db")  # noqa: SLF001

        output_dir = project_root / "output" / "run1"
        output_dir.mkdir(parents=True)
        whois = WhoisPlugin(settings)

        # A prior run's filtered/authorized input included the host.
        old_filtered = output_dir / "authorized_whois_targets.txt"
        old_filtered.write_text("admin.example.com\n", encoding="utf-8")
        _seed_cache_entry(runner, whois, old_filtered)
        assert runner._load_cached_result(  # noqa: SLF001
            PipelineContext(output_dir=output_dir), whois, old_filtered
        )

        # Today's scope excludes it — its filtered input is now empty for
        # that host, never matching the stale cache entry above.
        from core.intel.scope import authorize_plugin_input

        raw_input = output_dir / "targets.txt"
        raw_input.write_text("admin.example.com\n", encoding="utf-8")
        scope_today = CollectionScope.from_seeds(
            ["example.com"], patterns=["*.example.com", "!admin.example.com"]
        )
        context_today = PipelineContext(output_dir=output_dir, collection_scope=scope_today)
        new_filtered = authorize_plugin_input(
            context_today, raw_input, "whois", capability="registration_lookup"
        )
        assert "admin.example.com" not in new_filtered.read_text()
        assert (
            runner._load_cached_result(context_today, whois, new_filtered) is None  # noqa: SLF001
        )


class TestCacheNeverBypassesAuthorization:
    """Task 2: confirm — with an explicit test, not by assumption — that
    an indicator ingested from a *cache-restored* artifact carries no
    special status. There is no "cached" flag anywhere in
    core/intel/authorize.py, core/collection/*.py, or the follow-up
    planner/queue (grepped directly) for a bypass to hide in; this test
    proves the observable behavior that absence implies: the exact same
    host, indistinguishable from a live discovery, is independently
    re-authorized before it could ever reach active collection.
    """

    def test_followup_planner_reauthorizes_regardless_of_how_the_indicator_was_discovered(
        self,
    ) -> None:
        """core/intel/followup.py:plan_followup_collection takes plain
        hostnames with no provenance field at all — a host recorded via a
        cache-restored artifact and one just discovered live are the same
        Python string by the time this function sees it. Prove an
        out-of-scope one is rejected regardless."""
        from core.intel.bounds import DiscoveryBounds
        from core.intel.followup import plan_followup_collection
        from core.intel.model import CollectReason, IndicatorKind, ScopeStatus
        from core.intel.queue import IndicatorQueue

        queue = IndicatorQueue(DiscoveryBounds())
        queue.add(
            kind=IndicatorKind.DOMAIN,
            value="cached-looking.example.org",
            depth=1,
            parent_id=None,
            reason=CollectReason.CERTIFICATE_SAN,
            scope_status=ScopeStatus.IN_SCOPE,  # a claim, exactly like cached data would carry
            evidence_id="e",
            discovered_from="ctlogs",
            collected=False,
            is_seed=False,
        )
        claimed = queue.eligible_followups()
        assert claimed

        # The real scope only ever authorized example.com — nothing about
        # how "cached-looking.example.org" got into the queue (a claimed
        # IN_SCOPE status, indistinguishable from what a cache-restored
        # artifact's ingestion would produce) changes the outcome.
        plan = plan_followup_collection(
            candidates=claimed,
            scope=CollectionScope.from_seeds(["example.com"], patterns=["example.com"]),
            wildcard_roots=set(),
            already_collected={"example.com"},
            dns_budget=10,
            http_budget=10,
        )
        assert plan.dns_targets == []
        assert plan.http_targets == []
        assert any(item.reason == "out_of_scope" for item in plan.rejected())

    def test_authorize_active_indicator_has_no_cache_aware_code_path(self) -> None:
        """Static confirmation backing the grep-based claim in this
        module's docstring: calling the real authorization function twice
        with the exact same arguments (simulating "this looks like a
        repeat/cached decision") produces the identical result both
        times — there is no hidden memoization or cache-trust shortcut
        that could diverge from a fresh evaluation."""
        scope = CollectionScope.from_seeds(["example.com"], patterns=["*.example.com"])
        first = authorize_active_indicator("admin.example.com", scope, "httpx", "seed_dns")
        second = authorize_active_indicator("admin.example.com", scope, "httpx", "seed_dns")
        assert first.allowed == second.allowed
        # And changing the scope object between calls (as a real scope
        # change would) changes the outcome — nothing was cached from the
        # first call.
        narrower_scope = CollectionScope.from_seeds(
            ["example.com"], patterns=["*.example.com", "!admin.example.com"]
        )
        third = authorize_active_indicator("admin.example.com", narrower_scope, "httpx", "seed_dns")
        assert third.allowed is False


def test_every_active_collection_plugin_class_is_covered_by_the_gate(
    project_root: Path,
) -> None:
    """Sanity check on the audit's own scoping claim: `_gate_active_input`
    filters input for every plugin in ACTIVE_COLLECTION_PLUGINS, which is
    derived from `active_collection=True`, not a hand-maintained list that
    could silently drift out of sync with new plugins."""
    from core.collectors import ACTIVE_COLLECTION_PLUGINS

    declared = {cls.name for cls in plugin_classes() if getattr(cls, "active_collection", False)}
    assert declared == ACTIVE_COLLECTION_PLUGINS
    assert declared  # never silently empty
