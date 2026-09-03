"""Host-wildcard SCOPE_FILE exclusions (`!mta*.stripchat.com`) — the real,
confirmed-live gap: `host_fully_excluded` only ever matched an exact domain
or a subdomain of it, so a wildcard *inside* the excluded host pattern
(anywhere, not only a leading `*.`) had no effect at all. Surfaced by
`core/verification/preflight.py::scope_exclusion_canary_check`
(docs/VERIFICATION_AGENT_DESIGN.md), which is also this fix's acceptance
test — see `test_canary_check_finds_nothing_wrong_now` below, which is
literally the acceptance snippet from the fix request, not a paraphrase.

Fixed via a new `hostname_matches_pattern` (core/scope.py) that runs
`fnmatch` against the whole hostname — the same engine `url_path_excluded`
already uses per path segment and the positive `*.domain` patterns already
rely on, not a second comparison mechanism — plus the existing
label-suffix walk for "further subdomain of an excluded name" coverage.
"""

from __future__ import annotations

from core.intel.scope import CollectionScope, allows_active_collection
from core.scope import host_fully_excluded, hostname_matches_pattern, split_scope_patterns
from core.verification.preflight import scope_exclusion_canary_check

# ---------------------------------------------------------------------------
# hostname_matches_pattern — the new primitive, tested directly.
# ---------------------------------------------------------------------------


class TestHostnameMatchesPattern:
    def test_wildcard_at_start_of_subdomain_label(self) -> None:
        assert hostname_matches_pattern("mta1.stripchat.com", "mta*.stripchat.com")
        assert hostname_matches_pattern("mta-eu.stripchat.com", "mta*.stripchat.com")
        assert hostname_matches_pattern("mta.stripchat.com", "mta*.stripchat.com")

    def test_wildcard_at_end_of_subdomain_label(self) -> None:
        assert hostname_matches_pattern("staging-1.example.com", "staging-*.example.com")
        assert hostname_matches_pattern("staging-.example.com", "staging-*.example.com")

    def test_wildcard_before_a_suffix_label(self) -> None:
        assert hostname_matches_pattern("api-beta.example.com", "*-beta.example.com")
        assert hostname_matches_pattern("web-beta.example.com", "*-beta.example.com")

    def test_adversarial_text_sharing_prefix_is_not_a_match(self) -> None:
        """The real risk of a naive substring check: 'notmta1...' merely
        contains 'mta' but is not the host segment the pattern describes.
        fnmatch anchors the whole string, so this must never match."""
        assert not hostname_matches_pattern("notmta1.stripchat.com", "mta*.stripchat.com")

    def test_unrelated_host_on_same_domain_is_not_a_match(self) -> None:
        assert not hostname_matches_pattern("creator.stripchat.com", "mta*.stripchat.com")

    def test_further_subdomain_of_a_wildcard_match_is_also_matched(self) -> None:
        """Same conservative principle as the exact-domain case: excluding
        more is safer than excluding less."""
        assert hostname_matches_pattern("sub.mta1.stripchat.com", "mta*.stripchat.com")

    def test_no_wildcard_pattern_behaves_as_exact_or_subdomain_match(self) -> None:
        """Regression: plain fnmatch with no special characters must
        reproduce the pre-fix exact/subdomain behavior exactly."""
        assert hostname_matches_pattern("community.linktr.ee", "community.linktr.ee")
        assert hostname_matches_pattern("sub.community.linktr.ee", "community.linktr.ee")
        assert not hostname_matches_pattern("otrosub.linktr.ee", "community.linktr.ee")
        assert not hostname_matches_pattern("linktr.ee", "community.linktr.ee")

    def test_empty_host_or_pattern_is_never_a_match(self) -> None:
        assert not hostname_matches_pattern("", "mta*.stripchat.com")
        assert not hostname_matches_pattern("mta1.stripchat.com", "")


# ---------------------------------------------------------------------------
# host_fully_excluded — wildcard domain patterns wired through.
# ---------------------------------------------------------------------------


class TestHostFullyExcludedWithWildcard:
    def test_matches_subdomains_shaped_like_the_wildcard_pattern(self) -> None:
        exclusions = [("mta*.stripchat.com", "/*")]
        assert host_fully_excluded("mta1.stripchat.com", exclusions)
        assert host_fully_excluded("mta-eu.stripchat.com", exclusions)
        assert host_fully_excluded("mta.stripchat.com", exclusions)

    def test_non_matching_subdomain_stays_authorized(self) -> None:
        exclusions = [("mta*.stripchat.com", "/*")]
        assert not host_fully_excluded("creator.stripchat.com", exclusions)
        assert not host_fully_excluded("api.stripchat.com", exclusions)

    def test_adversarial_shared_text_prefix_not_excluded(self) -> None:
        exclusions = [("mta*.stripchat.com", "/*")]
        assert not host_fully_excluded("notmta1.stripchat.com", exclusions)

    def test_still_requires_the_whole_domain_sentinel(self) -> None:
        """A wildcard host pattern paired with a real path (not `/*`) must
        never trigger the whole-domain check — no regression against the
        existing path-specific-exclusion behavior."""
        exclusions = [("mta*.stripchat.com", "/status")]
        assert not host_fully_excluded("mta1.stripchat.com", exclusions)


# ---------------------------------------------------------------------------
# split_scope_patterns — a wildcard exclusion line parses the same way an
# exact one does; the wildcard character is just part of the domain text.
# ---------------------------------------------------------------------------


def test_split_scope_patterns_preserves_the_wildcard_in_the_exclusion_domain() -> None:
    positive, exclusions = split_scope_patterns(["*.stripchat.com", "!mta*.stripchat.com"])
    assert positive == ["*.stripchat.com"]
    assert exclusions == [("mta*.stripchat.com", "/*")]


# ---------------------------------------------------------------------------
# End-to-end through allows_active_collection / CollectionScope, mirroring
# tests/test_scope_path_exclusions.py's real Linktree/BancoPlata coverage.
# ---------------------------------------------------------------------------


def _stripchat_scope(**kwargs: object) -> CollectionScope:
    return CollectionScope.from_seeds(
        ["stripchat.com"],
        patterns=["*.stripchat.com", "!mta*.stripchat.com"],
        **kwargs,
    )


class TestStripchatWildcardExclusionEndToEnd:
    def test_mta_subdomains_are_excluded(self) -> None:
        scope = _stripchat_scope()
        assert not allows_active_collection("mta1.stripchat.com", scope)
        assert not allows_active_collection("mta-eu.stripchat.com", scope)
        assert not allows_active_collection("mta.stripchat.com", scope)
        assert not allows_active_collection("https://mta1.stripchat.com/", scope)

    def test_other_subdomains_remain_authorized(self) -> None:
        scope = _stripchat_scope()
        assert allows_active_collection("creator.stripchat.com", scope)
        assert allows_active_collection("api.stripchat.com", scope)
        assert allows_active_collection("https://creator.stripchat.com/", scope)

    def test_adversarial_lookalike_subdomain_remains_authorized(self) -> None:
        scope = _stripchat_scope()
        assert allows_active_collection("notmta1.stripchat.com", scope)


class TestCombinedWithExactDomainExclusion:
    """A host-wildcard exclusion and an exact-domain exclusion in the same
    SCOPE_FILE must not interfere with each other."""

    def _scope(self) -> CollectionScope:
        return CollectionScope.from_seeds(
            ["stripchat.com"],
            patterns=["*.stripchat.com", "!mta*.stripchat.com", "!wiki.stripchat.com"],
        )

    def test_both_exclusions_take_effect_independently(self) -> None:
        scope = self._scope()
        assert not allows_active_collection("mta1.stripchat.com", scope)
        assert not allows_active_collection("wiki.stripchat.com", scope)
        assert not allows_active_collection("sub.wiki.stripchat.com", scope)

    def test_unrelated_subdomain_still_authorized(self) -> None:
        scope = self._scope()
        assert allows_active_collection("creator.stripchat.com", scope)


class TestCombinedWithPathExclusion:
    """A host-wildcard whole-domain exclusion and an existing path-glob
    exclusion (`!bancoplata.mx/*/whistleblowing`) coexisting must not
    regress either feature — same overall SCOPE_FILE, different domains,
    both kinds of exclusion active at once."""

    def _scope(self) -> CollectionScope:
        return CollectionScope.from_seeds(
            ["stripchat.com", "bancoplata.mx"],
            patterns=[
                "*.stripchat.com",
                "!mta*.stripchat.com",
                "*.bancoplata.mx",
                "!bancoplata.mx/*/whistleblowing",
            ],
        )

    def test_host_wildcard_exclusion_still_works(self) -> None:
        scope = self._scope()
        assert not allows_active_collection("mta1.stripchat.com", scope)
        assert allows_active_collection("creator.stripchat.com", scope)

    def test_path_exclusion_still_works_unaffected(self) -> None:
        scope = self._scope()
        assert not allows_active_collection("https://bancoplata.mx/es/whistleblowing", scope)
        assert not allows_active_collection(
            "https://bancoplata.mx/es/whistleblowing/reportar", scope
        )
        assert allows_active_collection("https://bancoplata.mx/es/otra-cosa", scope)
        # The bare domain itself must stay resolvable — path exclusions
        # never make host_fully_excluded fire (regression already covered
        # in tests/test_scope_path_exclusions.py, re-asserted here in
        # combination with the new wildcard-host exclusion).
        assert allows_active_collection("bancoplata.mx", scope)


# ---------------------------------------------------------------------------
# scope_exclusion_canary_check — the acceptance test from the fix request,
# verbatim, plus its "no new false positives" counterpart.
# ---------------------------------------------------------------------------


class TestScopeExclusionCanaryCheckNoLongerFlagsTheFix:
    def test_canary_check_finds_nothing_wrong_now(self) -> None:
        """Literally the acceptance snippet from the fix request: the real
        Stripchat wildcard-exclusion bug, run through the same verification
        agent that originally caught it, now finds nothing wrong."""
        scope = CollectionScope.from_seeds(
            ["stripchat.com"], patterns=["*.stripchat.com", "!mta*.stripchat.com"]
        )
        findings = scope_exclusion_canary_check(scope)
        assert findings == [], f"la exclusión con wildcard en host sigue sin funcionar: {findings}"

    def test_canary_check_still_finds_nothing_for_an_already_working_exact_exclusion(
        self,
    ) -> None:
        """No new false positives introduced by this change: a scope with
        only an already-correct exact-domain exclusion must still come back
        clean."""
        scope = CollectionScope.from_seeds(
            ["stripchat.com"], patterns=["*.stripchat.com", "!wiki.stripchat.com"]
        )
        findings = scope_exclusion_canary_check(scope)
        assert findings == []
