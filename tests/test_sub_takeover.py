"""`modules/sub_takeover.py` — two-stage subdomain takeover detection.

The fixture data below reconstructs the REAL, documented unclaimed-state
response shapes for S3 (AWS's own documented XML error format),
GitHub Pages, Heroku, and Bitbucket — the exact fingerprint TEXT for each
comes straight from `modules/data/takeover_fingerprints.json`, itself a
filtered snapshot fetched live from the real, current
`can-i-take-over-xyz` project on 2026-09-23 (see that file's own `_meta`
block and `modules/sub_takeover.py`'s module docstring). This module's
own hard rule — never actually claim a dangling resource — means a truly
live capture of an unclaimed page under a real, currently-dangling name
is not something this test suite can ethically produce; wrapping each
service's own real, known fingerprint text in a realistic minimal page
shell is the honest alternative, and is called out here rather than
silently presented as a live capture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.collection.gateway import CollectionGateway
from core.collection.target import AuthorizedCollectionTarget
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.response_diff import ResponseSnapshot
from modules.sub_takeover import (
    SubTakeoverPlugin,
    _apply_wildcard_policy,
    find_candidates,
    load_signatures,
    match_signature,
)

_SIGNATURES = load_signatures()


async def _async_resolve(host: str) -> list[str]:
    return ["203.0.113.10"]


@pytest.fixture(autouse=True)
def _fake_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic `*.example.com` test hostnames never really resolve —
    stub the SSRF layer's resolver to a fixed public-looking address, the
    same pattern `tests/test_collection_gateway.py` uses, so these tests
    exercise authorization/confirmation logic, not real DNS."""
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["203.0.113.10"])
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _async_resolve)


def _dnsx_record(host: str, cname: str | None, *, has_address: bool = True) -> dict[str, object]:
    rec: dict[str, object] = {"host": host}
    if cname:
        rec["cname"] = [cname]
    if has_address:
        rec["a"] = ["93.184.216.34"]
    return rec


class TestLoadSignatures:
    def test_loads_the_vendored_snapshot(self) -> None:
        assert len(_SIGNATURES) >= 25
        services = {s.service for s in _SIGNATURES}
        assert "AWS/S3" in services
        assert "Microsoft Azure" in services

    def test_github_and_heroku_are_present_as_hydra_supplementary(self) -> None:
        """The real, current can-i-take-over-xyz fingerprints.json (fetched
        2026-09-23) lists Github/Heroku with an EMPTY cname array and
        status 'Edge case' — this module adds the well-known github.io/
        herokuapp.com patterns back in, but tagged with a distinct source
        and a lower severity/confidence than a can-i-take-over-xyz
        'Vulnerable' entry gets (see _SEVERITY_BY_STATUS)."""
        by_service = {s.service: s for s in _SIGNATURES}
        assert by_service["GitHub Pages"].source == "hydra-supplementary"
        assert by_service["GitHub Pages"].status == "Edge case"
        assert by_service["Heroku"].source == "hydra-supplementary"
        assert by_service["Heroku"].status == "Edge case"

    def test_no_signature_has_a_bare_ip_literal_cname_pattern(self) -> None:
        """SmartJobBoard's only real cname pattern was a bare IP literal
        and was dropped entirely; Worksites kept its hostname pattern but
        lost its IP-literal one. A bare IP can never be a CNAME value, so
        keeping one in cname_patterns could never match anything and would
        just be dead weight."""
        import re

        ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        for sig in _SIGNATURES:
            for pattern in sig.cname_patterns:
                assert not ip_re.match(pattern), f"{sig.service} kept a bare IP pattern"
        assert "SmartJobBoard" not in {s.service for s in _SIGNATURES}


class TestMatchSignature:
    def test_exact_and_subdomain_suffix_match(self) -> None:
        sig = match_signature("mybucket.s3.amazonaws.com", _SIGNATURES)
        assert sig is not None
        assert sig.service == "AWS/S3"

    def test_unrelated_cname_does_not_match(self) -> None:
        assert match_signature("app.internal-cdn.example.com", _SIGNATURES) is None

    def test_lookalike_domain_does_not_falsely_match_by_substring(self) -> None:
        """'s3.amazonaws.com.evil.example' contains the pattern as a
        substring but is not a subdomain OF it — must not match."""
        assert match_signature("foo.s3.amazonaws.com.evil.example", _SIGNATURES) is None


class TestFingerprintRegexCompilation:
    """can-i-take-over-xyz's own fingerprint field is used as a regex by
    that project's other downstream tooling — confirmed directly from the
    real fetched data: ngrok's fingerprint contains a literal `.*`
    wildcard, and Ghost's contains the HTML-escaped pipe `&#124;` for
    regex alternation."""

    def test_ngrok_wildcard_matches_any_subdomain_name(self) -> None:
        sig = next(s for s in _SIGNATURES if s.service == "Ngrok")
        assert sig.fingerprint_regex is not None
        assert sig.fingerprint_regex.search("Tunnel abc123.ngrok.io not found")
        assert sig.fingerprint_regex.search("Tunnel xyz-999.ngrok.io not found")

    def test_ghost_html_escaped_pipe_becomes_real_alternation(self) -> None:
        sig = next(s for s in _SIGNATURES if s.service == "Ghost")
        assert sig.fingerprint is not None
        assert "&#124;" in sig.fingerprint
        assert sig.fingerprint_regex is not None
        assert sig.fingerprint_regex.search("Site unavailable.")
        assert sig.fingerprint_regex.search("Failed to resolve DNS path for this host")

    def test_nxdomain_sentinel_has_no_regex(self) -> None:
        sig = next(s for s in _SIGNATURES if s.service == "AWS/Elastic Beanstalk")
        assert sig.fingerprint_regex is None


class TestFindCandidatesStage1:
    def test_matching_cname_produces_a_candidate(self) -> None:
        records = [_dnsx_record("assets.example.com", "assets.example.com.s3.amazonaws.com")]
        candidates = find_candidates(records, _SIGNATURES)
        assert len(candidates) == 1
        assert candidates[0].host == "assets.example.com"
        assert candidates[0].signature.service == "AWS/S3"

    def test_non_matching_cname_produces_no_candidate(self) -> None:
        records = [_dnsx_record("app.example.com", "app.internal-lb.example.com")]
        assert find_candidates(records, _SIGNATURES) == []

    def test_host_with_no_cname_at_all_is_ignored(self) -> None:
        records = [_dnsx_record("plain.example.com", None)]
        assert find_candidates(records, _SIGNATURES) == []

    def test_has_address_is_carried_through_for_nxdomain_gating(self) -> None:
        records = [
            _dnsx_record("dead.example.com", "myapp.elasticbeanstalk.com", has_address=False)
        ]
        candidates = find_candidates(records, _SIGNATURES)
        assert len(candidates) == 1
        assert candidates[0].has_address is False


class TestWildcardPolicy:
    def _finding(self, host: str, service: str = "AWS/S3", confidence: int = 95) -> dict:
        return {
            "host": host,
            "service": service,
            "description": "base description.",
            "confidence_score": confidence,
            "wildcard_dns_active": False,
        }

    def test_non_wildcard_root_passes_through_unchanged(self) -> None:
        findings = [self._finding("a.example.com")]
        result = _apply_wildcard_policy(findings, wildcard_roots=set())
        assert result == findings

    def test_single_subdomain_under_wildcard_root_is_downgraded_not_dropped(self) -> None:
        findings = [self._finding("only-one.example.com")]
        result = _apply_wildcard_policy(findings, wildcard_roots={"example.com"})
        assert len(result) == 1
        assert result[0]["wildcard_dns_active"] is True
        assert result[0]["confidence_score"] <= 60
        assert "wildcard" in result[0]["description"].lower()

    def test_two_distinct_confirmed_subdomains_collapse_into_one_root_finding(self) -> None:
        findings = [
            self._finding("one.example.com"),
            self._finding("two.example.com"),
        ]
        result = _apply_wildcard_policy(findings, wildcard_roots={"example.com"})
        assert len(result) == 1
        assert result[0]["host"] == "example.com"
        assert result[0]["wildcard_dns_active"] is True
        assert result[0]["confidence_score"] == 95  # not downgraded — corroborated
        assert set(result[0]["wildcard_confirmed_subdomains"]) == {
            "one.example.com",
            "two.example.com",
        }

    def test_different_services_under_the_same_root_are_not_merged_together(self) -> None:
        findings = [
            self._finding("one.example.com", service="AWS/S3"),
            self._finding("two.example.com", service="Heroku"),
        ]
        result = _apply_wildcard_policy(findings, wildcard_roots={"example.com"})
        # Each service only has a single corroborating subdomain of its own —
        # both downgraded, neither merged with the other's unrelated service.
        assert len(result) == 2
        assert {r["host"] for r in result} == {"one.example.com", "two.example.com"}


class _FakeGateway:
    """Records every host `http_get` is asked to fetch, and returns a
    canned response per host — stands in for a real network call so
    Stage-2 confirmation logic can be exercised without touching the
    network at all."""

    def __init__(self, responses: dict[str, ResponseSnapshot], scope: CollectionScope) -> None:
        self.responses = responses
        self.scope = scope
        self.requested_hosts: list[str] = []

    def authorize(self, raw: str, *, operation: str = "") -> AuthorizedCollectionTarget | None:
        return AuthorizedCollectionTarget.authorize(
            raw, self.scope, capability="sub_takeover", operation=operation
        )

    async def http_get(
        self, target: AuthorizedCollectionTarget, *, timeout: int, operation: str = ""
    ):
        self.requested_hosts.append(target.hostname)
        return self.responses.get(
            target.hostname, ResponseSnapshot(status_code=200, body=b"", error=None)
        )


class TestStage2HttpConfirmation:
    """`SubTakeoverPlugin._confirm` directly — the response bodies below
    wrap each service's own real fingerprint text (see module docstring
    for why these are reconstructions, not live captures)."""

    def _s3_signature(self):
        return next(s for s in _SIGNATURES if s.service == "AWS/S3")

    def _github_signature(self):
        return next(s for s in _SIGNATURES if s.service == "GitHub Pages")

    @pytest.mark.asyncio
    async def test_s3_nosuchbucket_xml_confirms_a_finding(self, tmp_path: Path) -> None:
        from modules.sub_takeover import SubTakeoverPlugin, _Candidate

        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        plugin = SubTakeoverPlugin(settings)
        candidate = _Candidate(
            host="assets.example.com",
            cname="assets.example.com.s3.amazonaws.com",
            signature=self._s3_signature(),
            has_address=True,
        )
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b"<Error><Code>NoSuchBucket</Code>"
            b"<Message>The specified bucket does not exist</Message>"
            b"<BucketName>assets-example-com</BucketName></Error>"
        )
        scope = CollectionScope.from_seeds(["example.com"])
        gateway = _FakeGateway(
            {"assets.example.com": ResponseSnapshot(status_code=404, body=body, error=None)},
            scope,
        )
        result = await plugin._confirm(
            gateway, candidate, {"assets.example.com": "https://assets.example.com"}, timeout=5
        )
        assert result is not None
        assert result["service"] == "AWS/S3"
        assert result["stage2_method"] == "http_fingerprint"
        assert result["severity"] == "high"
        assert result["confidence_score"] == 95

    @pytest.mark.asyncio
    async def test_a_normal_provisioned_response_produces_no_finding(self, tmp_path: Path) -> None:
        """The core false-positive guard: a CNAME matching a vulnerable
        pattern whose live response is an ordinary, provisioned page must
        never be reported."""
        from modules.sub_takeover import SubTakeoverPlugin, _Candidate

        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        plugin = SubTakeoverPlugin(settings)
        candidate = _Candidate(
            host="assets.example.com",
            cname="assets.example.com.s3.amazonaws.com",
            signature=self._s3_signature(),
            has_address=True,
        )
        scope = CollectionScope.from_seeds(["example.com"])
        gateway = _FakeGateway(
            {
                "assets.example.com": ResponseSnapshot(
                    status_code=200, body=b"<html>Welcome to our real site</html>", error=None
                )
            },
            scope,
        )
        result = await plugin._confirm(
            gateway, candidate, {"assets.example.com": "https://assets.example.com"}, timeout=5
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_github_pages_edge_case_signature_confirms_at_lower_confidence(
        self, tmp_path: Path
    ) -> None:
        from modules.sub_takeover import SubTakeoverPlugin, _Candidate

        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        plugin = SubTakeoverPlugin(settings)
        candidate = _Candidate(
            host="blog.example.com",
            cname="someuser.github.io",
            signature=self._github_signature(),
            has_address=True,
        )
        body = b"<html><body><h1>404</h1>There isn't a GitHub Pages site here.</body></html>"
        scope = CollectionScope.from_seeds(["example.com"])
        gateway = _FakeGateway(
            {"blog.example.com": ResponseSnapshot(status_code=404, body=body, error=None)}, scope
        )
        result = await plugin._confirm(
            gateway, candidate, {"blog.example.com": "https://blog.example.com"}, timeout=5
        )
        assert result is not None
        assert result["severity"] == "medium"
        assert result["confidence_score"] == 65
        assert "edge case" in result["description"].lower()

    @pytest.mark.asyncio
    async def test_candidate_not_in_alive_set_is_stage1_only_never_a_finding(
        self, tmp_path: Path
    ) -> None:
        from modules.sub_takeover import SubTakeoverPlugin, _Candidate

        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        plugin = SubTakeoverPlugin(settings)
        candidate = _Candidate(
            host="dead-httpx.example.com",
            cname="dead-httpx.example.com.s3.amazonaws.com",
            signature=self._s3_signature(),
            has_address=True,
        )
        scope = CollectionScope.from_seeds(["example.com"])
        gateway = _FakeGateway({}, scope)
        result = await plugin._confirm(gateway, candidate, {}, timeout=5)
        assert result is None
        assert gateway.requested_hosts == []


class TestStage2NxdomainConfirmation:
    """Azure/Elastic-Beanstalk/Discourse-style signatures: confirmation
    comes from dnsx's own has_address observation, never a live probe —
    see module docstring for why an HTTP attempt through the confinement
    proxy would be indistinguishable from an ordinary scope denial here."""

    def _azure_signature(self):
        return next(s for s in _SIGNATURES if s.service == "Microsoft Azure")

    @pytest.mark.asyncio
    async def test_no_address_record_confirms_without_any_network_call(
        self, tmp_path: Path
    ) -> None:
        from modules.sub_takeover import SubTakeoverPlugin, _Candidate

        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        plugin = SubTakeoverPlugin(settings)
        candidate = _Candidate(
            host="old.example.com",
            cname="old-app.azurewebsites.net",
            signature=self._azure_signature(),
            has_address=False,
        )
        scope = CollectionScope.from_seeds(["example.com"])
        gateway = _FakeGateway({}, scope)
        result = await plugin._confirm(gateway, candidate, {}, timeout=5)
        assert result is not None
        assert result["stage2_method"] == "dns_nxdomain_confirmed"
        assert result["url"] is None
        assert gateway.requested_hosts == []  # no network call was made

    @pytest.mark.asyncio
    async def test_an_address_record_contradicts_nxdomain_expectation_no_finding(
        self, tmp_path: Path
    ) -> None:
        """If the host actually DOES resolve, the NXDOMAIN signature's own
        precondition is false — must not be reported."""
        from modules.sub_takeover import SubTakeoverPlugin, _Candidate

        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        plugin = SubTakeoverPlugin(settings)
        candidate = _Candidate(
            host="reclaimed.example.com",
            cname="reclaimed-app.azurewebsites.net",
            signature=self._azure_signature(),
            has_address=True,
        )
        scope = CollectionScope.from_seeds(["example.com"])
        gateway = _FakeGateway({}, scope)
        result = await plugin._confirm(gateway, candidate, {}, timeout=5)
        assert result is None


class TestScopeEnforcement:
    """Proves Stage 2's active probe never reaches an out-of-scope host —
    the same class of test every other active plugin already has."""

    def _context(self, tmp_path: Path) -> PipelineContext:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        records = [
            json.dumps(
                {
                    "host": "assets.example.com",
                    "a": ["93.184.216.34"],
                    "cname": ["assets.example.com.s3.amazonaws.com"],
                }
            ),
            json.dumps(
                {
                    "host": "assets.evil-out-of-scope.example",
                    "a": ["203.0.113.9"],
                    "cname": ["assets.evil-out-of-scope.example.s3.amazonaws.com"],
                }
            ),
        ]
        (output_dir / "dnsx_records.jsonl").write_text("\n".join(records) + "\n", encoding="utf-8")
        (output_dir / "alive.txt").write_text(
            "https://assets.example.com\nhttps://assets.evil-out-of-scope.example\n",
            encoding="utf-8",
        )
        return PipelineContext(
            targets=[DomainTarget(domain="example.com")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["example.com"]),
        )

    @pytest.mark.asyncio
    async def test_an_out_of_scope_host_never_receives_a_real_http_request(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(project_root=tmp_path, enable_sub_takeover=True)
        context = self._context(tmp_path)
        plugin = SubTakeoverPlugin(settings)

        requested_hosts: list[str] = []
        real_http_get = CollectionGateway.http_get

        async def spying_http_get(self_, target, *, timeout, operation=""):  # noqa: ANN001
            requested_hosts.append(target.hostname)
            return ResponseSnapshot(
                status_code=404,
                body=b"The specified bucket does not exist",
                error=None,
            )

        monkeypatch.setattr(CollectionGateway, "http_get", spying_http_get)
        try:
            await plugin.run(context, tmp_path / "unused")
        finally:
            monkeypatch.setattr(CollectionGateway, "http_get", real_http_get)

        assert "assets.example.com" in requested_hosts
        assert "assets.evil-out-of-scope.example" not in requested_hosts

        from utils.files import read_jsonl

        findings = read_jsonl(context.output_dir / "sub_takeover.jsonl")
        assert all(f["host"] != "assets.evil-out-of-scope.example" for f in findings)
