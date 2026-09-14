"""amass subdomain enumeration plugin (optional)."""

from __future__ import annotations

import re
from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines

# amass v4's `-o`/`-oA` output is a transcript of discovered relationships,
# one per line: "<endpoint> (<Type>) --> <relation> --> <endpoint> (<Type>)"
# — e.g. "api.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)" — not
# a plain subdomain list. Verified against a real installed amass v4.2.0
# (the version this module is pinned to install_hint-wise) run against a
# real domain: neither `-o` nor `-oA` has a "names only" mode in this
# version. Reading every line as a bare hostname (the old assumption) would
# feed garbage like the full relationship line itself into the asset
# registry as a "domain." See docs/HARDENING_ROUND2_P1.md /
# docs/PRODUCTION_READINESS.md for why v5 (whose `enum` no longer supports
# a simple one-shot invocation at all — see below) isn't used instead.
_AMASS_RELATIONSHIP_LINE = re.compile(
    r"^(?P<left>.+?)\s+\((?P<left_type>[A-Za-z]+)\)\s+-->\s+\S+\s+-->\s+"
    r"(?P<right>.+?)\s+\((?P<right_type>[A-Za-z]+)\)\s*$"
)


def _extract_amass_fqdns(lines: list[str], domain: str) -> list[str]:
    """Pull real subdomains of `domain` out of one amass `-o` run.

    Only `(FQDN)`-typed endpoints are considered — `(Netblock)`,
    `(IPAddress)`, `(ASN)`, and `(RIROrganization)` endpoints (all real,
    common lines in amass's output) are correctly excluded, as are FQDNs
    that belong to unrelated third-party infrastructure the target merely
    points at (a mail provider's MX record, a CDN's CNAME target) — an
    endpoint only counts if it equals `domain` or ends with `.<domain>`.

    A line that doesn't match the relationship-transcript shape is treated
    as an already-bare hostname (still subject to the same domain-suffix
    filter) rather than silently dropped — defensive tolerance for a
    differently-formatted `amass.txt` (e.g. one written by this same
    function on a prior run), not an assumption that this is amass's own
    native output shape.
    """
    root = domain.strip().lower().rstrip(".")
    suffix = f".{root}"
    found: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        match = _AMASS_RELATIONSHIP_LINE.match(line)
        candidates = (
            [(match["left"], match["left_type"]), (match["right"], match["right_type"])]
            if match
            else [(line, "FQDN")]
        )
        for value, value_type in candidates:
            if value_type != "FQDN":
                continue
            candidate = value.strip().lower().rstrip(".")
            if candidate == root or candidate.endswith(suffix):
                found.add(candidate)
    return sorted(found)


class AmassPlugin(BaseToolPlugin):
    """amass passive/active subdomain enumeration.

    Pinned to v4 — see docs/HARDENING_ROUND2_P1.md (Task 1) and
    docs/PRODUCTION_READINESS.md for why: v5 replaced the single-process
    `enum -o <file>` model this plugin (and every other Hydra tool
    integration) depends on with a client/server architecture (`amass
    engine` + `amass enum` as a client + a separate `amass subs` query
    step against a graph database) — confirmed by direct testing, not
    assumed from a version number alone, including a real run that
    returned zero results even with a 2-minute timeout and no `-passive`
    flag. That is a different, larger integration than a parser fix, and
    not what this module implements.

    https://github.com/owasp-amass/amass
    """

    name = "amass"
    display_name = "amass"
    required = False
    stage_order = 16  # runs after subfinder (10) and before assetfinder-only dedup (17)
    produces = ("domains",)
    capability = "enumerate_domains"
    # Homebrew has no versioned "amass@4" formula — its one `amass` formula
    # tracks upstream latest (v5.x, confirmed via `brew search amass`), so
    # `go install` pinned to an exact tag is the only reliable way to get
    # v4 on any platform.
    install_hint_macos = "go install -v github.com/owasp-amass/amass/v4/...@v4.2.0"
    install_hint_linux = "go install -v github.com/owasp-amass/amass/v4/...@v4.2.0"

    def is_enabled(self) -> bool:
        return self.settings.enable_amass

    def get_binary_path(self) -> Path:
        return self.settings.amass_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "amass.txt")
        merged_path = self._output_path(context, "subdomains.txt")

        existing: list[str] = read_lines(merged_path) if merged_path.exists() else []
        all_subs: list[str] = list(existing)
        discovered: list[str] = []
        domains = [t.domain for t in context.targets]
        results: list[PluginResult] = []

        for domain in domains:
            context.current_target = domain
            args = [
                str(self.resolved_binary(context)),
                "enum",
                "-passive",
                "-d",
                domain,
                "-o",
                str(output_path),
                "-timeout",
                "5",  # minutes
            ]
            # amass writes its own output (-o), so use _execute_self_output
            result = await self._execute_self_output(context, args, output_path, allow_empty=True)
            results.append(result)
            if output_path.exists():
                found = _extract_amass_fqdns(read_lines(output_path), domain)
                discovered.extend(found)
                all_subs.extend(found)

        raw_count = write_lines(output_path, discovered)

        # Merge into the shared subdomains.txt (dedup happens in runner stage 3)
        count = write_lines(merged_path, all_subs)
        context.subdomains = read_lines(merged_path)

        any_success = any(result.success for result in results)
        if domains and not any_success:
            message = "amass failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(
                success=False,
                output_path=merged_path,
                lines_produced=raw_count or count,
                message=message,
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=raw_count or count)
        return PluginResult(
            success=True,
            output_path=merged_path,
            lines_produced=raw_count or count,
            message=f"amass found {len(discovered)} raw subdomain observations",
        )
