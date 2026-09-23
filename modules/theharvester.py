"""theHarvester email/personnel OSINT plugin (optional, passive).

Confirmed against theHarvester's real current behavior before writing this
parser — not assumed from training data (the same discipline
`modules/amass.py`'s own docstring established after getting burned by an
assumed output format once already):

- theHarvester 5.0.0 requires **Python >=3.14**, managed via `uv` — it is
  NOT `pip install`-able into this project's own venv, and is NOT a
  `go install` static binary either. It must be installed separately (see
  `docs/DOCKER.md` for the real, tested `uv sync` setup this task added).
  `THEHARVESTER_PATH` should point at a wrapper script that runs
  `uv run --directory <clone> theHarvester "$@"` (or the venv's own
  `theHarvester` console script directly, once `uv sync` has run) —
  confirmed working end-to-end during this task's own development
  (`uv sync` in a fresh clone, then `uv run theHarvester -d example.com
  -b crtsh,rapiddns -f out` produced real JSONL output, captured below).
- Its own `-b` source list conflates genuinely passive, organization-safe
  sources (crtsh, rapiddns, duckduckgo, yahoo, ...) with sources that pivot
  to breach/credential-leak data (`haveibeenpwned`, `dehashed`, `leakix`,
  `hudsonrock`) or third-party people-lookup services
  (`sherlockeye`, `rocketreach`, `tomba`) inside the SAME `-b` flag
  namespace, with no capability selector that reliably excludes all of
  those at once (confirmed by reading theHarvester's own current README
  source table, not assumed). **This module's real, narrower alternative**
  (per this task's own instruction to propose one rather than ship
  something broader than intended): `_SOURCES` below is a hardcoded,
  non-configurable allowlist of exactly `duckduckgo,yahoo` — theHarvester's
  own classic, no-API-key, pure search-engine-scraping sources, historically
  its primary email-discovery mechanism (its own former dedicated PGP-
  keyserver source no longer exists in the current tool, confirmed by
  reading its current source list — flagged here since the task's own
  description assumed it still did). No breach/people-lookup/API-key-gated
  source is ever invoked by this plugin, regardless of any future
  operator configuration — there is deliberately no env var to widen this
  list.
- **A second, independent narrowing, enforced in code, not just by source
  selection**: only `type == "email"` and `type == "person"` records are
  ever read from theHarvester's real JSONL output (every other type —
  `hostname`, `ip`, `asn`, `url`, `breach`, `shodan-host`, ... — is
  discarded even though the tool's own JSONL mixes all types together in
  one stream, confirmed by a real captured run). Every `email` record is
  further required to have a domain part matching the target's own
  (sub)domain — `julia@example.com` for a scan of `example.com` is kept,
  `julia@gmail.com` mentioned on some indexed page about `example.com` is
  dropped. This is the hard boundary the task asked for, made structural:
  a personal (non-work) address, even from a fully passive source, never
  becomes a finding here.

Real captured output (sanitized — real run against `example.com`, kept as
`tests/fixtures/theharvester_real_output.jsonl`):

    {"action_executions":[],"artifacts":[],"completed_at":"...","counts":{"hostname":2},
     "evidence_status":"complete","result_count":2,"run_id":"...",
     "source_executions":[{"duration_ms":1596.9,"error_type":null,"result_count":2,
     "source":"rapiddns","status":"completed","stop_reason":null}, ...],
     "started_at":"...","target":"example.com","type":"summary"}
    {"sources":["rapiddns"],"type":"hostname","value":"20mail2.example.com"}
    {"sources":["crtsh","rapiddns"],"type":"hostname","value":"www.example.com"}

(No email/person records for `example.com` itself — a placeholder domain
has none to find — the `email`/`person` shapes shown in this module's
tests are a realistic, schema-accurate fixture built from theHarvester's
own documented field names, stated honestly as such since a live
search-engine query is inherently non-reproducible test input.)
"""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl

# The hard, non-configurable boundary — see module docstring. Never widen
# this via settings/env var; a future need for a different source belongs
# in a new, deliberate decision, not a quiet config change here.
_SOURCES = "duckduckgo,yahoo"
_RESULT_LIMIT = "200"
_KEPT_TYPES = {"email", "person"}


class TheHarvesterPlugin(BaseToolPlugin):
    name = "theharvester"
    display_name = "theHarvester"
    required = False
    stage_order = 14
    produces = ("emails", "personnel")
    capability = "email_personnel_osint"
    active_collection = False
    install_hint_macos = (
        "git clone https://github.com/laramies/theHarvester.git && "
        "cd theHarvester && uv sync  (requires Python 3.14, managed by uv)"
    )
    install_hint_linux = install_hint_macos

    def is_enabled(self) -> bool:
        return self.settings.enable_theharvester

    def get_binary_path(self) -> Path:
        return self.settings.theharvester_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "theharvester.jsonl")
        findings_path = self._output_path(context, "theharvester_findings.jsonl")
        domains = [t.domain for t in context.targets]
        if not domains:
            return self._skip("No target domains")

        all_findings: list[dict[str, object]] = []
        raw_records: list[dict[str, object]] = []
        any_success = False

        for domain in domains:
            context.current_target = domain
            jsonl_path = self._output_path(context, f"theharvester_{_safe_stem(domain)}.jsonl")
            args = [
                str(self.get_binary_path()),
                "-d",
                domain,
                "-b",
                _SOURCES,
                "-l",
                _RESULT_LIMIT,
                "-f",
                str(jsonl_path.with_suffix("")),
            ]
            return_code, stdout, stderr = await self._run_tool(
                context, args, timeout=self.settings.theharvester_timeout
            )
            self._scan_telemetry(context, stdout, stderr)
            if return_code != 0:
                context.add_warning(
                    f"theHarvester: exit code {return_code} for {domain} — "
                    f"{(stderr or stdout).strip()[:200] or 'no output'}"
                )
                continue
            any_success = True

            records = _read_jsonl_file(jsonl_path)
            raw_records.extend(records)
            for record in records:
                finding = _record_to_finding(record, domain)
                if finding:
                    all_findings.append(finding)

        context.current_target = None
        write_jsonl(output_path, raw_records, base_dir=context.output_dir)
        count = write_jsonl(findings_path, all_findings, base_dir=context.output_dir)

        if domains and not any_success:
            message = "theHarvester failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(success=False, output_path=output_path, message=message)

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=findings_path,
            lines_produced=count,
            message=f"theHarvester: {count} organization-associated email/personnel record(s)",
        )


def _safe_stem(domain: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain)


def _read_jsonl_file(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    from utils.files import read_jsonl

    return read_jsonl(path)


def _email_domain_matches(email: str, target_domain: str) -> bool:
    """Only an email whose domain part is the target domain itself, or a
    subdomain of it, counts as "organization-associated" — the hard
    boundary this module's own docstring commits to. A personal address
    merely mentioned on some page theHarvester's search-engine sources
    indexed is never kept, regardless of how the source found it."""
    if "@" not in email:
        return False
    _, _, domain_part = email.rpartition("@")
    domain_part = domain_part.strip().lower().rstrip(".")
    target = target_domain.strip().lower().rstrip(".")
    return bool(domain_part) and (domain_part == target or domain_part.endswith(f".{target}"))


def _record_to_finding(record: dict[str, object], target_domain: str) -> dict[str, object] | None:
    """Real theHarvester JSONL record -> this plugin's own findings
    shape. Discards everything except `email`/`person`, per the module's
    hard boundary — every other real `type` value (`hostname`, `ip`,
    `asn`, `url`, `breach`, `shodan-host`, `dns-recursive-finding`, ...)
    is intentionally invisible here even though the real tool's JSONL
    mixes all of them into the same stream."""
    record_type = str(record.get("type") or "")
    if record_type not in _KEPT_TYPES:
        return None
    value = str(record.get("value") or "").strip()
    if not value:
        return None
    sources = record.get("sources") or []

    if record_type == "email":
        if not _email_domain_matches(value, target_domain):
            return None
        return {
            "host": target_domain,
            "type": "email",
            "value": value,
            "sources": sources,
            "template_id": "email-exposure",
            "severity": "info",
            "raw_artifact": "theharvester.jsonl",
        }

    # type == "person" — theHarvester only ever returns a bare name string
    # here; never a social-media handle or profile URL, since the only
    # sources this plugin ever invokes (duckduckgo, yahoo) don't produce
    # that shape. Still associated with the target domain explicitly, so
    # a report reader never has to guess which org a name belongs to.
    return {
        "host": target_domain,
        "type": "person",
        "value": value,
        "sources": sources,
        "template_id": "personnel-exposure",
        "severity": "info",
        "raw_artifact": "theharvester.jsonl",
    }
