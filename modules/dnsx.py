"""dnsx DNS resolution and full-record intelligence plugin."""

from __future__ import annotations

import json
from pathlib import Path

from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class DnsxPlugin(BaseToolPlugin):
    name = "dnsx"
    display_name = "dnsx"
    required = True
    stage_order = 30
    produces = ("domains", "ips")
    capability = "resolve_dns"
    active_collection = True
    install_hint_macos = "brew install dnsx"
    install_hint_linux = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

    def is_enabled(self) -> bool:
        return True

    def get_binary_path(self) -> Path:
        return self.settings.dnsx_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        """Resolve all record types and emit resolved.txt + dnsx_records.jsonl.

        Follow-up collection sets ``dnsx_output_suffix`` so seed artifacts are
        not overwritten. The runner merges follow-up files into the canonical
        collection state atomically.
        """
        input_path = self._authorized_input(context, input_path)
        suffix = str(context.metadata.get("dnsx_output_suffix") or "")
        output_path = self._output_path(context, f"resolved{suffix}.txt")
        records_path = self._output_path(context, f"dnsx_records{suffix}.jsonl")

        args = [
            str(self.get_binary_path()),
            "-l",
            str(input_path),
            # Record types for full intelligence
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-txt",
            "-ns",
            "-soa",
            "-caa",
            "-srv",
            "-ptr",
            "-resp",
            "-json",
            "-o",
            str(records_path),
            "-silent",
            "-t",
            str(self.settings.threads),
            "-retry",
            "2",
        ]

        if self.settings.resolvers_file and self.settings.resolvers_file.exists():
            from utils.security import validate_readable_file

            resolvers = validate_readable_file(self.settings.resolvers_file)
            args.extend(["-r", str(resolvers)])

        # dnsx writes JSON to -o; don't capture stdout
        result = await self._execute_self_output(context, args, records_path, allow_empty=True)

        # Build resolved.txt (simple hostname list) from JSON output
        resolved_hosts: list[str] = []
        if records_path.exists():
            for line in records_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    host = rec.get("host", "").strip().rstrip(".")
                    if host:
                        resolved_hosts.append(host)
                except (json.JSONDecodeError, KeyError):
                    # Fallback: treat non-JSON line as plain hostname
                    domain = line.split()[0].rstrip(".")
                    if domain:
                        resolved_hosts.append(domain)

        if not resolved_hosts and result.success:
            # dnsx ran successfully but wrote a non-JSON/legacy format we didn't
            # recognize — fall back to treating input as resolved. Only do this
            # when the tool actually succeeded; if it crashed, timed out, or the
            # binary was missing, resolved_hosts must stay empty so the failure
            # is visible instead of being silently treated as "everything resolved".
            resolved_hosts = read_lines(input_path)

        from core.intel.scope import filter_authorized_indicators

        scope = getattr(context, "collection_scope", None)
        if scope is not None:
            resolved_hosts = filter_authorized_indicators(resolved_hosts, scope)

        count = write_lines(output_path, resolved_hosts)
        # Follow-up writes a sidecar file. Replacing context.resolved here would
        # drop the seed set; the runner unions after an atomic merge.
        if not suffix:
            context.resolved = read_lines(output_path)

        if not result.success:
            return PluginResult(
                success=False,
                output_path=output_path,
                lines_produced=count,
                message=result.message or "dnsx execution failed",
            )

        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=f"Resolved {count} hosts with full DNS records",
        )
