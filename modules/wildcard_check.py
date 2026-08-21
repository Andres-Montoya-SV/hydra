"""Wildcard DNS canary check — detect catch-all DNS before trusting subdomains.

Mirrors the tarpit canary pattern in ``modules/naabu.py``: probe randomly
chosen, improbable names that no real service would register. If they
resolve, every subsequently discovered subdomain under that root may be a
wildcard false positive and must be treated accordingly.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

from core.domain import parse_hostname
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl, write_lines
from utils.subprocess import run_command


class WildcardCheckPlugin(BaseToolPlugin):
    """Probe random canary subdomains with dnsx before trusting enumeration."""

    name = "wildcard_check"
    display_name = "Wildcard DNS Check"
    required = False
    # Built-in check that *uses* the dnsx binary (same as dnsx plugin) —
    # readiness is gated on dnsx being runnable in the runner, not on a
    # separate ToolDefinition named "wildcard_check".
    external_dependency = False
    stage_order = 29
    cacheable = False
    install_hint_macos = "brew install dnsx"
    install_hint_linux = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_wildcard_check

    def get_binary_path(self) -> Path:
        return self.settings.dnsx_path

    def get_install_hint(self) -> str:
        return f"macOS: {self.install_hint_macos} | Linux: {self.install_hint_linux}"

    def _dnsx_binary(self, context: PipelineContext) -> Path:
        return context.resolved_binaries.get("dnsx", self.settings.dnsx_path)

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        root_domains = list(
            dict.fromkeys(
                parse_hostname(target.domain)[2] for target in context.targets if target.domain
            )
        )
        root_domains = [domain for domain in root_domains if domain]
        if not root_domains:
            return self._skip("No root domains to probe for wildcard DNS")

        self.update_status(context, ToolStatus.RUNNING)
        canary_count = max(2, self.settings.wildcard_canary_count)
        canaries_by_root: dict[str, list[str]] = {}
        all_canaries: list[str] = []
        for root in root_domains:
            canaries = [_canary_hostname(root) for _ in range(canary_count)]
            canaries_by_root[root] = canaries
            all_canaries.extend(canaries)

        canary_path = self._output_path(context, "wildcard_canaries.txt")
        write_lines(canary_path, all_canaries, base_dir=context.output_dir)
        raw_path = self._output_path(context, "wildcard_check_raw.txt")

        args = [
            str(self._dnsx_binary(context)),
            "-l",
            str(canary_path),
            "-a",
            "-silent",
            "-resp",
            "-t",
            str(min(self.settings.threads, 20)),
            "-retry",
            "1",
        ]
        try:
            return_code, stdout, stderr = await run_command(
                args, timeout=self.settings.timeout, tool_name=self.name
            )
        except Exception as exc:
            self.update_status(context, ToolStatus.FAILED, error_message=str(exc))
            return PluginResult(success=False, message=f"Wildcard canary probe failed: {exc}")

        from utils.security import atomic_write_text, relative_output_path, scrub_local_paths

        raw_content = scrub_local_paths(
            f"$ {' '.join(args)}\n\n"
            f"----- stdout -----\n{stdout}\n"
            f"----- stderr -----\n{stderr}\n",
            context.output_dir,
        )
        atomic_write_text(raw_path, raw_content)

        resolved_canaries = _parse_resolved_hosts(stdout)
        records: list[dict[str, object]] = []
        wildcard_roots: list[str] = []
        for root, canaries in canaries_by_root.items():
            hit = [name for name in canaries if name in resolved_canaries]
            detected = len(hit) >= 1
            records.append(
                {
                    "root_domain": root,
                    "wildcard_dns_detected": detected,
                    "canary_hosts": canaries,
                    "canary_resolved": hit,
                    "raw_artifact": relative_output_path(raw_path, context.output_dir),
                    "return_code": return_code,
                }
            )
            if detected:
                wildcard_roots.append(root)
                context.add_warning(
                    f"wildcard_check: {root} resolved {len(hit)}/{len(canaries)} "
                    "improbable canary subdomain(s) — DNS wildcard active; passively "
                    "discovered subdomains under this root are not independently confirmed"
                )

        output_path = self._output_path(context, "wildcard_check.jsonl")
        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        context.metadata["wildcard_dns_detected"] = bool(wildcard_roots)
        context.metadata["wildcard_dns_roots"] = wildcard_roots

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"Wildcard DNS detected on {len(wildcard_roots)}/{len(root_domains)} root(s)"
                if wildcard_roots
                else f"No wildcard DNS on {len(root_domains)} root(s)"
            ),
        )


def _canary_hostname(root_domain: str) -> str:
    """Build an improbable subdomain that no real service would register."""
    prefix = "zqxvw" + "".join(
        random.choices(
            string.ascii_lowercase + string.digits, k=8
        )  # nosec B311  # canary hostname, not cryptography
    )
    return f"{prefix}.{root_domain}"


def _parse_resolved_hosts(stdout: str) -> set[str]:
    """Extract hostnames that dnsx reported as resolved (JSON or plain)."""
    resolved: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(rec.get("host", "")).strip().rstrip(".").lower()
            # Only count names that actually returned address records —
            # dnsx JSON for NXDOMAIN/failed lookups must not count as hits.
            if host and (rec.get("a") or rec.get("aaaa")):
                resolved.add(host)
            continue
        # Plain: "hostname [ip]" — require at least one token after the name
        # that looks like an IP so a bare hostname echo is not a false hit.
        parts = line.split()
        token = parts[0].rstrip(".").lower()
        if token and len(parts) > 1:
            resolved.add(token)
    return resolved
