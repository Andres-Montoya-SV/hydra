"""Second-pass service verification for Naabu findings using nmap."""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from pathlib import Path

from core.exceptions import ValidationError
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from core.validation.engine import parse_naabu_line
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_jsonl
from utils.security import (
    atomic_write_text,
    relative_output_path,
    scrub_local_paths,
    validate_output_path,
    validate_safe_filename,
)
from utils.subprocess import run_command

_NMAP_PORT_LINE = re.compile(
    r"^(?P<port>\d+)\/(?P<protocol>\w+)\s+"
    r"(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$"
)


class PortVerifyPlugin(BaseToolPlugin):
    """Confirm Naabu observations with nmap TCP service detection."""

    name = "port_verify"
    display_name = "Port Verification"
    required = False
    stage_order = 36
    produces = ("ports",)
    capability = "port_verify"
    active_collection = True
    # This plugin exists specifically to re-check naabu's findings against
    # the *current* live TCP state. Replaying a cached artifact would defeat
    # its entire purpose — a target's filtering/firewall behavior can change
    # within minutes (e.g. after repeated scanning triggers rate limiting).
    cacheable = False
    install_hint_macos = "brew install nmap"
    install_hint_linux = "sudo apt install nmap"

    def is_enabled(self) -> bool:
        return self.settings.enable_naabu and self.settings.enable_port_verify

    def get_binary_path(self) -> Path:
        return self.settings.nmap_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        naabu_path = self._authorized_input(
            context,
            input_path if input_path.exists() else context.output_dir / "naabu.txt",
        )
        output_path = self._output_path(context, "port_verify.jsonl")
        grouped = _group_naabu_ports(naabu_path)
        if not grouped:
            return self._skip("Naabu produced no ports to verify")

        hosts = sorted(grouped)
        selected_hosts = hosts[: self.settings.port_verify_max_hosts]
        if len(hosts) > len(selected_hosts):
            context.add_warning(
                "Port Verification capped at "
                f"{len(selected_hosts)}/{len(hosts)} hosts; increase "
                "PORT_VERIFY_MAX_HOSTS to verify the remainder"
            )

        self.update_status(context, ToolStatus.RUNNING)
        semaphore = asyncio.Semaphore(self.settings.port_verify_concurrency)

        async def verify(host: str) -> tuple[list[dict[str, object]], str | None]:
            ports = sorted(grouped[host])[: self.settings.port_verify_max_ports_per_host]
            async with semaphore:
                return await self._verify_host(context, host, ports)

        results = await asyncio.gather(
            *(verify(host) for host in selected_hosts),
            return_exceptions=True,
        )

        records: list[dict[str, object]] = []
        warnings: list[str] = []
        for host, result in zip(selected_hosts, results, strict=False):
            if isinstance(result, Exception):
                warnings.append(f"{host}: {result}")
                continue
            host_records, warning = result
            records.extend(host_records)
            if warning:
                warnings.append(warning)

        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        for warning in warnings[:10]:
            context.add_warning(f"Port Verification: {warning}")
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)

        verified = sum(1 for record in records if record["nmap_state"] == "open")
        rejected = sum(1 for record in records if record["nmap_state"] in {"filtered", "closed"})
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=(
                f"Verified {verified} open port(s); "
                f"{rejected} Naabu observation(s) were filtered/closed"
            ),
        )

    async def _verify_host(
        self,
        context: PipelineContext,
        host: str,
        ports: list[int],
    ) -> tuple[list[dict[str, object]], str | None]:
        args = [
            str(self.resolved_binary(context)),
            "-sV",
            "-Pn",
            "--version-light",
            "-p",
            ",".join(str(port) for port in ports),
            host,
        ]
        try:
            return_code, stdout, stderr = await run_command(
                args,
                timeout=self.settings.port_verify_timeout,
                tool_name=self.name,
            )
        except Exception as exc:
            return [], f"{host}: {exc}"

        raw_artifact = self._write_raw_artifact(context, host, args, stdout, stderr)

        parsed = _parse_nmap_output(stdout)
        records: list[dict[str, object]] = []
        for port in ports:
            observation = parsed.get(port, {})
            raw_state = str(observation.get("state", "unknown"))
            state = _normalize_state(raw_state)
            records.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": observation.get("protocol", "tcp"),
                    "naabu_state": "open",
                    "nmap_state": state,
                    "nmap_raw_state": raw_state,
                    "service": observation.get("service"),
                    "version": observation.get("version"),
                    "raw_artifact": raw_artifact,
                }
            )

        warning = None
        if return_code != 0:
            detail = stderr.strip().splitlines()[-1] if stderr.strip() else "unknown error"
            warning = f"{host}: nmap exited {return_code}: {detail[:160]}"
        return records, warning

    def _write_raw_artifact(
        self,
        context: PipelineContext,
        host: str,
        args: list[str],
        stdout: str,
        stderr: str,
    ) -> str | None:
        """Persist nmap's raw stdout/stderr for this host, mirroring the
        `whois_raw.txt` pattern — without the actual command text and full
        output on disk, there is no way to audit whether the parser read
        nmap's response correctly (this was essential to diagnosing prior
        parsing bugs in this exact plugin).
        """
        try:
            filename = validate_safe_filename(f"{host}.txt")
        except ValidationError:
            filename = validate_safe_filename(f"host-{abs(hash(host))}.txt")

        raw_path = validate_output_path(
            context.output_dir / "port_verify_raw" / filename, context.output_dir
        )
        content = scrub_local_paths(
            f"$ {' '.join(args)}\n\n"
            f"----- stdout -----\n{stdout}\n"
            f"----- stderr -----\n{stderr}\n",
            context.output_dir,
        )
        try:
            atomic_write_text(raw_path, content)
        except OSError as exc:
            self.logger.warning("Failed to write nmap raw artifact for %s: %s", host, exc)
            return None
        return relative_output_path(raw_path, context.output_dir)


def _group_naabu_ports(path: Path) -> dict[str, set[int]]:
    grouped: dict[str, set[int]] = defaultdict(set)
    for line in read_lines(path):
        port = parse_naabu_line(line)
        if port:
            grouped[port.host].add(port.port)
    return dict(grouped)


def _parse_nmap_output(output: str) -> dict[int, dict[str, str]]:
    parsed: dict[int, dict[str, str]] = {}
    in_port_table = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("PORT ") and "STATE" in line:
            in_port_table = True
            continue
        if not in_port_table:
            continue
        match = _NMAP_PORT_LINE.match(line)
        if not match:
            continue
        values = match.groupdict()
        parsed[int(values["port"])] = {
            "protocol": values["protocol"],
            "state": values["state"],
            "service": values["service"],
            "version": (values.get("version") or "").strip(),
        }
    return parsed


def _normalize_state(state: str) -> str:
    normalized = state.lower()
    if normalized == "open":
        return "open"
    if "filtered" in normalized:
        return "filtered"
    if normalized == "closed":
        return "closed"
    return "unknown"
