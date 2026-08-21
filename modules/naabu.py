"""naabu port scanning plugin (optional)."""

from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from pathlib import Path

from core.exceptions import ValidationError
from core.models import PipelineContext
from core.plugin_base import PluginResult
from core.validation.engine import parse_naabu_line
from modules._base import BaseToolPlugin
from modules.port_verify import _normalize_state, _parse_nmap_output
from utils.files import read_lines, write_jsonl, write_lines
from utils.security import (
    atomic_write_text,
    relative_output_path,
    scrub_local_paths,
    validate_output_path,
    validate_safe_filename,
)
from utils.subprocess import run_command

# Range for randomly-chosen canary ports used by the tarpit/portspoof check.
# High and unassigned enough that no legitimate service should ever be found
# there, and re-randomized every run so a defense cannot special-case a
# fixed, well-known probe set. TCP/6 is always included separately — it is
# the strongest "impossible service" signal (RFC742, 1970s).
_TARPIT_CANARY_MIN_PORT = 20000
_TARPIT_CANARY_MAX_PORT = 60000
_TARPIT_FIXED_CANARY = 6


class NaabuPlugin(BaseToolPlugin):
    name = "naabu"
    display_name = "naabu"
    required = False
    stage_order = 35
    # Port state is a live, time-varying network property (firewalls, rate
    # limiting, and ephemeral services all change it between runs) — a
    # cached result is not a re-scan and must never be silently replayed.
    cacheable = False
    install_hint_macos = "brew install naabu"
    install_hint_linux = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_naabu

    def get_binary_path(self) -> Path:
        return self.settings.naabu_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "naabu.txt")
        hosts = [h for h in read_lines(input_path) if h.strip()]

        scan_input_path = input_path
        tarpit_hosts: set[str] = set()
        if self.settings.naabu_tarpit_check and hosts:
            tarpit_hosts = await self._run_tarpit_check(context, input_path, hosts)
            if tarpit_hosts:
                remaining = [h for h in hosts if h not in tarpit_hosts]
                if not remaining:
                    # Every candidate host failed the canary check — skip the
                    # real scan entirely rather than spend time producing a
                    # long "open ports" list we already know is fabricated.
                    write_lines(output_path, [])
                    context.metadata["naabu_ports"] = 0
                    context.metadata["tarpit_suspected_hosts"] = sorted(tarpit_hosts)
                    return PluginResult(
                        success=True,
                        output_path=output_path,
                        lines_produced=0,
                        message=(
                            f"Skipped port scan — all {len(tarpit_hosts)} host(s) failed the "
                            "tarpit/portspoof canary check"
                        ),
                    )
                scan_input_path = self._output_path(context, "naabu_scan_targets.txt")
                write_lines(scan_input_path, remaining)

        args = [
            str(self.get_binary_path()),
            "-l",
            str(scan_input_path),
            "-silent",
            "-c",
            str(self.settings.threads),
            "-rate",
            str(self.settings.rate_limit),
        ]

        result = await self._execute(context, args, output_path, allow_empty=True)
        ports = read_lines(output_path)

        if self.settings.naabu_confirm_open_ports and ports:
            confirmed = await self._confirm_ports(context, scan_input_path, ports)
            dropped = sorted(set(ports) - set(confirmed))
            if dropped:
                context.add_warning(
                    f"naabu: dropped {len(dropped)} port(s) that did not reproduce on a "
                    "confirmation pass (likely a shared-hosting/anti-scan middlebox "
                    f"completing handshakes on random ports): {', '.join(dropped[:10])}"
                    + (", ..." if len(dropped) > 10 else "")
                )
            if confirmed != ports:
                write_lines(output_path, confirmed)
            ports = confirmed

        context.metadata["naabu_ports"] = len(ports)
        context.metadata["tarpit_suspected_hosts"] = sorted(tarpit_hosts)

        message = f"Discovered {len(ports)} open ports"
        if tarpit_hosts:
            message += f" ({len(tarpit_hosts)} host(s) excluded: tarpit/portspoof suspected)"

        return PluginResult(
            success=result.success,
            output_path=output_path,
            lines_produced=len(ports),
            message=message,
        )

    def _nmap_binary(self, context: PipelineContext) -> Path:
        """Resolve nmap the same way port_verify does (not the naabu binary)."""
        return (
            context.resolved_binaries.get("port_verify")
            or context.resolved_binaries.get("nmap")
            or self.settings.nmap_path
        )

    def _select_canary_ports(self) -> list[int]:
        """Build the canary port set for one run.

        Always includes TCP/6 (RFC742 — no modern host runs a real service
        here). The rest are random high ports so a defense cannot special-case
        a fixed, well-known probe set across runs.
        """
        count = max(1, self.settings.naabu_tarpit_canary_count)
        ports = [_TARPIT_FIXED_CANARY]
        remaining = max(0, count - 1)
        if remaining:
            ports.extend(
                random.sample(
                    range(_TARPIT_CANARY_MIN_PORT, _TARPIT_CANARY_MAX_PORT + 1),
                    remaining,
                )
            )
        return ports

    async def _run_tarpit_check(
        self, context: PipelineContext, input_path: Path, hosts: list[str]
    ) -> set[str]:
        """Probe canary ports with ``nmap -sV`` before trusting naabu's scan.

        Root-cause history (run 20260806_180339): the previous implementation
        used *naabu* for the canary. Against www.metaversejustice.com that
        produced ``tarpit_suspected: false`` with ``canary_open_ports: []`` —
        contradicting two independent ``nmap -sV -p 6,9999,23456,54321``
        runs that showed all four ports ``open``. Diagnosis:

        1. **Technique mismatch** — DreamHost-style tarpits respond to a full
           TCP connect + service-detect handshake (what ``nmap -sV`` does)
           differently than to naabu's lightweight SYN/connect probe.
        2. **Silent failure masking** — when naabu failed with
           ``no valid ipv4 or ipv6 targets were found`` on stderr, this
           method ignored return_code/stderr and treated empty stdout as
           "all canaries closed" → false ``tarpit_suspected: false``.
        3. **No raw artifact** — the failure was invisible in the run output.

        The canary now uses the same ``nmap -sV -Pn`` technique the user
        confirmed against this host, with per-host raw artifacts and explicit
        ``probe_error`` records when the probe itself fails (never a silent
        "not a tarpit" verdict on a broken probe).

        Timing (run 20260806_183325): default nmap timing finished in ~3s and
        reported every canary ``filtered``, while the user's identical-style
        manual ``nmap -sV`` took 165–178s and reported all four ``open``.
        We therefore run a cheap fast pass first, and only if canaries look
        filtered/inconclusive do we re-probe with patient timing
        (``-T1 --max-retries 10 --host-timeout 5m``). Empirically ``-T2``
        still finishes in ~10s against this host; ``-T1`` stretches to the
        ~150–180s window that matches the user's manual confirmation.
        """
        canary_ports = self._select_canary_ports()
        threshold = max(1, self.settings.naabu_tarpit_open_threshold)
        nmap_bin = self._nmap_binary(context)
        records: list[dict[str, object]] = []
        tarpit_hosts: set[str] = set()

        for host in hosts:
            record = await self._probe_host_canaries(context, host, canary_ports, nmap_bin=nmap_bin)
            if record.get("probe_error"):
                context.add_warning(
                    f"naabu tarpit canary: {host}: probe failed "
                    f"({record['probe_error']}) — NOT treating as "
                    "'not a tarpit'; check is inconclusive"
                )
            else:
                opened = list(record.get("canary_open_ports") or [])
                if len(opened) >= threshold:
                    record["tarpit_suspected"] = True
                    tarpit_hosts.add(host)
                    context.add_warning(
                        f"naabu: {host} responded 'open' to {len(opened)}/{len(canary_ports)} "
                        "canary ports with no standard service association (nmap -sV) — "
                        "port scan results for this host are unreliable (tarpit/portspoof "
                        "defense suspected) and will not be treated as security findings"
                    )
                else:
                    record["tarpit_suspected"] = False
            # Drop ephemeral probe payloads — full nmap output lives in raw_artifact.
            records.append(
                {
                    key: value
                    for key, value in record.items()
                    if key not in {"stdout", "stderr", "argv"}
                }
            )

        write_jsonl(
            self._output_path(context, "tarpit_check.jsonl"), records, base_dir=context.output_dir
        )
        return tarpit_hosts

    @staticmethod
    def _build_tarpit_nmap_argv(
        nmap_bin: Path | str,
        canary_ports: list[int],
        host: str,
        *,
        patient: bool,
    ) -> list[str]:
        """Build the exact nmap argv used for a tarpit canary probe.

        ``patient=True`` adds the slow-tarpit timing flags required for hosts
        like DreamHost shared hosting (manual confirmation took ~165s). Kept
        as a pure helper so unit tests can lock the argv without network I/O.
        """
        args = [
            str(nmap_bin),
            "-sV",
            "-Pn",
            "--version-light",
            "-p",
            ",".join(str(port) for port in canary_ports),
        ]
        if patient:
            # -T1 + high retries + 5m host-timeout: match the slow response
            # profile of tarpit middleboxes (manual confirmations took
            # 165–178s). -T2 is not enough — it still exits in ~10s.
            args.extend(["-T1", "--max-retries", "10", "--host-timeout", "5m"])
        args.append(host)
        return args

    async def _probe_host_canaries(
        self,
        context: PipelineContext,
        host: str,
        canary_ports: list[int],
        *,
        nmap_bin: Path,
    ) -> dict[str, object]:
        threshold = max(1, self.settings.naabu_tarpit_open_threshold)
        # Fast pass — cheap for ordinary hosts that answer quickly.
        fast_record = await self._run_single_canary_pass(
            context,
            host,
            canary_ports,
            nmap_bin=nmap_bin,
            patient=False,
        )
        if fast_record.get("probe_error"):
            return fast_record
        opened = list(fast_record.get("canary_open_ports") or [])
        if len(opened) >= threshold:
            fast_record["probe_pass"] = "fast"  # nosec B105
            return fast_record

        # Ambiguous/negative after a fast pass: re-probe patiently. DreamHost-
        # style tarpits frequently answer "filtered" in ~3s under default
        # timing and "open" only after 100–180s of waiting.
        patient_record = await self._run_single_canary_pass(
            context,
            host,
            canary_ports,
            nmap_bin=nmap_bin,
            patient=True,
            prior_raw=str(fast_record.get("raw_artifact") or ""),
            prior_section=(
                f"$ {' '.join(fast_record.get('argv') or [])}\n\n"
                f"----- stdout -----\n{fast_record.get('stdout') or ''}\n"
                f"----- stderr -----\n{fast_record.get('stderr') or ''}\n"
            ),
        )
        if patient_record.get("probe_error") and opened:
            # Keep the (non-threshold) fast result rather than discarding it
            # for a failed slow pass — still not a tarpit, but auditable.
            fast_record["probe_pass"] = "fast"  # nosec B105
            fast_record["patient_probe_error"] = patient_record["probe_error"]
            return fast_record
        if patient_record.get("probe_error"):
            return patient_record
        patient_record["probe_pass"] = "patient"  # nosec B105
        return patient_record

    async def _run_single_canary_pass(
        self,
        context: PipelineContext,
        host: str,
        canary_ports: list[int],
        *,
        nmap_bin: Path,
        patient: bool,
        prior_raw: str = "",
        prior_section: str = "",
    ) -> dict[str, object]:
        args = self._build_tarpit_nmap_argv(nmap_bin, canary_ports, host, patient=patient)
        technique = (
            "nmap -sV -Pn -T1 --max-retries 10 --host-timeout 5m" if patient else "nmap -sV -Pn"
        )
        try:
            return_code, stdout, stderr = await run_command(
                args,
                timeout=self.settings.naabu_tarpit_timeout,
                tool_name="tarpit_check",
            )
        except Exception as exc:
            raw_artifact = self._write_tarpit_raw_artifact(
                context,
                host,
                args,
                stdout="",
                stderr=str(exc),
                prior_section=prior_section,
            )
            return {
                "host": host,
                "tarpit_suspected": False,
                "canary_ports": canary_ports,
                "canary_open_ports": [],
                "canary_states": {},
                "probe_error": str(exc)[:240],
                "probe_technique": technique,
                "raw_artifact": raw_artifact or prior_raw or None,
                "argv": args,
                "stdout": "",
                "stderr": str(exc),
            }

        raw_artifact = self._write_tarpit_raw_artifact(
            context, host, args, stdout, stderr, prior_section=prior_section
        )

        # Fatal tool failures (missing binary, DNS resolution inside nmap that
        # produces no port table, etc.) must NOT be reported as a clean
        # "0 canaries open" negative. That was the exact bug in run
        # 20260806_180339 when naabu printed FTL to stderr and we treated
        # empty stdout as proof the host was not a tarpit.
        fatal_markers = ("Could not run enumeration", "Failed to resolve", "QUITTING")
        combined_err = (stderr or "") + "\n" + (stdout or "")
        if any(marker in combined_err for marker in fatal_markers) and "PORT" not in (stdout or ""):
            return {
                "host": host,
                "tarpit_suspected": False,
                "canary_ports": canary_ports,
                "canary_open_ports": [],
                "canary_states": {},
                "probe_error": f"nmap probe failed (exit {return_code}): {stderr.strip()[:200] or 'no port table'}",
                "probe_technique": technique,
                "raw_artifact": raw_artifact or prior_raw or None,
                "return_code": return_code,
                "argv": args,
                "stdout": stdout,
                "stderr": stderr,
            }

        parsed = _parse_nmap_output(stdout)
        if not parsed and return_code != 0:
            return {
                "host": host,
                "tarpit_suspected": False,
                "canary_ports": canary_ports,
                "canary_open_ports": [],
                "canary_states": {},
                "probe_error": (
                    f"nmap exited {return_code} with no parseable port table: "
                    f"{(stderr or stdout).strip()[:200] or 'empty output'}"
                ),
                "probe_technique": technique,
                "raw_artifact": raw_artifact or prior_raw or None,
                "return_code": return_code,
                "argv": args,
                "stdout": stdout,
                "stderr": stderr,
            }

        states: dict[str, str] = {}
        opened: list[int] = []
        for port in canary_ports:
            observation = parsed.get(port, {})
            raw_state = str(observation.get("state", "unknown"))
            state = _normalize_state(raw_state)
            states[str(port)] = state
            if state == "open":
                opened.append(port)

        return {
            "host": host,
            "tarpit_suspected": False,  # set by caller after threshold check
            "canary_ports": canary_ports,
            "canary_open_ports": opened,
            "canary_states": states,
            "probe_error": None,
            "probe_technique": technique,
            "raw_artifact": raw_artifact or prior_raw or None,
            "return_code": return_code,
            "argv": args,
            "stdout": stdout,
            "stderr": stderr,
        }

    def _write_tarpit_raw_artifact(
        self,
        context: PipelineContext,
        host: str,
        args: list[str],
        stdout: str,
        stderr: str,
        *,
        prior_section: str = "",
    ) -> str | None:
        """Persist the exact nmap canary command + output for auditability.

        Same pattern as ``wildcard_check_raw.txt`` / ``port_verify_raw/`` —
        without this, a silent tool failure (empty stdout, FTL on stderr) is
        indistinguishable from a genuine "all canaries closed" result.
        """
        try:
            filename = validate_safe_filename(f"{host}.txt")
        except ValidationError:
            filename = validate_safe_filename(f"host-{abs(hash(host))}.txt")
        raw_path = validate_output_path(
            context.output_dir / "tarpit_check_raw" / filename, context.output_dir
        )
        sections = []
        if prior_section.strip():
            sections.append(prior_section.rstrip() + "\n")
        sections.append(
            f"$ {' '.join(args)}\n\n"
            f"----- stdout -----\n{stdout}\n"
            f"----- stderr -----\n{stderr}\n"
        )
        try:
            atomic_write_text(raw_path, scrub_local_paths("\n".join(sections), context.output_dir))
        except OSError as exc:
            self.logger.warning("Failed to write tarpit raw artifact for %s: %s", host, exc)
            return None
        return relative_output_path(raw_path, context.output_dir)

    async def _confirm_ports(
        self, context: PipelineContext, input_path: Path, first_pass_lines: list[str]
    ) -> list[str]:
        """Re-probe first-pass ports and keep only what reproduces.

        Some shared-hosting/anti-scan middleboxes (common on cheap shared
        hosting) complete TCP handshakes for an essentially random sample of
        probed ports on any single scan, so a lone naabu pass against such a
        target reports a different noisy "open" set every run even though
        nothing on the target actually changed. A single "open" observation
        is therefore not trustworthy signal by itself. Re-probing exactly
        the ports found open — targeted, so this is fast — after a short
        delay and keeping only the intersection filters this false-positive
        noise out before it reaches nmap/port_verify.
        """
        ports_by_host: dict[str, set[int]] = defaultdict(set)
        for line in first_pass_lines:
            parsed = parse_naabu_line(line)
            if parsed:
                ports_by_host[parsed.host].add(parsed.port)
        if not ports_by_host:
            return first_pass_lines

        await asyncio.sleep(self.settings.naabu_confirm_delay_seconds)

        all_ports = sorted({port for ports in ports_by_host.values() for port in ports})
        args = [
            str(self.resolved_binary(context)),
            "-l",
            str(input_path),
            "-p",
            ",".join(str(port) for port in all_ports),
            "-silent",
            "-c",
            str(self.settings.threads),
            "-rate",
            str(self.settings.rate_limit),
        ]
        try:
            _return_code, stdout, _stderr = await run_command(
                args, timeout=self.settings.timeout, tool_name=self.name
            )
        except Exception as exc:
            self.logger.warning(
                "naabu confirmation pass failed (%s); keeping first-pass results", exc
            )
            return first_pass_lines

        confirmed_set = {line.strip() for line in stdout.splitlines() if line.strip()}
        return [line for line in first_pass_lines if line.strip() in confirmed_set]
