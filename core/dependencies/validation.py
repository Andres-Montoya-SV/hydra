"""Phase 2 — health validation and optional version detection."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from core.dependencies.models import ToolDefinition, ValidationResult
from utils.subprocess import child_process_env

# Exit codes commonly used for help/version output
_ACCEPTABLE_EXIT_CODES = frozenset({0, 1, 2})

_VERSION_LINE = re.compile(
    r"(?:version|v)[\s:]*([0-9][\w.\-+()]*)",
    re.IGNORECASE,
)
# A bare "1.2.3"/"v1.2.3" line with nothing else on it — the fallback used
# only when no line matched _VERSION_LINE above. Deliberately anchored
# start-to-end (not "contains a digit somewhere"): several real tools
# (amass, httpx, naabu, katana, dnsx) print a multi-line ASCII banner
# before their real version line, and the previous "any digit, under 80
# chars" fallback matched banner art lines that happen to contain a
# stray digit from the box-drawing pattern — confirmed live against real
# installed binaries (hardening round 2, Task 1): amass's own `version`
# subcommand banner produced the "version" string
# '+W@@@@@@8        &+W@#...' this way, silently, with no error.
_BARE_VERSION_LINE = re.compile(r"^(?:[a-zA-Z]+-)?v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][\w.]+)?$")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


class HealthValidator:
    """Validate tool executability without requiring version flags."""

    def __init__(self, *, probe_timeout: float = 10.0, smoke_timeout: float = 3.0) -> None:
        self.probe_timeout = probe_timeout
        self.smoke_timeout = smoke_timeout

    async def validate(self, path: Path, defn: ToolDefinition) -> ValidationResult:
        notes: list[str] = []

        # Health probes (tool-specific, then generic)
        for args in defn.health_commands:
            outcome = await self._run_probe(path, args)
            if outcome.success:
                notes.append(f"Health check passed ({outcome.label})")
                version = await self._try_version(path, defn)
                return ValidationResult(
                    can_execute=True,
                    version=version,
                    probe_command=outcome.label,
                    probe_exit_code=outcome.exit_code,
                    version_obtained=version is not None,
                    notes=notes,
                    probe_output=outcome.output,
                )

        # Generic fallbacks — do not assume -version works
        for args in (("-h",), ("--help",), ("-help",), ("help",)):
            if args in defn.health_commands:
                continue
            outcome = await self._run_probe(path, args)
            if outcome.success:
                notes.append(f"Generic health check passed ({outcome.label})")
                version = await self._try_version(path, defn)
                return ValidationResult(
                    can_execute=True,
                    version=version,
                    probe_command=outcome.label,
                    probe_exit_code=outcome.exit_code,
                    version_obtained=version is not None,
                    notes=notes,
                    probe_output=outcome.output,
                )

        # Smoke test — process starts successfully (no version required)
        if defn.allow_smoke_test:
            if await self._smoke_test(path):
                notes.append("Smoke test passed (binary executes)")
                version = await self._try_version(path, defn)
                return ValidationResult(
                    can_execute=True,
                    version=version,
                    probe_command="smoke_test",
                    probe_exit_code=0,
                    version_obtained=version is not None,
                    notes=notes,
                    probe_output="",
                )

        notes.append("All health probes failed")
        return ValidationResult(can_execute=False, notes=notes)

    def _identity_confirmed(self, defn: ToolDefinition, validation: ValidationResult) -> bool:
        combined = f"{validation.probe_output} {validation.version or ''} {' '.join(validation.notes)}".lower()
        return any(marker.lower() in combined for marker in defn.identity_markers)

    async def validate_at_path(
        self,
        path: Path,
        defn: ToolDefinition,
    ) -> ValidationResult:
        """Validate a specific binary path."""
        validation = await self.validate(path, defn)
        if not validation.can_execute:
            return validation
        if defn.identity_markers and not self._identity_confirmed(defn, validation):
            return ValidationResult(
                can_execute=False,
                notes=["Wrong binary variant (identity check failed)"],
            )
        return validation

    async def _try_version(self, path: Path, defn: ToolDefinition) -> str | None:
        """Attempt version detection — failures are non-fatal.

        Tries every configured version_commands entry in order until one
        actually yields a parseable version, not just until one "succeeds"
        (exit code 0 with output) — confirmed live that amass's own
        ``version`` subcommand exits 0 with real output (a multi-line
        ASCII banner) that contains no parseable version at all, while its
        ``-version`` flag gives a single clean line. Previously the first
        "successful" command won regardless, and the loop fell back to
        that command's own first output line (banner art) as if it were
        the version — never correct, only silently wrong.
        """
        for args in defn.version_commands:
            outcome = await self._run_probe(path, args)
            if not (outcome.success and outcome.output):
                continue
            parsed = _extract_version(outcome.output)
            if parsed:
                return parsed
        return None

    async def _run_probe(self, path: Path, args: tuple[str, ...]) -> _ProbeOutcome:
        label = f"{path.name} {' '.join(args)}".strip()
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                str(path),
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_process_env(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.probe_timeout,
            )
            output = ((stdout or b"") + (stderr or b"")).decode("utf-8", errors="replace").strip()
            exit_code = proc.returncode if proc.returncode is not None else -1
            success = exit_code in _ACCEPTABLE_EXIT_CODES or bool(output)
            return _ProbeOutcome(success=success, label=label, exit_code=exit_code, output=output)
        except FileNotFoundError:
            return _ProbeOutcome(success=False, label=label)
        except (PermissionError, OSError):
            return _ProbeOutcome(success=False, label=label)
        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            return _ProbeOutcome(success=False, label=label)
        except Exception:
            return _ProbeOutcome(success=False, label=label)

    async def _smoke_test(self, path: Path) -> bool:
        """Verify the binary can be invoked — version flags not required."""
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_process_env(),
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=self.smoke_timeout)
            except asyncio.TimeoutError:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                return True
            return True
        except (FileNotFoundError, PermissionError, OSError):
            return False


def _extract_version(output: str) -> str | None:
    """Find a real version string in a tool's version/help output.

    Scans up to 40 lines (not 5) — confirmed live against real installed
    binaries that several of Hydra's primary tools (httpx, naabu, katana,
    dnsx) print a multi-line ASCII banner before their actual
    "Current Version: vX.Y.Z" line, which sits well past line 5. The
    stricter bare-version fallback below only accepts a line that is
    *entirely* a version token (optionally ANSI-colored) — not "contains
    a digit anywhere," which previously matched banner art by accident.
    """
    lines = [_ANSI_ESCAPE.sub("", line).strip() for line in output.splitlines()[:40]]
    for line in lines:
        match = _VERSION_LINE.search(line)
        if match:
            return match.group(1)
    for line in lines:
        if line and _BARE_VERSION_LINE.match(line):
            return line
    return None


class _ProbeOutcome:
    __slots__ = ("success", "label", "exit_code", "output")

    def __init__(
        self,
        *,
        success: bool,
        label: str = "",
        exit_code: int | None = None,
        output: str = "",
    ) -> None:
        self.success = success
        self.label = label
        self.exit_code = exit_code
        self.output = output
