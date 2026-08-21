"""Phase 2 — health validation and optional version detection."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from core.dependencies.models import ToolDefinition, ValidationResult

# Exit codes commonly used for help/version output
_ACCEPTABLE_EXIT_CODES = frozenset({0, 1, 2})

_VERSION_LINE = re.compile(
    r"(?:version|v)[\s:]*([0-9][\w.\-+()]*)",
    re.IGNORECASE,
)


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
        """Attempt version detection — failures are non-fatal."""
        for args in defn.version_commands:
            outcome = await self._run_probe(path, args)
            if outcome.success and outcome.output:
                parsed = _extract_version(outcome.output)
                return parsed or outcome.output.split("\n")[0][:120]
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
    for line in output.splitlines()[:5]:
        match = _VERSION_LINE.search(line)
        if match:
            return match.group(1)
        if line and any(c.isdigit() for c in line) and len(line) < 80:
            return line.strip()
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
