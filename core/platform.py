"""Cross-platform environment detection."""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class OSType(str, Enum):
    """Detected operating system family."""

    MACOS = "macos"
    LINUX = "linux"
    UNKNOWN = "unknown"


class MacArch(str, Enum):
    """macOS CPU architecture."""

    ARM64 = "arm64"
    X86_64 = "x86_64"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PlatformInfo:
    """Detected platform characteristics for portable path resolution."""

    os_type: OSType
    mac_arch: MacArch
    is_macos: bool
    is_linux: bool
    home: Path
    path_dirs: tuple[Path, ...]
    gobin: Path | None
    gopath_bin: Path | None
    homebrew_bin: Path | None
    homebrew_prefix: Path | None

    @property
    def label(self) -> str:
        """Human-readable platform label."""
        if self.is_macos:
            return f"macOS ({self.mac_arch.value})"
        if self.is_linux:
            return f"Linux ({platform.release()})"
        return platform.system()


def detect_platform() -> PlatformInfo:
    """Detect OS, architecture, and common binary search locations.

    Returns:
        PlatformInfo with resolved search paths. Never assumes Homebrew or Go
        are installed — paths are included only when directories exist.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_type = OSType.MACOS
        mac_arch = MacArch.ARM64 if machine in {"arm64", "aarch64"} else MacArch.X86_64
    elif system == "linux":
        os_type = OSType.LINUX
        mac_arch = MacArch.UNKNOWN
    else:
        os_type = OSType.UNKNOWN
        mac_arch = MacArch.UNKNOWN

    home = Path.home()

    path_dirs: list[Path] = []
    path_env = os.environ.get("PATH", "")
    if path_env:
        for part in path_env.split(os.pathsep):
            part = part.strip()
            if part:
                path_dirs.append(Path(part).expanduser())

    gobin = _path_from_env("GOBIN")
    gopath = os.environ.get("GOPATH", "")
    gopath_bin = (Path(gopath).expanduser() / "bin") if gopath else home / "go" / "bin"

    homebrew_prefix: Path | None = None
    homebrew_bin: Path | None = None
    for prefix in (Path("/opt/homebrew"), Path("/usr/local")):
        brew_bin = prefix / "bin"
        if brew_bin.is_dir():
            homebrew_prefix = prefix
            homebrew_bin = brew_bin
            break

    standard = [
        home / "go" / "bin",
        gopath_bin,
        gobin,
        homebrew_bin,
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/bin"),
        Path("/sbin"),
    ]

    seen: set[Path] = set()
    all_dirs: list[Path] = []
    for directory in path_dirs + [p for p in standard if p is not None]:
        try:
            resolved = directory.expanduser().resolve()
        except OSError:
            continue
        if resolved not in seen and resolved.is_dir():
            seen.add(resolved)
            all_dirs.append(resolved)

    return PlatformInfo(
        os_type=os_type,
        mac_arch=mac_arch,
        is_macos=os_type == OSType.MACOS,
        is_linux=os_type == OSType.LINUX,
        home=home,
        path_dirs=tuple(path_dirs),
        gobin=gobin,
        gopath_bin=gopath_bin if gopath_bin.is_dir() else None,
        homebrew_bin=homebrew_bin,
        homebrew_prefix=homebrew_prefix,
    )


def _path_from_env(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_dir() else None


def python_info() -> dict[str, str]:
    """Return Python runtime information."""
    return {
        "version": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
    }
