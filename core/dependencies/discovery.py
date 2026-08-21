"""Phase 1 — binary discovery with PATH and Homebrew symlink preference."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from core.dependencies.models import DiscoveryResult, ToolDefinition
from core.platform import PlatformInfo


class BinaryDiscovery:
    """Locate tool binaries without executing them."""

    CELLAR_MARKER = "/Cellar/"

    def __init__(self, platform: PlatformInfo) -> None:
        self.platform = platform

    def discover(self, defn: ToolDefinition, configured: Path) -> DiscoveryResult:
        """Return best discovery result (legacy single-candidate API)."""
        candidates = self.discover_candidates(defn, configured)
        if not candidates:
            tried: list[str] = []
            for path, _, _ in self._build_candidates(defn.binary_name, configured):
                tried.append(str(path))
            return DiscoveryResult(found=False, candidates_tried=tried)
        return candidates[0]

    def discover_candidates(self, defn: ToolDefinition, configured: Path) -> list[DiscoveryResult]:
        """Return ordered discovery results for all viable candidates."""
        bare = defn.binary_name
        raw_candidates = self._build_candidates(bare, configured)
        tried: list[str] = []
        results: list[tuple[int, DiscoveryResult]] = []

        for path, source, score in raw_candidates:
            tried.append(str(path))
            path_str = str(path)
            if defn.path_denylist and any(d in path_str for d in defn.path_denylist):
                continue
            if not path.is_file():
                continue
            if not os.access(path, os.X_OK):
                continue

            resolved = self._resolve_path(path)
            in_path = self._in_path(resolved, bare)
            is_cellar = self.CELLAR_MARKER in str(resolved)
            final_score = score + (20 if in_path else 0) - (15 if is_cellar else 0)

            result = DiscoveryResult(
                found=True,
                path=resolved,
                source=source,
                in_path=in_path,
                is_symlink=path.is_symlink(),
                is_cellar_path=is_cellar,
                candidates_tried=list(tried),
            )
            results.append((final_score, result))

        results.sort(key=lambda item: item[0], reverse=True)
        return [r for _, r in results]

    def _build_candidates(
        self,
        bare: str,
        configured: Path,
    ) -> list[tuple[Path, str, int]]:
        """Return (path, source_label, base_score) ordered by preference."""
        seen: set[Path] = set()
        results: list[tuple[Path, str, int]] = []

        def add(path: Path, source: str, score: int) -> None:
            try:
                resolved = path.expanduser()
                key = resolved.resolve() if resolved.exists() else resolved
            except OSError:
                key = path
            if key in seen:
                return
            seen.add(key)
            results.append((path.expanduser(), source, score))

        # Homebrew symlinks first — stable, preferred over Python conflicts
        if self.platform.homebrew_bin:
            add(self.platform.homebrew_bin / bare, "homebrew", 98)

        which_hit = shutil.which(bare)
        if which_hit:
            add(Path(which_hit), "PATH", 90)

        if os.sep in str(configured) or configured.name != str(configured):
            add(configured, "configured", 85)

        for label, directory in (
            ("GOBIN", self.platform.gobin),
            ("GOPATH/bin", self.platform.gopath_bin),
            ("~/go/bin", self.platform.home / "go" / "bin"),
        ):
            if directory and directory.is_dir():
                add(directory / bare, label, 80)

        for directory in self.platform.path_dirs:
            add(directory / bare, "PATH", 75)

        for directory in (Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin")):
            if directory.is_dir():
                add(directory / bare, "system", 60)

        if self.platform.homebrew_prefix:
            cellar_root = self.platform.homebrew_prefix / "Cellar" / bare
            if cellar_root.is_dir():
                for version_dir in sorted(cellar_root.iterdir(), reverse=True):
                    candidate = version_dir / "bin" / bare
                    if candidate.is_file():
                        add(candidate, "homebrew-cellar", 10)
                        break

        results.sort(key=lambda item: item[2], reverse=True)
        return results

    def _resolve_path(self, path: Path) -> Path:
        try:
            return path.resolve()
        except OSError:
            return path

    def _in_path(self, path: Path, bare: str) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return False

        which_hit = shutil.which(bare)
        if which_hit:
            try:
                if Path(which_hit).resolve() == resolved:
                    return True
            except OSError:
                pass

        for directory in self.platform.path_dirs:
            try:
                dir_resolved = directory.resolve()
                if resolved.parent == dir_resolved:
                    return True
                try:
                    link = dir_resolved / bare
                    if link.exists() and link.resolve() == resolved:
                        return True
                except OSError:
                    pass
            except OSError:
                continue
        return False
