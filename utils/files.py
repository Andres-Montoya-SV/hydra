"""File I/O utilities for reconnaissance outputs."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from utils.security import atomic_write_text, backup_if_exists, validate_output_path


def read_lines(path: Path, *, max_lines: int = 1_000_000) -> list[str]:
    """Read non-empty, stripped lines from a text file.

    Args:
        path: File to read.
        max_lines: Maximum lines to read (DoS protection).

    Returns:
        List of non-empty stripped lines.

    Raises:
        OSError: On read failure.
        ValueError: If file exceeds max_lines.
    """
    if not path.exists():
        return []

    lines: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if len(lines) >= max_lines:
                raise ValueError(f"File exceeds maximum line count ({max_lines}): {path}")
            stripped = raw.strip()
            if stripped:
                lines.append(stripped)
    return lines


def write_lines(path: Path, lines: Iterable[str], *, base_dir: Path | None = None) -> int:
    """Write unique lines to a file using atomic write.

    Args:
        path: Destination file path.
        lines: Lines to write.
        base_dir: Optional base directory for path confinement.

    Returns:
        Number of unique lines written.

    Raises:
        ValidationError: If path escapes base_dir.
    """
    if base_dir is not None:
        path = validate_output_path(path, base_dir)

    unique = list(dict.fromkeys(line.strip() for line in lines if line and line.strip()))
    content = "\n".join(unique) + ("\n" if unique else "")
    atomic_write_text(path, content)
    return len(unique)


def dedupe_file(
    input_path: Path,
    output_path: Path | None = None,
    *,
    base_dir: Path | None = None,
) -> tuple[Path, int]:
    """Remove duplicate lines from a file, preserving order.

    Args:
        input_path: Source file.
        output_path: Optional separate output; defaults to input_path.
        base_dir: Optional base directory for path confinement.

    Returns:
        Tuple of (output path, line count).
    """
    target = output_path or input_path
    lines = read_lines(input_path)
    count = write_lines(target, lines, base_dir=base_dir)
    return target, count


def write_json(path: Path, data: Any, *, base_dir: Path | None = None) -> None:
    """Write JSON data atomically with pretty formatting.

    Args:
        path: Destination path.
        data: JSON-serializable data.
        base_dir: Optional base directory for path confinement.
    """
    if base_dir is not None:
        path = validate_output_path(path, base_dir)
    content = json.dumps(data, indent=2, default=str)
    atomic_write_text(path, content)


def read_json(path: Path) -> Any:
    """Read and parse a JSON file.

    Args:
        path: JSON file path.

    Returns:
        Parsed data, or None if file does not exist.
    """
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_jsonl(
    path: Path,
    records: list[dict[str, Any]],
    *,
    base_dir: Path | None = None,
) -> int:
    """Write records as JSON lines atomically.

    Args:
        path: Destination path.
        records: List of dict records.
        base_dir: Optional base directory for path confinement.

    Returns:
        Number of records written.
    """
    if base_dir is not None:
        path = validate_output_path(path, base_dir)
    lines = [json.dumps(r, default=str) for r in records]
    content = "\n".join(lines) + ("\n" if lines else "")
    atomic_write_text(path, content)
    return len(lines)


def read_jsonl(path: Path, *, max_records: int = 500_000) -> list[dict[str, Any]]:
    """Read JSON lines from a file with a record limit.

    Args:
        path: JSONL file path.
        max_records: Maximum records to parse.

    Returns:
        Parsed records.
    """
    if not path.exists():
        return []
    results: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(results) >= max_records:
                break
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        results.append(record)
                except json.JSONDecodeError:
                    continue
    return results


def ensure_parent(path: Path) -> Path:
    """Ensure parent directory exists and return the path.

    Args:
        path: File path.

    Returns:
        The same path after creating parents.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def safe_write_text(path: Path, content: str, *, base_dir: Path) -> None:
    """Write text with backup and atomic replace, confined to base_dir.

    Args:
        path: Destination path.
        content: Text content.
        base_dir: Required base directory for confinement.
    """
    path = validate_output_path(path, base_dir)
    backup_if_exists(path)
    atomic_write_text(path, content)
