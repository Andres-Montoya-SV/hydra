"""Security utilities: path validation, log sanitization, and safe identifiers."""

from __future__ import annotations

import html
import os
import re
import shutil
import uuid
from pathlib import Path

from core.exceptions import ConfigurationError, ValidationError

# Safe run-id: alphanumeric, underscore, hyphen only
_RUN_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Safe filename component (no path separators or traversal)
_SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")

# Header name per RFC 7230 token
_HEADER_NAME = re.compile(r"^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$")

# Patterns redacted from log output. Keyword-tagged value patterns redact
# through end-of-line (not just the first \S+ token) — a log-sanitizer must
# fail safe by over-redacting rather than leaking trailing same-line content
# after a credential-like keyword.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*.+"),
    re.compile(r"(?i)(token|secret|password|passwd|credential)\s*[:=]\s*.+"),
    re.compile(r"(?i)bearer\s+.+"),
    re.compile(r"(?i)(authorization|cookie|set-cookie)\s*[:=]\s*.+"),
    re.compile(r"(?i)x-hackerone-researcher\s*[:=]\s*.+"),
    re.compile(r"(?i)(session[_-]?id|sid)\s*[:=]\s*.+"),
    re.compile(r"(?i)(https?://)[^/\s:@]+:[^@\s/]+@"),
]

_MAX_READ_BYTES = 50 * 1024 * 1024  # 50 MB


def escape_html(text: object) -> str:
    """Escape text for safe HTML embedding."""
    return html.escape(str(text), quote=True)


def sanitize_log_message(message: str) -> str:
    """Remove secrets and credentials from a log message."""
    sanitized = message
    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub(
            r"\1[REDACTED]@" if pattern.pattern.startswith("(?i)(https?://)") else "[REDACTED]",
            sanitized,
        )
    sanitized = re.sub(
        r"(-H\s+)(?:\"[^\"]*\"|'[^']*'|[^\s:]+:\s*[^\s]+)",
        r"\1[REDACTED_HEADER]",
        sanitized,
    )
    home = str(Path.home())
    if home and home != "/":
        # Case-insensitive (case-insensitive-but-preserving filesystems like
        # macOS APFS/Windows can surface a differently-cased representation
        # of the same path) with a path-boundary lookahead so an unrelated
        # directory that merely starts with the same prefix (e.g. a sibling
        # "~2" directory) isn't incorrectly matched.
        sanitized = re.sub(
            re.escape(home) + r"(?=$|[/\\])",
            "~",
            sanitized,
            flags=re.IGNORECASE,
        )
    return sanitized


def validate_run_id(run_id: str) -> str:
    """Validate a user-supplied run identifier.

    Args:
        run_id: Proposed run directory name.

    Returns:
        The validated run_id unchanged.

    Raises:
        ValidationError: If run_id contains unsafe characters.
    """
    run_id = run_id.strip()
    if not _RUN_ID_PATTERN.match(run_id):
        raise ValidationError(
            "Invalid run-id: use 1-64 alphanumeric characters, underscores, or hyphens only"
        )
    return run_id


def validate_safe_filename(name: str) -> str:
    """Validate a single path component filename.

    Raises:
        ValidationError: If the name is unsafe.
    """
    if not _SAFE_FILENAME.match(name):
        raise ValidationError(f"Unsafe filename: {name!r}")
    return name


def resolve_path(path: Path, *, must_exist: bool = False) -> Path:
    """Resolve a path, rejecting symlinks when checking existence.

    Args:
        path: Path to resolve.
        must_exist: Require the path to exist as a regular file or directory.

    Returns:
        Resolved absolute path.

    Raises:
        ValidationError: If path does not exist or is not accessible.
    """
    try:
        resolved = path.expanduser().resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise ValidationError(f"Path not found: {path}") from exc
    except OSError as exc:
        raise ValidationError(f"Cannot resolve path: {path}") from exc

    if must_exist and resolved.is_symlink():
        raise ValidationError(f"Symbolic links are not allowed: {path}")

    return resolved


def confine_path(path: Path, base_dir: Path, *, must_exist: bool = False) -> Path:
    """Resolve path and ensure it stays within base_dir (anti-traversal).

    Args:
        path: User-supplied path.
        base_dir: Trusted base directory.
        must_exist: Require path to exist.

    Returns:
        Confined resolved path.

    Raises:
        ValidationError: If path escapes base_dir.
    """
    base = resolve_path(base_dir)
    resolved = resolve_path(path, must_exist=must_exist)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValidationError(f"Path escapes allowed directory: {path}") from exc
    return resolved


def validate_readable_file(path: Path, base_dir: Path | None = None) -> Path:
    """Validate a user-readable input file.

    Args:
        path: File path to validate.
        base_dir: Optional directory the file must reside in.

    Returns:
        Validated resolved path.

    Raises:
        ValidationError: On traversal, missing file, or oversize file.
    """
    resolved = (
        confine_path(path, base_dir, must_exist=True)
        if base_dir
        else resolve_path(path, must_exist=True)
    )

    if not resolved.is_file():
        raise ValidationError(f"Not a regular file: {path}")

    size = resolved.stat().st_size
    if size > _MAX_READ_BYTES:
        raise ValidationError(
            f"File too large ({size} bytes). Maximum allowed: {_MAX_READ_BYTES} bytes"
        )

    return resolved


def validate_output_path(path: Path, base_dir: Path) -> Path:
    """Validate an output path stays within the run output directory.

    Args:
        path: Desired output file path.
        base_dir: Run output directory.

    Returns:
        Confined resolved path.

    Raises:
        ValidationError: If path escapes base_dir.
    """
    return confine_path(path, base_dir)


def relative_output_path(path: Path, output_dir: Path) -> str:
    """Return ``path`` relative to the run output directory (POSIX).

    Shareable artifacts (JSONL, HTML, summary) must never embed the analyst's
    home directory or absolute project path. Internal code that needs to open
    the file should join this string back onto ``context.output_dir``.
    """
    try:
        return path.resolve().relative_to(output_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def scrub_local_paths(text: str, output_dir: Path) -> str:
    """Strip home directory and run-output absolute prefixes from artifact text."""
    needles = []
    for candidate in (output_dir.resolve(), Path.home(), output_dir):
        value = str(candidate)
        if value and value not in {"/", "."}:
            needles.append(value)
    needles.sort(key=len, reverse=True)
    cleaned = text
    for needle in needles:
        cleaned = cleaned.replace(needle, "<run>")
    return cleaned


def resolve_raw_artifact(output_dir: Path, relative: str | None) -> Path | None:
    """Resolve a stored relative ``raw_artifact`` back to an absolute path."""
    if not relative:
        return None
    candidate = Path(relative)
    if candidate.is_absolute():
        # Legacy absolute values: keep confined to the run dir by name only.
        candidate = Path(candidate.name)
    return validate_output_path(output_dir / candidate, output_dir)


def validate_binary_path(path: Path) -> Path:
    """Validate an executable binary path.

    For bare names (no directory component), returns as-is for PATH lookup.
    For absolute/relative paths, resolves and verifies file exists and is executable.

    Args:
        path: Configured tool binary path.

    Returns:
        Validated path.

    Raises:
        ConfigurationError: If path is invalid or not executable.
    """
    if not path.name:
        raise ConfigurationError(f"Invalid binary path: {path}")

    # Bare command name — resolved via PATH at runtime
    if path.name == str(path) and os.sep not in str(path) and "/" not in str(path):
        return path

    try:
        resolved = resolve_path(path, must_exist=True)
    except ValidationError as exc:
        raise ConfigurationError(str(exc)) from exc

    if resolved.is_symlink():
        raise ConfigurationError(f"Symbolic link binaries are not allowed: {path}")

    if not resolved.is_file():
        raise ConfigurationError(f"Binary is not a regular file: {path}")

    if not os.access(resolved, os.X_OK):
        raise ConfigurationError(f"Binary is not executable: {path}")

    return resolved


def validate_env_file(path: Path, project_root: Path) -> Path:
    """Validate .env file path is a readable regular file within project.

    Args:
        path: Path to .env file.
        project_root: Project root directory.

    Returns:
        Validated path.

    Raises:
        ValidationError: If path is invalid.
    """
    resolved = confine_path(path, project_root, must_exist=True)
    if not resolved.is_file():
        raise ValidationError(f"Env file is not a regular file: {path}")
    return resolved


def validate_header_name(name: str) -> str:
    """Validate an HTTP header name.

    Raises:
        ConfigurationError: If header name is invalid.
    """
    name = name.strip()
    if not name or not _HEADER_NAME.match(name):
        raise ConfigurationError(f"Invalid HTTP header name: {name!r}")
    return name


def validate_header_value(value: str) -> str:
    """Validate an HTTP header value (no CRLF injection).

    Raises:
        ConfigurationError: If header value contains control characters.
    """
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ConfigurationError("HTTP header values must not contain control characters")
    if len(value) > 8192:
        raise ConfigurationError("HTTP header value exceeds maximum length (8192)")
    return value


def validate_log_level(level: str) -> str:
    """Validate logging level string.

    Raises:
        ConfigurationError: If level is unknown.
    """
    upper = level.upper()
    if upper not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigurationError(f"Invalid LOG_LEVEL: {level!r}")
    return upper


def validate_positive_int(
    value: int,
    name: str,
    *,
    minimum: int = 1,
    maximum: int = 10_000,
) -> int:
    """Validate a positive bounded integer configuration value.

    Raises:
        ConfigurationError: If out of range.
    """
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write text atomically via a temporary file in the same directory.

    Args:
        path: Destination file path.
        content: Text content to write.

    Side effects:
        Creates parent directories. Replaces destination atomically on success.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Collision-resistant temp name: path.with_suffix(suffix + ".tmp") can
    # collide with an unrelated real file (e.g. writing "x" uses temp name
    # "x.tmp", which may itself be another file's real, completed name —
    # silently destroying it on replace()). Embed pid + a random token instead.
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(content, encoding=encoding)
        tmp_path.chmod(0o600)
        tmp_path.replace(path)
    except OSError:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def backup_if_exists(path: Path) -> Path | None:
    """Create a .bak copy of an existing file before overwrite.

    Returns:
        Backup path if created, else None.
    """
    if not path.exists():
        return None
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    return backup
