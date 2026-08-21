"""Input validation utilities."""

from __future__ import annotations

import re
from pathlib import Path

from core.exceptions import ValidationError
from core.models import DomainTarget
from utils.security import validate_readable_file, validate_run_id

# RFC 1123 compliant domain pattern (simplified)
_DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

# Block path traversal and shell metacharacters in domain input
_UNSAFE_CHARS = re.compile(r"""[`$;|&<>(){}\\'"]""")

_MAX_TARGETS = 500


def is_valid_domain(domain: str) -> bool:
    """Check whether a string is a valid domain name.

    Args:
        domain: Raw domain string.

    Returns:
        True if the domain passes validation rules.
    """
    domain = domain.strip().lower()
    if not domain or len(domain) > 253:
        return False
    if _UNSAFE_CHARS.search(domain):
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    if ".." in domain:
        return False
    return bool(_DOMAIN_PATTERN.match(domain))


def sanitize_domain(domain: str) -> str:
    """Validate and normalize a domain.

    Args:
        domain: Raw domain input.

    Returns:
        Lowercase normalized domain.

    Raises:
        ValidationError: If domain is invalid.
    """
    cleaned = domain.strip().lower().rstrip(".")
    if not is_valid_domain(cleaned):
        raise ValidationError(f"Invalid domain: {domain!r}")
    return cleaned


def load_targets(
    domain: str | None,
    targets_file: Path | None,
    *,
    project_root: Path | None = None,
) -> list[DomainTarget]:
    """Load and validate targets from CLI domain or file.

    Args:
        domain: Single domain from CLI.
        targets_file: Path to targets list file.
        project_root: Optional project root for path confinement.

    Returns:
        Deduplicated list of validated targets.

    Raises:
        ValidationError: On invalid input or too many targets.
    """
    targets: list[DomainTarget] = []

    if domain is not None:
        if not isinstance(domain, str) or not domain.strip():
            raise ValidationError("Domain must be a non-empty string")
        targets.append(DomainTarget(domain=sanitize_domain(domain), source="cli"))

    if targets_file is not None:
        if project_root is not None:
            validated_file = validate_readable_file(targets_file, project_root)
        else:
            validated_file = validate_readable_file(targets_file)

        for line_num, line in enumerate(
            validated_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                targets.append(
                    DomainTarget(domain=sanitize_domain(line), source=str(validated_file))
                )
            except ValidationError as exc:
                raise ValidationError(f"Line {line_num} in {validated_file.name}: {exc}") from exc

    if not targets:
        raise ValidationError("No valid targets provided. Specify a domain or targets file.")

    if len(targets) > _MAX_TARGETS:
        raise ValidationError(f"Too many targets ({len(targets)}). Maximum allowed: {_MAX_TARGETS}")

    seen: set[str] = set()
    unique: list[DomainTarget] = []
    for t in targets:
        if t.domain not in seen:
            seen.add(t.domain)
            unique.append(t)

    return unique


def sanitize_run_id(run_id: str | None) -> str | None:
    """Validate optional run identifier.

    Args:
        run_id: User-supplied run ID or None.

    Returns:
        Validated run_id or None.

    Raises:
        ValidationError: If run_id format is invalid.
    """
    if run_id is None:
        return None
    return validate_run_id(run_id)
