"""Tests for domain and path validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.exceptions import ValidationError
from utils.validators import is_valid_domain, load_targets, sanitize_domain, sanitize_run_id


class TestDomainValidation:
    def test_valid_domain(self) -> None:
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.co.uk")

    def test_rejects_shell_metacharacters(self) -> None:
        assert not is_valid_domain("example.com; rm -rf /")
        assert not is_valid_domain("$(whoami).evil.com")

    def test_rejects_traversal_patterns(self) -> None:
        assert not is_valid_domain("..evil.com")
        assert not is_valid_domain("")

    def test_rejects_oversized_domain(self) -> None:
        assert not is_valid_domain("a" * 254 + ".com")

    def test_sanitize_domain_normalizes(self) -> None:
        assert sanitize_domain(" Example.COM. ") == "example.com"

    def test_sanitize_domain_raises_on_invalid(self) -> None:
        with pytest.raises(ValidationError):
            sanitize_domain("not a domain!")


class TestLoadTargets:
    def test_load_single_domain(self) -> None:
        targets = load_targets("example.com", None)
        assert len(targets) == 1
        assert targets[0].domain == "example.com"

    def test_load_from_file(self, project_root: Path, targets_file: Path) -> None:
        targets = load_targets(None, targets_file, project_root=project_root)
        assert len(targets) == 2

    def test_skips_comments_and_blanks(self, project_root: Path) -> None:
        path = project_root / "t.txt"
        path.write_text("# comment\n\nexample.com\n", encoding="utf-8")
        targets = load_targets(None, path, project_root=project_root)
        assert len(targets) == 1

    def test_rejects_no_targets(self) -> None:
        with pytest.raises(ValidationError):
            load_targets(None, None)

    def test_rejects_path_outside_project(self, project_root: Path) -> None:
        outside = project_root.parent / "outside_targets.txt"
        outside.write_text("example.com\n", encoding="utf-8")
        try:
            with pytest.raises(ValidationError):
                load_targets(None, outside, project_root=project_root)
        finally:
            outside.unlink(missing_ok=True)

    def test_deduplicates_targets(self, project_root: Path) -> None:
        path = project_root / "dup.txt"
        path.write_text("example.com\nexample.com\n", encoding="utf-8")
        targets = load_targets(None, path, project_root=project_root)
        assert len(targets) == 1


class TestRunIdValidation:
    def test_valid_run_id(self) -> None:
        assert sanitize_run_id("run_2025_v1") == "run_2025_v1"

    def test_rejects_traversal(self) -> None:
        with pytest.raises(ValidationError):
            sanitize_run_id("../etc/passwd")

    def test_none_allowed(self) -> None:
        assert sanitize_run_id(None) is None
