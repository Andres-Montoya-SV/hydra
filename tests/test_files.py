"""Tests for file I/O utilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.exceptions import ValidationError
from utils.files import dedupe_file, read_lines, write_json, write_lines


class TestFileOperations:
    def test_write_and_read_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "lines.txt"
        count = write_lines(path, ["b.com", "a.com", "b.com"])
        assert count == 2
        assert read_lines(path) == ["b.com", "a.com"]

    def test_write_lines_confined(self, tmp_path: Path) -> None:
        base = tmp_path / "run"
        base.mkdir()
        path = base / "out.txt"
        write_lines(path, ["example.com"], base_dir=base)
        assert path.exists()

    def test_write_lines_rejects_escape(self, tmp_path: Path) -> None:
        base = tmp_path / "run"
        base.mkdir()
        with pytest.raises(ValidationError):
            write_lines(base / ".." / "escape.txt", ["x"], base_dir=base)

    def test_dedupe_file(self, tmp_path: Path) -> None:
        path = tmp_path / "dup.txt"
        path.write_text("a\na\nb\n", encoding="utf-8")
        _, count = dedupe_file(path)
        assert count == 2

    def test_write_json_atomic(self, tmp_path: Path) -> None:
        path = tmp_path / "data.json"
        write_json(path, {"key": "value"})
        assert path.read_text(encoding="utf-8").startswith("{")

    def test_read_lines_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.txt"
        path.write_text("", encoding="utf-8")
        assert read_lines(path) == []

    def test_read_lines_max_limit(self, tmp_path: Path) -> None:
        path = tmp_path / "many.txt"
        path.write_text("\n".join(f"line{i}" for i in range(5)) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="maximum line count"):
            read_lines(path, max_lines=3)
