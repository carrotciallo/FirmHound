"""Local config files fall back to tracked ``*.example.yaml`` templates."""

from __future__ import annotations

from pathlib import Path

from fsa.utils.config_files import resolve_config_file


def test_prefers_local_config(tmp_path: Path) -> None:
    local = tmp_path / "dev.yaml"
    example = tmp_path / "dev.example.yaml"
    local.write_text("local: true\n", encoding="utf-8")
    example.write_text("example: true\n", encoding="utf-8")
    assert resolve_config_file(local) == local.resolve()


def test_falls_back_to_example(tmp_path: Path) -> None:
    local = tmp_path / "dev.yaml"
    example = tmp_path / "dev.example.yaml"
    example.write_text("example: true\n", encoding="utf-8")
    assert resolve_config_file(local) == example.resolve()


def test_returns_missing_path_when_no_example(tmp_path: Path) -> None:
    local = tmp_path / "missing.yaml"
    assert resolve_config_file(local) == local.resolve()
