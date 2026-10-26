"""Resolve local configuration files with tracked ``*.example.yaml`` fallbacks."""

from __future__ import annotations

from pathlib import Path


def resolve_config_file(path: str | Path, *, base: str | Path | None = None) -> Path:
    """Return the local config if present, else its ``*.example.yaml`` sibling.

    The working copy keeps user configuration (``config/dev.yaml`` etc.) out of
    git; a fresh clone only has ``config/dev.example.yaml``. Code can therefore
    use this helper everywhere it previously hard-coded the local path.
    """
    candidate = Path(path)
    if base is not None and not candidate.is_absolute():
        candidate = Path(base) / candidate
    candidate = candidate.resolve()
    if candidate.is_file():
        return candidate
    example = candidate.with_name(f"{candidate.stem}.example{candidate.suffix}")
    if example.is_file():
        return example.resolve()
    return candidate
