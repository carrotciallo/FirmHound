"""Integration tests for the M2 unpacking pipeline.

These tests require a Linux toolchain (file/strings/binwalk/unsquashfs/readelf)
and skip automatically when it is missing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from tools.firmware.build_manifest import build_manifest


def _has_docker() -> bool:
    return shutil.which("docker") is not None


def _docker_available() -> bool:
    if not _has_docker():
        return False
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, check=False, timeout=5
        )
        return result.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _linux_tool_available() -> bool:
    return all(
        shutil.which(tool)
        for tool in ["file", "binwalk", "unsquashfs", "readelf", "mksquashfs"]
    )


@pytest.fixture
def linux_ready() -> bool:
    """Return True if the pipeline can run on the host or via Docker."""
    return _linux_tool_available() or _docker_available()


def _build_squashfs_fixture(tmp_path: Path) -> Path:
    """Build a tiny but plausible SquashFS fixture using the host toolchain."""
    fixture_dir = tmp_path / "rootfs"
    fixture_dir.mkdir()
    (fixture_dir / "bin").mkdir()
    (fixture_dir / "sbin").mkdir()
    (fixture_dir / "lib").mkdir()
    (fixture_dir / "usr" / "bin").mkdir(parents=True)
    (fixture_dir / "www").mkdir()
    (fixture_dir / "etc" / "init.d").mkdir(parents=True)
    (fixture_dir / "bin" / "busybox").write_text("busybox", encoding="utf-8")
    (fixture_dir / "etc" / "init.d" / "rcS").write_text("#!/bin/sh\n", encoding="utf-8")
    (fixture_dir / "etc" / "passwd").write_text("root:x:0:0:root:/:/bin/sh\n", encoding="utf-8")

    image_path = tmp_path / "fixture.squashfs"
    mksquashfs = shutil.which("mksquashfs") or "mksquashfs"
    subprocess.run(
        [mksquashfs, str(fixture_dir), str(image_path), "-noappend", "-quiet"],
        check=True,
        timeout=120,
        text=True,
        errors="replace",
    )
    return image_path


@pytest.mark.skipif(not _linux_tool_available(), reason="Linux extraction tools not available")
def test_manifest_from_squashfs_fixture(tmp_path: Path) -> None:
    """A real SquashFS fixture produces a valid firmware_manifest.json."""
    fw = _build_squashfs_fixture(tmp_path)
    run_root = tmp_path / "runs"
    manifest = build_manifest(fw, "run-fixture-001", run_root)
    assert manifest["status"] in {"success", "partial"}
    assert manifest["rootfs_path"] is not None
    assert manifest["extraction_confidence"] >= 0.7
    assert Path(run_root / "run-fixture-001" / "firmware_manifest.json").exists()


@pytest.mark.skipif(not _linux_tool_available(), reason="Linux extraction tools not available")
def test_carve_fallback_on_host(tmp_path: Path) -> None:
    """A vendor header in front of a real SquashFS image is handled by carving."""
    inner = _build_squashfs_fixture(tmp_path)
    fw = tmp_path / "wrapped.bin"
    fw.write_bytes(b"HEADER" * 8 + inner.read_bytes())

    manifest = build_manifest(fw, "run-carve-001", tmp_path / "runs")

    assert manifest["status"] in {"success", "partial"}
    assert manifest["rootfs_path"] is not None
    assert Path(manifest["rootfs_path"]).is_dir()
