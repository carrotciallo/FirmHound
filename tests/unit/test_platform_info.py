"""Tests for host platform detection and per-distro install hints."""

from __future__ import annotations

import pytest

from fsa.utils import platform_info


def _release(monkeypatch: pytest.MonkeyPatch, fields: dict[str, str]) -> None:
    monkeypatch.setattr(platform_info, "_read_os_release", lambda *a, **k: fields)


@pytest.mark.parametrize(
    ("fields", "family", "manager"),
    [
        ({"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04"}, "Debian/Ubuntu", "apt"),
        ({"ID": "debian", "PRETTY_NAME": "Debian 12"}, "Debian/Ubuntu", "apt"),
        ({"ID": "linuxmint"}, "Debian/Ubuntu", "apt"),
        ({"ID": "fedora"}, "Fedora/RHEL", "dnf"),
        ({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "Fedora/RHEL", "dnf"),
        ({"ID": "arch"}, "Arch", "pacman"),
        ({"ID": "manjaro", "ID_LIKE": "arch"}, "Arch", "pacman"),
        ({"ID": "opensuse-tumbleweed"}, "openSUSE", "zypper"),
        ({"ID": "alpine"}, "Alpine", "apk"),
    ],
)
def test_family_mapping(
    monkeypatch: pytest.MonkeyPatch, fields: dict[str, str], family: str, manager: str
) -> None:
    _release(monkeypatch, fields)
    info = platform_info.detect()
    assert info.family == family
    assert info.package_manager == manager
    assert info.install_hint


def test_unknown_distro_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    _release(monkeypatch, {"ID": "somevendor", "PRETTY_NAME": "SomeVendor Linux"})
    info = platform_info.detect()
    assert info.package_manager == "unknown"
    assert info.distro_name == "SomeVendor Linux"
    assert "README" in info.install_hint


def test_os_release_parser(tmp_path) -> None:
    release = tmp_path / "os-release"
    release.write_text(
        'ID=ubuntu\nID_LIKE="debian"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n', encoding="utf-8"
    )
    fields = platform_info._read_os_release(release)
    assert fields["ID"] == "ubuntu"
    assert fields["ID_LIKE"] == "debian"
    assert fields["PRETTY_NAME"] == "Ubuntu 22.04 LTS"


def test_os_release_missing_returns_empty(tmp_path) -> None:
    assert platform_info._read_os_release(tmp_path / "nope") == {}


@pytest.mark.parametrize(
    ("distro", "command", "expected"),
    [
        ({"ID": "ubuntu"}, "unsquashfs", "squashfs-tools"),
        ({"ID": "opensuse-leap"}, "unsquashfs", "squashfs"),
        ({"ID": "alpine"}, "unsquashfs", "squashfs-tools"),
        ({"ID": "fedora"}, "7z", "p7zip p7zip-plugins"),
        ({"ID": "arch"}, "binwalk", "AUR"),
    ],
)
def test_install_hints_follow_distro(
    monkeypatch: pytest.MonkeyPatch, distro: dict[str, str], command: str, expected: str
) -> None:
    _release(monkeypatch, distro)
    hint = platform_info.hint_for(command)
    assert hint is not None
    assert expected in hint


def test_install_hint_for_unknown_command(monkeypatch: pytest.MonkeyPatch) -> None:
    _release(monkeypatch, {"ID": "ubuntu"})
    assert platform_info.hint_for("definitely-not-a-tool") is None
