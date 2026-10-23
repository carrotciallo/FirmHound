"""Host platform detection used by ``fsa doctor`` and install hints.

FirmHound supports any mainstream Linux distribution. Detection is best-effort:
it reads ``/etc/os-release`` and maps the distro to a package-manager family so
the CLI can print a hint that actually applies, instead of assuming Debian.
"""

from __future__ import annotations

import platform as _platform
import sys
from dataclasses import dataclass
from pathlib import Path

# family -> (human readable name, package manager, base install command)
_FAMILIES: dict[str, tuple[str, str, str]] = {
    "debian": (
        "Debian/Ubuntu",
        "apt",
        "sudo apt install -y binwalk squashfs-tools cpio p7zip-full binutils build-essential",
    ),
    "fedora": (
        "Fedora/RHEL",
        "dnf",
        "sudo dnf install -y binwalk squashfs-tools cpio p7zip p7zip-plugins binutils gcc make",
    ),
    "arch": (
        "Arch",
        "pacman",
        "sudo pacman -S --needed squashfs-tools cpio p7zip binutils base-devel",
    ),
    "suse": (
        "openSUSE",
        "zypper",
        "sudo zypper install -y squashfs cpio p7zip binutils gcc make",
    ),
    "alpine": (
        "Alpine",
        "apk",
        "sudo apk add squashfs-tools cpio p7zip binutils build-base",
    ),
    "unknown": ("Unknown Linux", "unknown", "install the tools listed in README.md"),
}

# distro ``ID`` -> family
_ID_MAP: dict[str, str] = {
    "debian": "debian",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "kali": "debian",
    "raspbian": "debian",
    "pop": "debian",
    "elementary": "debian",
    "devuan": "debian",
    "fedora": "fedora",
    "rhel": "fedora",
    "centos": "fedora",
    "rocky": "fedora",
    "almalinux": "fedora",
    "ol": "fedora",
    "arch": "arch",
    "manjaro": "arch",
    "endeavouros": "arch",
    "garuda": "arch",
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sles": "suse",
    "sled": "suse",
    "alpine": "alpine",
}

# distro ``ID_LIKE`` values -> family (checked when ``ID`` is not recognised)
_LIKE_MAP: dict[str, str] = {
    "debian": "debian",
    "ubuntu": "debian",
    "rhel": "fedora",
    "fedora": "fedora",
    "centos": "fedora",
    "arch": "arch",
    "suse": "suse",
    "opensuse": "suse",
    "alpine": "alpine",
}

# command -> {package manager: package spec}
_COMMAND_PACKAGES: dict[str, dict[str, str]] = {
    "binwalk": {
        "apt": "binwalk",
        "dnf": "binwalk",
        "pacman": "binwalk（AUR）",
        "zypper": "pipx install binwalk",
        "apk": "pipx install binwalk",
    },
    "unsquashfs": {
        "apt": "squashfs-tools",
        "dnf": "squashfs-tools",
        "pacman": "squashfs-tools",
        "zypper": "squashfs",
        "apk": "squashfs-tools",
    },
    "sasquatch": {
        "apt": "源码编译：https://github.com/onekey-sec/sasquatch",
        "dnf": "源码编译：https://github.com/onekey-sec/sasquatch",
        "pacman": "sasquatch（AUR）",
        "zypper": "源码编译：https://github.com/onekey-sec/sasquatch",
        "apk": "源码编译：https://github.com/onekey-sec/sasquatch",
    },
    "7z": {
        "apt": "p7zip-full",
        "dnf": "p7zip p7zip-plugins",
        "pacman": "p7zip",
        "zypper": "p7zip",
        "apk": "p7zip",
    },
    "readelf": {
        "apt": "binutils",
        "dnf": "binutils",
        "pacman": "binutils",
        "zypper": "binutils",
        "apk": "binutils",
    },
    "strings": {
        "apt": "binutils",
        "dnf": "binutils",
        "pacman": "binutils",
        "zypper": "binutils",
        "apk": "binutils",
    },
    "cpio": {
        "apt": "cpio",
        "dnf": "cpio",
        "pacman": "cpio",
        "zypper": "cpio",
        "apk": "cpio",
    },
    "make": {
        "apt": "build-essential",
        "dnf": "gcc make",
        "pacman": "base-devel",
        "zypper": "gcc make",
        "apk": "build-base",
    },
}


@dataclass(frozen=True)
class PlatformInfo:
    """Best-effort description of the host platform."""

    distro_id: str
    distro_name: str
    family: str
    package_manager: str
    libc: str
    install_hint: str
    supported: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "distro_id": self.distro_id,
            "distro_name": self.distro_name,
            "family": self.family,
            "package_manager": self.package_manager,
            "libc": self.libc,
            "install_hint": self.install_hint,
            "supported": self.supported,
        }


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Parse ``/etc/os-release`` into a dict; return empty on any failure."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def _resolve_family(distro_id: str, id_like: str) -> str:
    """Map a distro id / id_like string onto a package-manager family."""
    if distro_id in _ID_MAP:
        return _ID_MAP[distro_id]
    for token in id_like.replace(",", " ").split():
        if token in _LIKE_MAP:
            return _LIKE_MAP[token]
        if token in _ID_MAP:
            return _ID_MAP[token]
    # Fall back to substring matching for derivatives (e.g. "linuxmint-una").
    for key, family in _ID_MAP.items():
        if key in distro_id:
            return family
    return "unknown"


def detect() -> PlatformInfo:
    """Detect the host distribution, package manager and libc."""
    supported = sys.platform.startswith("linux")
    fields = _read_os_release() if supported else {}
    distro_id = (fields.get("ID") or "").lower()
    distro_name = fields.get("PRETTY_NAME") or fields.get("NAME") or distro_id or "Unknown"
    family = _resolve_family(distro_id, (fields.get("ID_LIKE") or "").lower())

    libc_name, _ = _platform.libc_ver()
    if not libc_name and family == "alpine":
        libc_name = "musl"
    libc = libc_name or "unknown"

    name, manager, hint = _FAMILIES[family]
    if family == "unknown" and distro_id:
        name = distro_name
    return PlatformInfo(
        distro_id=distro_id or "unknown",
        distro_name=distro_name,
        family=name,
        package_manager=manager,
        libc=libc,
        install_hint=hint,
        supported=supported,
    )


def hint_for(command: str) -> str | None:
    """Return an install hint for ``command`` on the current host, if known."""
    info = detect()
    packages = _COMMAND_PACKAGES.get(Path(command).name)
    if not packages:
        return None
    spec = packages.get(info.package_manager)
    if not spec:
        return None
    if info.package_manager == "unknown":
        return spec
    return f"{info.package_manager}: {spec}"
