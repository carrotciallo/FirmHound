"""Stage inputs for upstream FirmRec (native and Docker backends).

Upstream FirmRec does **not** read the synthetic ``vulns.json`` this project
used to write. Its ``INPUT.md`` contract is::

    inout/
    ├── firmware/images/<VENDOR>/<IMAGE>
    ├── vuln_info/<VENDOR>/<NAME>/{meta.json, <vulnerable firmware>}
    └── experiment.json  {"name": ..., "vulns": [...], "images": [...]}

This module owns that staging step so ``runner.py`` stays focused on process
control. Every reader is tolerant: a CVE fixture without a vulnerable firmware
image or input descriptor is skipped and recorded as a limitation instead of
being turned into a fabricated signature.
"""

from __future__ import annotations

import json
import re
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tools.external.base import AnalysisContext
from tools.external.firmrec.vuln_info import cve_dir_to_vuln_info

_SAFE_RE = re.compile(r"[^A-Za-z0-9_-]+")
_FIRMWARE_SUFFIXES = {
    ".bin",
    ".img",
    ".chk",
    ".trx",
    ".fw",
    ".zip",
    ".tar",
    ".gz",
    ".xz",
    ".tgz",
}


@dataclass
class StagedFirmware:
    """A firmware image staged in the upstream ``images/<VENDOR>/`` layout."""

    vendor: str
    image_name: str
    image_ref: str  # "<VENDOR>/<IMAGE>"
    limitations: list[str] = field(default_factory=list)


@dataclass
class StagedVulnInfo:
    """Vulnerability signatures staged in the upstream ``vuln_info`` layout."""

    vuln_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def safe_name(value: str, fallback: str = "unknown") -> str:
    """Return an upstream-safe path segment: letters, digits, ``-`` and ``_``."""
    cleaned = _SAFE_RE.sub("-", str(value or "")).strip("-_")
    return cleaned or fallback


def _unique_cve(root: Path) -> str:
    return safe_name(root.name.upper(), "vuln")


def _first_firmware(directory: Path) -> Path | None:
    if not directory.is_dir():
        return None
    candidates = sorted(
        p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in _FIRMWARE_SUFFIXES
    )
    return candidates[0] if candidates else None


def _find_vuln_image(cve_dir: Path, vuln_firmware_dir: str | Path | None) -> Path | None:
    image = _first_firmware(Path(vuln_firmware_dir) / cve_dir.name) if vuln_firmware_dir else None
    if image is None:
        image = _first_firmware(cve_dir / "firmware")
    return image


def _input_spec(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Extract an upstream ``input`` object from a CVE fixture, if present.

    Accepted shapes: ``metadata.input``, ``poc.input``, or ``input``. The value
    must already be ``{"kv": {...}}`` or ``{"raw": [...]}``; this function never
    invents a payload.
    """
    metadata = candidate.get("metadata") or {}
    for container in (metadata, candidate.get("poc") or {}, candidate):
        spec = container.get("input") if isinstance(container, dict) else None
        if isinstance(spec, dict) and (isinstance(spec.get("kv"), dict) or spec.get("raw")):
            return spec
    return None


def stage_firmware(
    ctx: AnalysisContext,
    *,
    vendor: str = "unknown",
    image_name: str = "",
    allow_rootfs_tar: bool = True,
) -> StagedFirmware:
    """Stage the target firmware image in the upstream ``images/<VENDOR>/`` tree.

    Prefers the original firmware file from the task card. When the run only has
    an extracted rootfs, it packs that rootfs into a tar (upstream's extractor is
    magic-based) and records the approximation as a limitation.
    """
    inout = ctx.workdir / "inout"
    vendor = safe_name(vendor or "unknown", "unknown")
    images_dir = inout / "firmware" / "images" / vendor
    images_dir.mkdir(parents=True, exist_ok=True)

    limitations: list[str] = []
    raw = Path(ctx.firmware_path) if ctx.firmware_path else None
    if raw and raw.is_file():
        name = safe_name(image_name or raw.name, "firmware")
        target = images_dir / name
        shutil.copy2(raw, target)
        return StagedFirmware(vendor, name, f"{vendor}/{name}")

    if not allow_rootfs_tar:
        raise ValueError(
            "no raw firmware image is available; set allow_rootfs_tar=true or "
            "run with an original firmware image"
        )

    name = safe_name(image_name or ctx.rootfs_dir.name, "rootfs") + "-rootfs-tar"
    target = images_dir / name
    with tarfile.open(target, "w") as archive:
        archive.add(ctx.rootfs_dir, arcname=".")
    limitations.append(
        "no raw firmware image; packed rootfs into a tar for FirmRec "
        "(approximate input, not a vendor image)"
    )
    return StagedFirmware(vendor, name, f"{vendor}/{name}", limitations)


def collect_vuln_refs(vuln_info_dir: Path) -> list[str]:
    """Return ``<VENDOR>/<NAME>`` for every ``meta.json`` under ``vuln_info_dir``."""
    refs: list[str] = []
    if not vuln_info_dir.is_dir():
        return refs
    for meta in sorted(vuln_info_dir.glob("*/*/meta.json")):
        refs.append(f"{meta.parent.parent.name}/{meta.parent.name}")
    return refs


def _copy_vuln_tree(source: Path, out_dir: Path) -> list[str]:
    if not source.is_dir():
        raise ValueError(f"FirmRec vuln_info path must be a directory: {source}")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(source, out_dir)
    refs = collect_vuln_refs(out_dir)
    if not refs:
        raise ValueError(f"FirmRec vuln_info directory has no <VENDOR>/<NAME>/meta.json: {source}")
    return refs


def stage_upstream_vuln_info(
    workdir: Path,
    *,
    source: str = "our",
    official_dir: str | Path | None = None,
    vuln_info_dir: str | Path | None = None,
    cve_root: str | Path | None = None,
    vuln_firmware_dir: str | Path | None = None,
) -> StagedVulnInfo:
    """Stage upstream-compatible ``vuln_info`` signatures.

    Order of preference: an operator-prepared ``vuln_info_dir`` tree, then
    ``source=official`` (an upstream directory), then ``source=our`` fixture
    conversion. The ``our`` path intentionally skips CVEs that lack a vulnerable
    firmware image and a real input descriptor.
    """
    inout = workdir / "inout"
    out_dir = inout / "vuln_info"
    limitations: list[str] = []

    if vuln_info_dir:
        return StagedVulnInfo(_copy_vuln_tree(Path(vuln_info_dir), out_dir))

    if source == "official":
        if not official_dir:
            raise ValueError("official FirmRec vuln_info path is not configured")
        path = Path(official_dir)
        if path.is_file():
            raise ValueError(
                "official FirmRec vuln_info must be an upstream directory tree "
                "(<VENDOR>/<NAME>/meta.json + vulnerable firmware), not a JSON list"
            )
        return StagedVulnInfo(_copy_vuln_tree(path, out_dir))

    if source != "our":
        raise ValueError(f"unsupported FirmRec vuln_info source: {source}")

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    root = Path(cve_root) if cve_root else None
    if root is None or not root.is_dir():
        limitations.append(f"our-mode signature database is missing: {cve_root}")
        return StagedVulnInfo([], limitations)

    refs: list[str] = []
    for cve_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        candidate = _read_candidate(cve_dir)
        record = cve_dir_to_vuln_info(cve_dir)
        if not candidate or not record:
            limitations.append(f"{cve_dir.name}: no candidate.json; skipped")
            continue
        spec = _input_spec(candidate)
        if spec is None:
            limitations.append(
                f"{cve_dir.name}: no input descriptor (metadata.input/poc.input); skipped"
            )
            continue

        image = _find_vuln_image(cve_dir, vuln_firmware_dir)
        if image is None:
            limitations.append(
                f"{cve_dir.name}: no vulnerable firmware image "
                "(set vuln_firmware_dir/<CVE>/ or <CVE>/firmware/); skipped"
            )
            continue

        vendor = safe_name(str(record.get("device") or "unknown"), "unknown")
        name = _unique_cve(cve_dir)
        target_dir = out_dir / vendor / name
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(image, target_dir / safe_name(image.name, "firmware"))
        meta = {
            "firmware_filename": safe_name(image.name, "firmware"),
            "input": spec,
            "presumed": True,
            "cve_id": record.get("cve_id", ""),
        }
        (target_dir / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        refs.append(f"{vendor}/{name}")

    if not refs:
        limitations.append(
            "our-mode fixtures produced no upstream vuln_info entries; use "
            "vuln_info_dir/official with real vulnerable firmware images"
        )
    return StagedVulnInfo(refs, limitations)


def our_mode_ready(cve_root: str | Path | None, vuln_firmware_dir: str | Path | None) -> bool:
    """Return True when at least one CVE fixture has a firmware image + input spec."""
    root = Path(cve_root) if cve_root else None
    if root is None or not root.is_dir():
        return False
    for cve_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        candidate = _read_candidate(cve_dir)
        if not candidate or _input_spec(candidate) is None:
            continue
        image = _find_vuln_image(cve_dir, vuln_firmware_dir)
        if image is not None:
            return True
    return False


def _read_candidate(cve_dir: Path) -> dict[str, Any] | None:
    try:
        data = json.loads((cve_dir / "candidate.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def write_experiment(
    workdir: Path,
    *,
    run_id: str,
    vuln_refs: list[str],
    image_ref: str,
) -> Path:
    """Write upstream ``inout/experiment.json`` (``name``/``vulns``/``images``)."""
    path = workdir / "inout" / "experiment.json"
    payload = {
        "name": run_id,
        "vulns": list(vuln_refs),
        "images": [image_ref],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_local_config(
    workdir: Path,
    *,
    repo_dir: Path,
    inout: Path,
    db_name: str,
    db_user: str,
    db_password: str,
    firmrec_static_jar: Path,
    ghidra_headless: Path,
    llm_key: str = "",
    llm_url: str = "",
    llm_model: str = "",
) -> Path:
    """Write the per-run config consumed by :mod:`native_wrapper`.

    The YAML mirror is the flat ``gconfig`` mapping (upstream helper scripts may
    read ``ConstPaths.CONFIG_PATH`` directly). The JSON payload wraps it together
    with ``repo_dir`` for the wrapper. Both files contain the PostgreSQL password
    / optional LLM key, so they are mode ``0600``.
    """
    yaml_path = workdir / "config.local.yaml"
    gconfig = {
        "config_path": str(yaml_path),
        "poc_info_dir": str(inout / "poc_info"),
        "vuln_info_dir": str(inout / "vuln_info"),
        "firmware_dir": str(inout / "firmware"),
        "firmrec_output_dir": str(inout),
        "project_path": str(inout / "ghidra"),
        "emu_result_dir": str(inout / "emu_results"),
        "firmrec_static_jar": str(firmrec_static_jar),
        "ghidra_headless_path": str(ghidra_headless),
        "db_name": db_name,
        "db_user": db_user,
        "db_user_passwd": db_password,
        "llm_key": llm_key,
        "llm_url": llm_url,
        "llm_model": llm_model,
    }
    yaml_path.write_text(
        yaml.safe_dump(gconfig, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    yaml_path.chmod(0o600)
    payload = {
        "repo_dir": str(repo_dir),
        "gconfig": gconfig,
        "upstream_config_path": str(yaml_path),
    }
    path = workdir / "config.local.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    path.chmod(0o600)
    return path


__all__ = [
    "StagedFirmware",
    "StagedVulnInfo",
    "collect_vuln_refs",
    "our_mode_ready",
    "safe_name",
    "stage_firmware",
    "stage_upstream_vuln_info",
    "write_experiment",
    "write_local_config",
]
