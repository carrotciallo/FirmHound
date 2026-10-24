"""Firmware unpackability diagnosis for competition demos and triage."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from fsa.utils.hashing import sha256_file
from tools.firmware.collect_info import _binwalk_signatures
from tools.firmware.unpack import (
    CARVE_TARGETS,
    OPENSSL_SALTED_MAGIC,
    _check_extractors,
    _detect_strategy,
    _encrypted_signatures,
    _iter_magic_offsets,
)


def _sample_magic_hits(path: Path) -> list[dict[str, Any]]:
    """Return bounded magic hits used by the unpack fallback."""
    data = path.read_bytes()
    hits: list[dict[str, Any]] = []
    for target in CARVE_TARGETS:
        offsets = _iter_magic_offsets(data, target["magic"], max_hits=target["max_hits"])
        for offset in offsets:
            hits.append(
                {
                    "kind": target["kind"],
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "magic": target["magic"].hex(),
                }
            )
    salted = data.find(OPENSSL_SALTED_MAGIC)
    if salted >= 0 and not any(hit["offset"] == salted for hit in hits):
        hits.append(
            {
                "kind": "openssl-salted",
                "offset": salted,
                "offset_hex": hex(salted),
                "magic": OPENSSL_SALTED_MAGIC.hex(),
            }
        )
    hits.sort(key=lambda item: int(item["offset"]))
    return hits


def _recommendations(
    *,
    strategy: dict[str, Any] | None,
    encrypted: list[dict[str, Any]],
    extractors: dict[str, bool],
    magic_hits: list[dict[str, Any]],
) -> list[str]:
    """Generate plain-language next steps without pretending to decrypt firmware."""
    recs: list[str] = []
    if encrypted or any(hit["kind"] == "openssl-salted" for hit in magic_hits):
        recs.append(
            "OpenSSL Salted / encrypted payload detected: the vendor password or key, "
            "an upgraded decryption routine, or an already decrypted image is required."
        )
        recs.append(
            "Keep the encrypted slice for reverse engineering. Do not record a "
            "decryption-blocked sample as 'no vulnerabilities' or 'unpacked'."
        )
    if strategy:
        missing = [
            tool[0]
            for tool in strategy.get("tools", [])
            if tool[0] not in {"dd", "gzip"} and not extractors.get(tool[0], False)
        ]
        if missing:
            missing_tools = ", ".join(sorted(set(missing)))
            recs.append(
                f"Matched the {strategy['name']} strategy but the extractors are missing: "
                f"{missing_tools}."
            )
        else:
            recs.append(
                f"Matched the {strategy['name']} strategy and every extractor is available; "
                "a real unpack can be attempted."
            )
    elif magic_hits:
        kinds = ", ".join(sorted({str(hit["kind"]) for hit in magic_hits}))
        recs.append(
            f"No strategy matched binwalk signatures directly, "
            f"but carveable magic was found: {kinds}."
        )
    else:
        recs.append(
            "No filesystem magic was found. Check for a vendor header, an extra "
            "compression layer, or a differential/signed upgrade package."
        )
    if any(hit["kind"] == "squashfs" for hit in magic_hits) and not extractors.get("sasquatch"):
        recs.append(
            "SquashFS signatures are present but sasquatch is not installed; "
            "vendor-patched SquashFS images usually need it."
        )
    return recs


def diagnose_firmware(path: str | Path) -> dict[str, Any]:
    """Diagnose how likely a firmware image can be unpacked in this environment."""
    firmware = Path(path).resolve()
    if not firmware.is_file():
        raise FileNotFoundError(f"Firmware not found: {firmware}")

    signatures = _binwalk_signatures(firmware)
    strategy = _detect_strategy(signatures)
    encrypted = _encrypted_signatures(signatures)
    extractors = _check_extractors()
    magic_hits = _sample_magic_hits(firmware)
    strategy_tools = strategy.get("tools", []) if strategy else []
    tool_ready = [
        tool[0] in {"dd", "gzip"} or shutil.which(tool[0]) is not None for tool in strategy_tools
    ]
    if encrypted or any(hit["kind"] == "openssl-salted" for hit in magic_hits):
        status = "blocked_needs_decryption"
        confidence = 0.2
    elif strategy and any(tool_ready):
        status = "likely_unpackable"
        confidence = 0.85
    elif any(hit["kind"] in {"squashfs", "ubi"} for hit in magic_hits):
        status = "carving_possible"
        confidence = 0.65
    else:
        status = "unknown"
        confidence = 0.3

    return {
        "status": status,
        "firmware": str(firmware),
        "size_bytes": firmware.stat().st_size,
        "sha256": sha256_file(firmware),
        "binwalk_available": bool(shutil.which("binwalk")),
        "signature_count": len(signatures),
        "signatures": signatures[:50],
        "selected_strategy": strategy["name"] if strategy else None,
        "extractors": extractors,
        "magic_hits": magic_hits[:80],
        "encrypted_indicators": encrypted,
        "confidence": confidence,
        "recommendations": _recommendations(
            strategy=strategy,
            encrypted=encrypted,
            extractors=extractors,
            magic_hits=magic_hits,
        ),
    }
