"""Parse FirmRec raw output into normalized ``external_finding`` documents.

FirmRec (CCS'24, seclab-fudan/FirmRec) emits three kinds of artifact that we
normalize:

  * ``VULNS.md`` -- the human-readable detection report (CVE id + firmware +
    binary + function + addr + similarity). This is the highest-value artifact.
  * PostgreSQL table dump (we export it as CSV via ``COPY ... TO STDOUT`` inside
    the container, redirected to ``tmp/external/firmrec/<run_id>/``) -- the
    detailed match rows (binary / addr / signature similarity / matched CVE).
  * ``poc_info/`` -- PoC payloads. **Every PoC MUST pass the sanitizer
    (``tools.external.firmrec.sanitize``) before the finding is persisted**;
    an unsafe PoC drops the finding (firmrec.md §7.4).

Parsing strategy (mirrors the SaTC parser): every reader is tolerant and never
raises. A malformed line / file degrades to fewer findings and a ``limitation``,
never to a failed stage. ``PARSER_VERSION`` is stamped on every finding.

A finding carrying ``matched_cve`` is a *recurring* detection: it is kept out of
the blind-benchmark delta by ``tools/analysis/finding_fusion`` (which sets
``blind_isolated``). This module only produces the raw normalized documents; the
isolation bookkeeping lives in the fusion layer.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.external.base import normalize_addr, normalize_binary_id
from tools.external.firmrec.sanitize import sanitize_poc

PARSER_VERSION = "firmrec-parser-v1"
RESULT_PARSER_VERSION = "firmrec-result-parser-v1"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,6}", re.I)
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
_KV_RE = re.compile(r"[:=]\s*|\t+|\s{2,}")
_SIMILARITY_RE = re.compile(r"(?:similarity|score|conf)\D{0,12}(0?\.\d+|\d(?:\.\d+)?)")


@dataclass
class ParseStats:
    """Counters describing what the parser managed to interpret."""

    files_seen: list[str] = field(default_factory=list)
    unparsed_lines: int = 0
    dropped_unsafe: int = 0
    limitations: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)


# --------------------------------------------------------------------------- #
# low-level readers (tolerant, never raise)
# --------------------------------------------------------------------------- #


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _split_kv(line: str) -> tuple[str, str]:
    parts = [p.strip() for p in _KV_RE.split(line, maxsplit=1) if p.strip()]
    if len(parts) < 2:
        return parts[0] if parts else "", ""
    return parts[0], parts[1]


def parse_vulns_md(path: Path, stats: ParseStats | None = None) -> list[dict[str, Any]]:
    """Parse ``VULNS.md`` into raw detection dicts.

    Tolerant grammar: a detection block is introduced by a ``[CVE-xxxx]`` or
    ``CVE-xxxx`` marker, followed by ``key: value`` lines (binary / function /
    addr / similarity / vuln_class / source). Blocks are merged so a missing
    field falls back to empty rather than dropping the whole detection.
    """
    text = _read_text(path)
    if stats:
        stats.files_seen.append(path.name)
    detections: list[dict[str, Any]] = []
    if not text.strip():
        return detections

    current: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            # A CVE marker starts a new block; flush the previous one.
            if _CVE_RE.search(line):
                if current:
                    detections.append(current)
                current = {"cve_id": _CVE_RE.search(line).group(0).upper()}
            continue
        m = _CVE_RE.search(line)
        if m and not current:
            current = {"cve_id": m.group(0).upper()}
            continue
        if _CVE_RE.search(line) and current:
            detections.append(current)
            current = {"cve_id": m.group(0).upper()}
            continue
        # Only a line with a real delimiter is a key:value pair. Prose / note
        # lines (e.g. "No recurring vulnerabilities detected for this firmware.")
        # have no delimiter and must be skipped, not parsed as a bogus field.
        if not re.search(r"[:=]|\t| {2,}", line):
            continue
        key, value = _split_kv(line)
        if not key:
            if stats:
                stats.unparsed_lines += 1
            continue
        kl = key.lower()
        if "binary" in kl:
            current["binary"] = value
        elif "function" in kl or "sink" in kl:
            current["function"] = value
        elif "addr" in kl:
            current["addr"] = value
        elif "similar" in kl or "score" in kl or "conf" in kl:
            current["similarity"] = value
        elif "class" in kl or "type" in kl:
            current["vuln_class"] = value
        elif "source" in kl or "entry" in kl or "param" in kl:
            current["source"] = value
        elif "firmware" in kl or "device" in kl:
            current["device"] = value
    if current:
        detections.append(current)
    return detections


def parse_pg_csv(path: Path, stats: ParseStats | None = None) -> list[dict[str, Any]]:
    """Parse a PostgreSQL ``COPY ... TO STDOUT WITH CSV HEADER`` dump.

    Expected columns (any order): binary, addr, function, vuln_class,
    similarity, matched_cve, source. Rows with the wrong arity or an unparsable
    address are skipped and counted -- a malformed dump must not abort parsing.
    """
    text = _read_text(path)
    if stats:
        stats.files_seen.append(path.name)
    if not text.strip():
        return []
    detections: list[dict[str, Any]] = []
    try:
        reader = csv.DictReader(text.splitlines())
    except Exception:
        if stats:
            stats.unparsed_lines += 1
        return detections

    expected = {"binary", "addr", "function", "vuln_class", "similarity", "matched_cve", "source"}
    for row in reader:
        if row is None:
            continue
        # Tolerate header drift: if no recognized column is present, skip.
        if not (set(row.keys()) & expected):
            if stats:
                stats.unparsed_lines += 1
            continue
        addr_raw = (row.get("addr") or "").strip()
        # A non-empty address that is not a valid hex literal is a malformed row
        # (FirmRec addrs are always hex); skip it and record the limitation.
        if addr_raw and not _ADDR_RE.fullmatch(addr_raw):
            if stats:
                stats.unparsed_lines += 1
                stats.note(f"pg row dropped: unparsable addr {addr_raw!r}")
            continue
        detections.append(
            {
                "binary": (row.get("binary") or "").strip(),
                "addr": (row.get("addr") or "").strip(),
                "function": (row.get("function") or "").strip(),
                "vuln_class": (row.get("vuln_class") or "").strip(),
                "similarity": (row.get("similarity") or "").strip(),
                "cve_id": (row.get("matched_cve") or "").strip(),
                "source": (row.get("source") or "").strip(),
            }
        )
    return detections


def parse_poc_info(poc_dir: Path, stats: ParseStats | None = None) -> list[dict[str, Any]]:
    """Parse ``poc_info/`` entries (``.json`` / ``.txt``).

    Each entry yields a raw detection carrying a ``payload``. The payload is run
    through :func:`sanitize_poc`; an unsafe payload drops the detection (and is
    counted in ``stats.dropped_unsafe``) -- it is never persisted.
    """
    poc_dir = Path(poc_dir)
    if not poc_dir.exists():
        return []
    if stats:
        stats.files_seen.append(poc_dir.name)
    detections: list[dict[str, Any]] = []
    for f in sorted(poc_dir.iterdir()):
        if not f.is_file():
            continue
        payload = ""
        meta: dict[str, Any] = {}
        if f.suffix.lower() == ".json":
            try:
                meta = _loads_json(f)
            except Exception:
                meta = {}
            payload = str(meta.get("payload", ""))
        else:
            payload = _read_text(f).strip()
        sanitized, ok = sanitize_poc(payload)
        if not ok:
            if stats:
                stats.dropped_unsafe += 1
                stats.note(
                    f"poc_info/{f.name}: unsafe payload rejected by sanitizer; finding dropped"
                )
            continue
        det = {
            "binary": str(meta.get("binary", "")).strip(),
            "addr": str(meta.get("addr", "")).strip(),
            "function": str(meta.get("function", "")).strip(),
            "vuln_class": str(meta.get("vuln_class", "")).strip(),
            "cve_id": str(meta.get("cve", meta.get("cve_id", ""))).strip(),
            "similarity": str(meta.get("similarity", "")).strip(),
            "source": str(meta.get("source", "")).strip(),
            "poc_sanitized": True,
            "payload": sanitized,
        }
        detections.append(det)
    return detections


def _loads_json(path: Path) -> dict[str, Any]:
    """Read a JSON file as a dict (helper for poc_info parsing)."""
    import json

    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# confidence + normalization helpers
# --------------------------------------------------------------------------- #


def compute_confidence(similarity: str | float | None = None, *, has_entry: bool = False) -> float:
    """Explainable confidence score (firmrec.md §7.3).

    If FirmRec reports a signature similarity, use it directly (capped 0..1).
    Otherwise fall back to ``0.5 + 0.3*similarity + 0.2*(has_entry evidence)``,
    with the formula recorded in ``notes`` by the caller.
    """
    if similarity is not None:
        try:
            s = float(similarity)
            return round(min(max(s, 0.0), 1.0), 2)
        except (TypeError, ValueError):
            pass
    base = (
        0.5
        + 0.3 * (float(similarity) if similarity is not None else 0.0)
        + 0.2 * (1 if has_entry else 0)
    )
    return round(min(base, 1.0), 2)


def _vuln_class_for(det: dict[str, Any]) -> str:
    vc = str(det.get("vuln_class", "")).strip().lower()
    if vc in {
        "command_injection",
        "overflow",
        "path_traversal",
        "auth_bypass",
        "config_injection",
        "format_string",
    }:
        return vc
    # Infer from sink function when the class is not stated.
    fn = det.get("function", "").lower()
    if fn in {"system", "popen", "execl", "execv", "doSystemCmd", "lxmldbc_system"}:
        return "command_injection"
    if fn in {"strcpy", "strcat", "sprintf", "memcpy", "gets", "scanf"}:
        return "overflow"
    return "other"


def _sink_type_for(vuln_class: str, function: str) -> str:
    if vuln_class == "command_injection" or function in {"system", "popen"}:
        return "command_execution"
    if vuln_class == "overflow" or function in {"strcpy", "memcpy", "sprintf"}:
        return "memory_copy"
    return "unknown"


# --------------------------------------------------------------------------- #
# high-level assembly
# --------------------------------------------------------------------------- #


def parse_firmrec_output(
    output_dir: Path,
    *,
    rootfs: Path,
    run_id: str,
    tool_version: str = "",
    duration_s: float = 0.0,
) -> tuple[list[dict[str, Any]], ParseStats]:
    """Walk a FirmRec output tree and emit normalized findings.

    Returns ``(findings, stats)``. Never raises for missing or malformed input.
    FirmRec findings always carry ``matched_cve`` (they are recurring detections),
    which lets the fusion layer apply the blind-run isolation.
    """
    stats = ParseStats()
    findings: list[dict[str, Any]] = []
    out = Path(output_dir)
    if not out.exists():
        stats.note(f"output directory missing: {output_dir}")
        return findings, stats

    vulns_md = out / "VULNS.md"
    raw_detections: list[dict[str, Any]] = []
    if vulns_md.exists():
        raw_detections.extend(parse_vulns_md(vulns_md, stats))

    for csv_file in sorted(out.glob("pg_*.csv")):
        raw_detections.extend(parse_pg_csv(csv_file, stats))

    poc_dir = out / "poc_info"
    raw_detections.extend(parse_poc_info(poc_dir, stats))

    # Merge detections that describe the same (binary, addr, cve) into one finding.
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for det in raw_detections:
        cve = _CVE_RE.search(det.get("cve_id", "") or "")
        cve_id = cve.group(0).upper() if cve else (det.get("cve_id", "") or "").upper()
        binary = det.get("binary", "").strip() or "unknown"
        addr = normalize_addr(det.get("addr"))
        key = (binary, addr, cve_id)
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(det)
            merged[key]["cve_id"] = cve_id
        else:
            # Prefer the entry that carries more evidence (e.g. PG over VULNS.md).
            if len(str(det.get("similarity", ""))) > len(str(existing.get("similarity", ""))):
                existing.update(det)
            existing["cve_id"] = cve_id

    for (binary, addr, cve_id), det in sorted(merged.items()):
        vuln_class = _vuln_class_for(det)
        sink_func = det.get("function", "").strip()
        similarity_raw = det.get("similarity")
        try:
            sim_val = float(similarity_raw) if similarity_raw not in (None, "") else None
        except (TypeError, ValueError):
            sim_val = None
        has_entry = bool(det.get("source"))
        confidence = compute_confidence(sim_val, has_entry=has_entry)
        formula_note = (
            "" if sim_val is not None else " (confidence=0.5+0.3*sim+0.2*entry; sim not reported)"
        )

        binary_id = (
            normalize_binary_id(rootfs, rootfs / binary) if (rootfs / binary).exists() else binary
        )
        slug = re.sub(r"[^A-Za-z0-9]+", "-", binary_id).strip("-") or "unknown"
        poc_sanitized = bool(det.get("poc_sanitized", False))
        payload = det.get("payload", "")

        finding: dict[str, Any] = {
            "finding_id": f"firmrec-{slug}-{addr or cve_id or 'na'}",
            "tool": "firmrec",
            "tool_version": tool_version or "unknown",
            "run_id": run_id,
            "binary_id": binary_id,
            "vuln_class": vuln_class,
            "entry_point": {"type": "unknown"},
            "source": {
                "type": "unknown" if not det.get("source") else "config",
                "name": det.get("source", ""),
                "evidence": f"firmrec:recurring-match:{cve_id}" if cve_id else "firmrec:recurring",
            },
            "sink": {
                "function": sink_func,
                "addr": addr,
                "type": _sink_type_for(vuln_class, sink_func),
            },
            "call_trace": [],
            "matched_cve": cve_id or None,
            "confidence": confidence,
            "status": "ok",
            "duration_s": round(duration_s, 1),
            "notes": (
                f"parser={PARSER_VERSION}; recurrence=true; "
                f"similarity={similarity_raw or 'n/a'}{formula_note}"
            ),
        }
        if poc_sanitized:
            finding["validation"] = {
                "triggered": None,
                "probe": "none",
                "poc_sanitized": True,
            }
            finding["notes"] += f"; poc_sanitized=true len={len(payload)}"
        findings.append(finding)

    if not findings:
        stats.note("no recurring vulnerabilities parsed; check VULNS.md / pg_*.csv / poc_info")
    return findings, stats


# --------------------------------------------------------------------------- #
# upstream result.csv (the real FirmRec output)
# --------------------------------------------------------------------------- #


def _norm_key(key: str | None) -> str:
    return str(key or "").strip().lower().replace(" ", "_")


def _result_row(row: dict[str, Any]) -> dict[str, str]:
    return {
        _norm_key(key): str(value or "").strip() for key, value in row.items() if key is not None
    }


def _vuln_class_for_reason(reason: str, sink: str) -> str:
    text = f"{reason} {sink}".lower()
    if any(word in text for word in ("command", "cmd", "rce", "system", "popen")):
        return "command_injection"
    if any(word in text for word in ("overflow", "buffer", "strcpy", "memcpy", "sprintf")):
        return "overflow"
    if any(word in text for word in ("path traversal", "directory traversal", "lfi")):
        return "path_traversal"
    if any(word in text for word in ("auth", "bypass")):
        return "auth_bypass"
    if any(word in text for word in ("config", "nvram")):
        return "config_injection"
    if any(word in text for word in ("format", "printf")):
        return "format_string"
    return "other"


def _source_type_for(source: str) -> str:
    name = source.strip().lower()
    if name in {"getenv", "secure_getenv"}:
        return "environment"
    if name.startswith("nvram"):
        return "nvram"
    if name in {"recv", "recvfrom", "read", "socket", "accept"}:
        return "socket_buffer"
    return "unknown"


def matched_cve_for_refs(vuln_refs: list[str]) -> str:
    """Return the CVE when the experiment used exactly one signature.

    ``result.csv`` does not carry the matched CVE. If several signatures were
    used (or none can be parsed) we return an empty string rather than guess;
    recurrence isolation does not depend on this field (the fusion layer splits
    on ``tool == "firmrec"`` and force-isolates the recurrence batch).
    """
    cves: list[str] = []
    for ref in vuln_refs:
        match = _CVE_RE.search(ref)
        if match and match.group(0).upper() not in cves:
            cves.append(match.group(0).upper())
    return cves[0] if len(cves) == 1 else ""


def _normalize_entry_addr(value: str) -> str:
    """Normalize ``entry_addr`` from hex or decimal without confusing the two."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return hex(int(text, 0))
    except ValueError:
        return normalize_addr(text)


def parse_result_csv(
    path: Path,
    *,
    rootfs: Path,
    run_id: str,
    tool_version: str = "",
    duration_s: float = 0.0,
    vuln_refs: list[str] | None = None,
) -> tuple[list[dict[str, Any]], ParseStats]:
    """Parse upstream FirmRec's ``inout/emu_results/result.csv``.

    Columns: ``firmware_id, vendor, bin_path, entry_addr, source, keyword, sink,
    vuln_reason, run_time``. Malformed rows are skipped and counted; the reader
    never raises.
    """
    stats = ParseStats()
    path = Path(path)
    if not path.is_file():
        stats.note(f"result.csv missing: {path}")
        return [], stats
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        stats.note(f"result.csv unreadable: {exc}")
        return [], stats
    if not text.strip():
        stats.note(f"result.csv is empty: {path}")
        return [], stats

    stats.files_seen.append(path.name)
    refs = list(vuln_refs or [])
    matched_cve = matched_cve_for_refs(refs)
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}

    for row in csv.DictReader(text.splitlines()):
        det = _result_row(row)
        vuln_flag = (det.get("vuln") or det.get("is_vuln") or "").upper()
        if vuln_flag in {"NORM", "NORMAL", "FALSE", "0", "NO", "BENIGN"}:
            continue
        bin_path = det.get("bin_path", "").lstrip("/")
        sink_func = det.get("sink", "")
        if not bin_path or not sink_func:
            stats.unparsed_lines += 1
            continue
        addr = _normalize_entry_addr(det.get("entry_addr"))
        vuln_class = _vuln_class_for_reason(det.get("vuln_reason", ""), sink_func)
        binary_id = normalize_binary_id(rootfs, bin_path)
        key = (binary_id, addr, vuln_class)
        if key in merged:
            continue

        source_func = det.get("source", "")
        keyword = det.get("keyword", "")
        confidence = compute_confidence(None, has_entry=bool(keyword))
        slug = re.sub(r"[^A-Za-z0-9]+", "-", binary_id).strip("-") or "unknown"
        notes = (
            f"parser={RESULT_PARSER_VERSION}; recurrence=true; "
            f"vendor={det.get('vendor', '')}; firmware_id={det.get('firmware_id', '')}; "
            f"run_time={det.get('run_time', '')}; source_function={source_func}; "
            f"keyword={keyword}; vuln_refs={','.join(refs)}; "
            f"confidence=0.5+0.2*entry"
        )
        finding: dict[str, Any] = {
            "finding_id": f"firmrec-{slug}-{addr or 'na'}",
            "tool": "firmrec",
            "tool_version": tool_version or "unknown",
            "run_id": run_id,
            "binary_id": binary_id,
            "vuln_class": vuln_class,
            "entry_point": {"type": "unknown", "path": bin_path},
            "source": {
                "type": _source_type_for(source_func),
                "name": source_func,
                "evidence": f"firmrec:source={source_func};keyword={keyword}",
            },
            "sink": {
                "function": sink_func,
                "addr": addr,
                "type": _sink_type_for(vuln_class, sink_func),
            },
            "call_trace": (
                [{"addr": addr, "func": sink_func, "note": "FirmRec concolic alarm"}]
                if addr
                else []
            ),
            "confidence": confidence,
            "status": "ok",
            "duration_s": round(duration_s, 1),
            "notes": notes,
        }
        if matched_cve:
            finding["matched_cve"] = matched_cve
        merged[key] = finding

    findings = list(merged.values())
    if not findings:
        stats.note("result.csv contained no usable vulnerability rows")
    return findings, stats


def _apply_poc_info(
    findings: list[dict[str, Any]],
    poc_dir: Path,
    *,
    rootfs: Path,
) -> None:
    """Attach sanitized PoC metadata to matching result.csv findings."""
    if not poc_dir.exists():
        return
    stats = ParseStats()
    detections = parse_poc_info(poc_dir, stats)
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        sink = finding.get("sink") or {}
        by_key[(str(finding.get("binary_id", "")), normalize_addr(sink.get("addr")))] = finding
    for det in detections:
        binary = str(det.get("binary", "")).lstrip("/")
        if not binary:
            continue
        key = (normalize_binary_id(rootfs, binary), normalize_addr(det.get("addr")))
        target = by_key.get(key)
        if target is None:
            continue
        target["validation"] = {"triggered": None, "probe": "none", "poc_sanitized": True}
        target["notes"] = str(target.get("notes", "")) + "; poc_sanitized=true"


def parse_upstream_output(
    inout_dir: Path,
    *,
    rootfs: Path,
    run_id: str,
    tool_version: str = "",
    duration_s: float = 0.0,
    vuln_refs: list[str] | None = None,
) -> tuple[list[dict[str, Any]], ParseStats]:
    """Parse an upstream FirmRec ``inout`` directory (result.csv + poc_info).

    Upstream versions disagree on the output directory name: the Docker image
    writes ``emu_results`` in some releases and ``simexp_results`` in others, and
    older builds write ``inout/result.csv``. Search all known locations, then
    fall back to a recursive search, and merge rows from every file found.
    """
    inout = Path(inout_dir)
    stats = ParseStats()
    candidates = [
        inout / "emu_results" / "result.csv",
        inout / "simexp_results" / "result.csv",
        inout / "result.csv",
    ]
    paths = [path for path in candidates if path.is_file()]
    if not paths:
        paths = sorted(inout.rglob("result.csv"))
    if not paths:
        stats.note(f"no upstream result.csv under: {inout}")
        return [], stats

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for result_path in paths:
        parsed_findings, parsed = parse_result_csv(
            result_path,
            rootfs=rootfs,
            run_id=run_id,
            tool_version=tool_version,
            duration_s=duration_s,
            vuln_refs=vuln_refs,
        )
        stats.files_seen.extend(parsed.files_seen)
        stats.unparsed_lines += parsed.unparsed_lines
        stats.dropped_unsafe += parsed.dropped_unsafe
        for note in parsed.limitations:
            stats.note(note)
        for finding in parsed_findings:
            sink = finding.get("sink") or {}
            key = (
                str(finding.get("binary_id", "")),
                normalize_addr(sink.get("addr")),
                str(finding.get("vuln_class", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    _apply_poc_info(findings, inout / "poc_info", rootfs=rootfs)
    return findings, stats


__all__ = [
    "PARSER_VERSION",
    "RESULT_PARSER_VERSION",
    "ParseStats",
    "parse_vulns_md",
    "parse_pg_csv",
    "parse_poc_info",
    "compute_confidence",
    "parse_firmrec_output",
    "parse_result_csv",
    "parse_upstream_output",
    "matched_cve_for_refs",
]
