"""Upstream FirmRec ``result.csv`` parsing."""

from __future__ import annotations

from pathlib import Path

from tools.external.firmrec.parser import parse_result_csv, parse_upstream_output

_HEADER = "firmware_id,vendor,bin_path,entry_addr,source,keyword,sink,vuln_reason,run_time\n"


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_parse_result_csv_maps_upstream_fields(tmp_path: Path) -> None:
    csv_path = _write(
        tmp_path / "result.csv",
        _HEADER
        + "fw1,acme,bin/httpd,0x0040A1B0,getenv,REMOTE_ADDR,system,command injection,12.5\n"
        + "fw1,acme,bin/httpd,64,recv,,strcpy,buffer overflow,3.0\n",
    )

    findings, stats = parse_result_csv(
        csv_path,
        rootfs=tmp_path / "rootfs",
        run_id="run-1",
        vuln_refs=["acme/CVE-2017-17215"],
    )

    assert stats.files_seen == ["result.csv"]
    assert len(findings) == 2
    first = findings[0]
    assert first["binary_id"] == "bin/httpd"
    assert first["sink"]["addr"] == "0x40a1b0"
    assert first["vuln_class"] == "command_injection"
    assert first["source"]["type"] == "environment"
    assert first["matched_cve"] == "CVE-2017-17215"
    assert first["confidence"] == 0.7
    second = findings[1]
    assert second["sink"]["addr"] == "0x40"
    assert second["vuln_class"] == "overflow"
    assert second["source"]["type"] == "socket_buffer"


def test_parse_result_csv_ambiguous_vuln_refs_omit_cve(tmp_path: Path) -> None:
    csv_path = _write(
        tmp_path / "result.csv",
        _HEADER + "fw1,acme,bin/httpd,0x40,getenv,K,system,command injection,1\n",
    )

    findings, _ = parse_result_csv(
        csv_path,
        rootfs=tmp_path,
        run_id="run-2",
        vuln_refs=["acme/CVE-2017-17215", "acme/CVE-2021-31802"],
    )

    assert "matched_cve" not in findings[0]
    assert "vuln_refs=acme/CVE-2017-17215,acme/CVE-2021-31802" in findings[0]["notes"]


def test_parse_result_csv_respects_vuln_filter_column(tmp_path: Path) -> None:
    csv_path = _write(
        tmp_path / "result.csv",
        _HEADER.rstrip("\n")
        + ",vuln\n"
        + "fw1,acme,bin/a,0x40,getenv,K,system,command injection,1,NORM\n"
        + "fw1,acme,bin/b,0x41,getenv,K,system,command injection,1,VULN\n",
    )

    findings, _ = parse_result_csv(csv_path, rootfs=tmp_path, run_id="run-3", vuln_refs=[])

    assert [item["binary_id"] for item in findings] == ["bin/b"]


def test_parse_result_csv_malformed_rows_degrade(tmp_path: Path) -> None:
    csv_path = _write(
        tmp_path / "result.csv",
        _HEADER
        + "fw1,acme,,0x40,getenv,K,system,command injection,1\n"
        + "fw1,acme,bin/httpd,0x41,getenv,K,system,command injection,1\n",
    )

    findings, stats = parse_result_csv(csv_path, rootfs=tmp_path, run_id="run-4", vuln_refs=[])

    assert len(findings) == 1
    assert stats.unparsed_lines == 1


def test_parse_upstream_output_finds_simexp_results(tmp_path: Path) -> None:
    _write(
        tmp_path / "inout" / "simexp_results" / "result.csv",
        _HEADER + "fw1,acme,bin/httpd,0x40,getenv,K,system,command injection,1\n",
    )

    findings, stats = parse_upstream_output(
        tmp_path / "inout",
        rootfs=tmp_path,
        run_id="run-5",
        vuln_refs=["acme/CVE-2017-17215"],
    )

    assert len(findings) == 1
    assert stats.files_seen == ["result.csv"]


def test_parse_upstream_output_missing_csv_is_tolerant(tmp_path: Path) -> None:
    findings, stats = parse_upstream_output(
        tmp_path / "inout", rootfs=tmp_path, run_id="run-6", vuln_refs=[]
    )

    assert findings == []
    assert any("no upstream result.csv" in item for item in stats.limitations)
