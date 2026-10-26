"""Report rendering for external findings and FirmRec recurrence isolation."""

from __future__ import annotations

import json
from pathlib import Path

from tools.report.generate import _finding_count, _tool_statuses, execute_report


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_finding_count_accepts_int_and_list() -> None:
    assert _finding_count({"findings": 3}) == 3
    assert _finding_count({"findings": [{"a": 1}, {"b": 2}]}) == 2
    assert _finding_count({}) == 0
    assert _finding_count(None) == 0


def test_tool_statuses_prefers_per_tool() -> None:
    payload = {"per_tool": {"satc": {"status": "ok"}, "firmrec": {"status": "skipped"}}}
    assert _tool_statuses(payload) == "firmrec=skipped, satc=ok"


def test_tool_statuses_missing_payload_names_the_tools() -> None:
    """No external artifact at all must still say which tools did not run."""
    rendered = _tool_statuses({})
    for name in ("satc", "firmrec", "klee", "bond"):
        assert name in rendered
    assert "未运行" in rendered
    assert _tool_statuses(None) == rendered


def test_tool_statuses_skipped_includes_limitation() -> None:
    payload = {
        "status": "skipped",
        "per_tool": {},
        "limitation": "all selected external analyzers disabled in config",
    }
    rendered = _tool_statuses(payload)
    assert "klee" in rendered
    assert "disabled in config" in rendered


def test_tool_statuses_includes_per_tool_limitation() -> None:
    payload = {"per_tool": {"klee": {"status": "skipped", "limitation": "klee not installed"}}}
    assert _tool_statuses(payload) == "klee=skipped（klee not installed）"


def test_report_without_external_artifacts_names_tools_and_limits(tmp_path: Path) -> None:
    """Regression: section 18 used to collapse to a bare 未启用 line."""
    run = tmp_path / "runs" / "run-noext"
    _write(
        run / "state" / "task_card.json",
        {
            "task_id": "run-noext",
            "authorization": {"holder": "owner", "scope": "analysis-only"},
        },
    )
    _write(run / "artifacts" / "rootfs.json", {"status": "ok"})
    _write(run / "artifacts" / "binary_summaries.json", {"inventory": {}, "summaries": []})
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(run / "artifacts" / "ranking.json", {"candidates": []})
    _write(run / "artifacts" / "verdict.json", {"run_id": "run-noext", "verdicts": []})
    _write(run / "artifacts" / "local_validation.json", {})

    result = execute_report(str(run))

    assert result["status"] == "ok"
    report = (run / "report.md").read_text(encoding="utf-8")
    section = report.split("## 18. 外部分析器结果", 1)[1].split("## 19.", 1)[0]
    for name in ("satc", "firmrec", "klee", "bond"):
        assert name in section
    assert "受限结论" in section


def test_report_handles_int_findings_and_renders_recurrence(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "run-1"
    _write(
        run / "state" / "task_card.json",
        {
            "task_id": "run-1",
            "authorization": {"holder": "owner", "scope": "analysis-only"},
        },
    )
    _write(run / "artifacts" / "rootfs.json", {"status": "ok"})
    _write(run / "artifacts" / "binary_summaries.json", {"inventory": {}, "summaries": []})
    _write(run / "artifacts" / "attack_surface.json", {"surfaces": []})
    _write(run / "artifacts" / "ranking.json", {"candidates": []})
    _write(run / "artifacts" / "verdict.json", {"run_id": "run-1", "verdicts": []})
    _write(run / "artifacts" / "local_validation.json", {})
    _write(
        run / "artifacts" / "external_findings" / "all.json",
        {
            "status": "ok",
            "findings": 3,
            "per_tool": {"satc": {"status": "ok"}, "firmrec": {"status": "skipped"}},
        },
    )
    _write(
        run / "artifacts" / "external_findings" / "recurrence_findings.json",
        {
            "summary": {"recurrence": 1, "blind_isolated": 1},
            "findings": [
                {
                    "tool": "firmrec",
                    "matched_cve": "CVE-2017-17215",
                    "blind_isolated": True,
                }
            ],
        },
    )

    result = execute_report(str(run))

    assert result["status"] == "ok"
    assert result["section_count"] == 24
    report = (run / "report.md").read_text(encoding="utf-8")
    assert report.count("\n## ") == 24
    assert "自主分析轨迹" in report
    assert "未启用" in report
    assert "规范化外部发现：3" in report
    assert "satc=ok" in report
    assert "复发发现：1 条" in report
    assert "CVE-2017-17215" in report
    assert "不计入 Blind Benchmark 指标" in report
