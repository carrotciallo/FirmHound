"""End-to-end coverage for the opt-in AGENT_LOOP stage."""

from __future__ import annotations

import sys
from pathlib import Path

from click.testing import CliRunner

from fsa.cli import main
from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fixtures"))
from elf_builder import write_elf64  # noqa: E402


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = Path(__file__).resolve().parents[2]
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "www" / "cgi-bin").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    write_elf64(
        root / "bin" / "httpd",
        imports=["system", "sprintf", "getenv"],
        defined_syms=["formexeCommand"],
        rodata_strings=["QUERY_STRING", "/cgi-bin/diagnostic.cgi"],
    )
    (root / "www" / "index.html").write_text("<html>router</html>", encoding="utf-8")
    (root / "etc" / "init.d" / "S50httpd").write_text("/bin/httpd -p 80\n", encoding="utf-8")

    runs = tmp_path / "runs"
    temp = tmp_path / "temp"
    safety = tmp_path / "safety.yaml"
    save_yaml(
        safety,
        {
            "enforce": True,
            "abort_on_violation": True,
            "allowed_paths": [str(runs), str(temp), str(root)],
            "blocked_paths": [],
            "command_blacklist": [],
            "network": {"allow_public": False, "allowed_hosts": ["localhost"]},
            "model": {},
        },
    )
    config = tmp_path / "dev.yaml"
    save_yaml(
        config,
        {
            "runtime": {"default": "mock"},
            "paths": {
                "runs": str(runs),
                "temp": str(temp),
                "schemas": str(repo / "schemas"),
                "models": str(repo / "config" / "models.yaml"),
            },
            "safety": {"config": str(safety), "enforce": True},
            "analysis": {"max_binaries": 50, "max_strings_per_binary": 100, "verify_top_k": 5},
            "external": {"enabled": False},
        },
    )
    return config, root, runs


def _analyze(config: Path, root: Path, *extra: str, run_id: str) -> object:
    runner = CliRunner()
    return runner.invoke(
        main,
        [
            "--config",
            str(config),
            "analyze",
            str(root),
            "--input-type",
            "rootfs",
            "--authorization-holder",
            "owner",
            "--depth",
            "standard",
            "--run-id",
            run_id,
            *extra,
        ],
    )


def test_agent_enabled_writes_trace_and_report_section(tmp_path: Path) -> None:
    config, root, runs = _workspace(tmp_path)
    result = _analyze(config, root, "--agent", run_id="agent-e2e")
    assert result.exit_code == 0, result.output
    run = runs / "agent-e2e"
    assert load_json(run / "state" / "run_state.json")["status"] == "done"
    trace = load_json(run / "artifacts" / "agent_trace.json")
    validate(trace, schema_name="agent_trace")
    assert trace["enabled"] is True
    assert trace["tier"] == "standard"
    assert trace["steps"]
    assert trace["model"]["used"] is False
    report = (run / "report.md").read_text(encoding="utf-8")
    assert report.count("\n## ") == 24
    assert "自主分析轨迹" in report
    assert "模型仅参与动作选择，不参与漏洞结论" in report
    assert (run / "artifacts" / "ranking.json").is_file()
    assert (run / "artifacts" / "verdict.json").is_file()


def test_agent_defaults_off(tmp_path: Path) -> None:
    config, root, runs = _workspace(tmp_path)
    result = _analyze(config, root, run_id="agent-off")
    assert result.exit_code == 0, result.output
    run = runs / "agent-off"
    state = load_json(run / "state" / "run_state.json")
    assert "AGENT_LOOP" not in state["completed_stages"]
    assert not (run / "artifacts" / "agent_trace.json").exists()
    report = (run / "report.md").read_text(encoding="utf-8")
    assert report.count("\n## ") == 24
    assert "未启用" in report


def test_blind_forces_agent_off(tmp_path: Path) -> None:
    config, root, runs = _workspace(tmp_path)
    result = _analyze(config, root, "--agent", "--blind", run_id="agent-blind")
    assert result.exit_code == 0, result.output
    run = runs / "agent-blind"
    state = load_json(run / "state" / "run_state.json")
    assert "AGENT_LOOP" not in state["completed_stages"]
    assert not (run / "artifacts" / "agent_trace.json").exists()
    report = (run / "report.md").read_text(encoding="utf-8")
    assert "Blind 运行强制禁用自主分析" in report


def test_plan_shows_agent_stage_only_when_requested(tmp_path: Path) -> None:
    config, root, _ = _workspace(tmp_path)
    runner = CliRunner()
    base = [
        "--config",
        str(config),
        "plan",
        "--firmware-path",
        str(root),
        "--authorization-holder",
        "owner",
        "--json-output",
    ]
    off = runner.invoke(main, base)
    assert off.exit_code == 0, off.output
    assert "AGENT_LOOP" not in off.output

    on = runner.invoke(main, [*base, "--agent"])
    assert on.exit_code == 0, on.output
    assert "AGENT_LOOP" in on.output
    assert '"enabled": true' in on.output
