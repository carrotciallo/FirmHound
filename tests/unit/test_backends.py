"""Execution backend helpers: env forwarding, missing binaries, duration."""

from __future__ import annotations

import sys
from pathlib import Path

from fsa.utils.proc import RunResult
from tools.external import backends


def test_run_local_forwards_env_and_measures_duration(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run_command(cmd, *, cwd=None, timeout=60.0, shell=False, env=None):
        captured.update({"cmd": cmd, "cwd": cwd, "timeout": timeout, "env": env})
        return RunResult(
            command=" ".join(cmd), returncode=0, stdout="ok", stderr="", status="success"
        )

    monkeypatch.setattr(backends, "run_command", fake_run_command)
    result = backends.run_local(
        [sys.executable, "-c", "print(1)"],
        cwd=tmp_path,
        env={"LC_ALL": "C", "PGPASSWORD": "secret"},
    )

    assert result.status == "ok"
    assert captured["env"] == {"LC_ALL": "C", "PGPASSWORD": "secret"}
    assert captured["cwd"] == tmp_path
    assert result.duration_s >= 0.0


def test_run_local_reports_missing_absolute_binary(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    result = backends.run_local([str(missing)])

    assert result.status == "missing"
    assert "executable not found" in result.stderr


def test_run_local_reports_missing_path_binary() -> None:
    result = backends.run_local(["definitely-not-a-real-binary-xyz"])

    assert result.status == "missing"
