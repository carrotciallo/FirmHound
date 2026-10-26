"""Registry-facing entry point for the optional bounded AGENT_LOOP stage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fsa.orchestrator.agent_loop import run_agent_loop
from fsa.orchestrator.agent_options import resolve_agent_options
from fsa.utils.config_files import resolve_config_file
from fsa.utils.jsonio import load_yaml
from tools.pipeline_context import load_task, run_path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_config(config_path: str | None) -> dict[str, Any]:
    path = resolve_config_file(
        config_path or _REPO_ROOT / "config" / "dev.yaml"
    )
    config = load_yaml(path)
    base = path.parent.parent if path.parent.name == "config" else path.parent
    safety = config.setdefault("safety", {})
    safety_config = safety.get("config")
    if safety_config and not Path(safety_config).is_absolute():
        safety["config"] = str((base / safety_config).resolve())
    config["_config_path"] = str(path)
    return config


def execute_agent_loop(run_dir: str, config_path: str | None = None) -> dict[str, Any]:
    """Run the bounded agent loop against an existing, ranked run."""
    try:
        run = run_path(run_dir)
        task = load_task(run)
        config = _load_config(config_path)
        options = task.get("agent")
        if not isinstance(options, dict) or not options:
            authorization = task.get("authorization", {}) if isinstance(task, dict) else {}
            options = resolve_agent_options(
                config.get("agent", {}),
                None,
                blind=bool(task.get("blind", False)),
                allow_emulation=bool(authorization.get("allow_emulation", False)),
                external_enabled=bool(config.get("external", {}).get("enabled", False)),
            )
        return run_agent_loop(run, options=options, config=config)
    except Exception as exc:  # noqa: BLE001 - the stage must degrade, not abort the run
        return {
            "status": "failed",
            "reason": f"{type(exc).__name__}: {exc}",
        }
