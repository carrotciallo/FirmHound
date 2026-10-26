"""Command-line interface for the firmware security analysis pipeline."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

import click
import structlog
from dotenv import load_dotenv

from fsa.orchestrator.engine import Orchestrator, validate_run_id
from fsa.schemas.loader import validate_all_examples
from fsa.utils import console
from fsa.utils.jsonio import load_json, load_yaml
from fsa.utils.platform_info import detect as detect_platform
from fsa.utils.platform_info import hint_for
from tools.firmware.diagnose import diagnose_firmware
from tools.report.explain import build_evidence_ledger, render_ledger_markdown


def _render_value(key: str, item: Any) -> Any:
    """Colour one value according to what it means, not where it sits."""
    if key == "status" and isinstance(item, str):
        return console.status(item)
    if key in {"run_dir", "report", "input", "run_id"} and item not in (None, ""):
        return console.muted(item)
    if item in (None, "", []):
        return console.muted("-")
    return item


def _emit(value: dict[str, Any], as_json: bool) -> None:
    if as_json:
        console.echo(json.dumps(value, ensure_ascii=False))
        return
    for key, item in value.items():
        console.echo(f"{console.muted(key)}: {_render_value(key, item)}")


def _status_from_checks(checks: dict[str, dict[str, Any]]) -> str:
    statuses = {item.get("status") for item in checks.values()}
    if "failed" in statuses:
        return "failed"
    if "degraded" in statuses:
        return "degraded"
    return "ok"


@click.group()
@click.option(
    "--config",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("config/dev.yaml"),
    show_default=True,
    help="YAML configuration path.",
)
@click.pass_context
def main(ctx: click.Context, config: Path) -> None:
    """FirmHound firmware-security agent CLI."""
    config = config.resolve()
    if not config.is_file():
        raise click.ClickException(f"configuration not found: {config}")
    load_dotenv(config.parent.parent / ".env")
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@main.command()
@click.option("--task", help="Natural-language task description.")
@click.option(
    "--task-package",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="ZIP package containing a task description and firmware artifacts.",
)
@click.option("--firmware-path", type=click.Path(path_type=Path), help="Firmware or rootfs path.")
@click.option(
    "--depth",
    type=click.Choice(["quick", "standard", "full"]),
    default="standard",
    show_default=True,
)
@click.option("--authorization-holder", default="", help="Authorized owner/operator name.")
@click.option("--authorization-scope", default="analysis-only", show_default=True)
@click.option("--allow-emulation", is_flag=True, help="Authorize isolated local emulation.")
@click.option("--vendor")
@click.option("--model")
@click.option("--version")
@click.option("--run-id", help="Optional stable run identifier.")
@click.option("--json-output", is_flag=True, help="Emit a machine-readable plan.")
@click.option(
    "--blind/--no-blind",
    default=False,
    show_default=True,
    help="Blind benchmark run: recurrence-only tools are force-disabled.",
)
@click.pass_context
def plan(
    ctx: click.Context,
    task: str | None,
    task_package: Path | None,
    firmware_path: Path | None,
    depth: str,
    authorization_holder: str,
    authorization_scope: str,
    allow_emulation: bool,
    vendor: str | None,
    model: str | None,
    version: str | None,
    run_id: str | None,
    json_output: bool,
    blind: bool,
) -> None:
    """Parse a task and show the planned CLI execution stages without running tools."""
    if not any((task, task_package, firmware_path)):
        raise click.ClickException("provide --task, --task-package, or --firmware-path")

    try:
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        if firmware_path:
            source = firmware_path.resolve()
            if not source.exists():
                raise click.ClickException(f"firmware path not found: {source}")
            orchestrator.policy.check_path(source)
            firmware_value = str(source)
        else:
            firmware_value = ""

        task_input: dict[str, Any] = {
            "task_id": run_id or uuid.uuid4().hex[:12],
            "natural_language": task or "",
            "task_package": str(task_package.resolve()) if task_package else "",
            "firmware_path": firmware_value,
            "vendor": vendor,
            "model": model,
            "version": version,
            "depth": depth,
            "blind": blind,
            "authorization": {
                "holder": authorization_holder,
                "scope": authorization_scope,
                "allow_emulation": allow_emulation,
                "network_isolation": True,
            },
        }
        task_card = orchestrator.planner.parse_task(task_input)
        execution_plan = orchestrator.planner.build_plan(task_card)
    except Exception as exc:  # noqa: BLE001
        structlog.get_logger().error("planning_failed", error=str(exc))
        raise click.ClickException(str(exc)) from exc

    _emit(
        {
            "status": "needs_human_input" if task_card["requires_human_gate"] else "ok",
            "run_id": task_card["task_id"],
            "objective": task_card["objective"],
            "firmware_path": task_card["firmware_path"],
            "depth": task_card["depth"],
            "blind": bool(task_card.get("blind", False)),
            "stages": execution_plan["stages"],
            "requires_human_gate": task_card["requires_human_gate"],
            "human_gate_reasons": task_card["human_gate_reasons"],
            "attachments": task_card.get("attachments", []),
        },
        json_output,
    )


@main.command()
@click.argument(
    "input_paths",
    nargs=-1,
    required=True,
    type=click.Path(path_type=Path, exists=True),
)
@click.option(
    "--input-type",
    type=click.Choice(["auto", "firmware", "rootfs"]),
    default="auto",
    show_default=True,
)
@click.option(
    "--depth",
    type=click.Choice(["quick", "standard", "full"]),
    default="standard",
    show_default=True,
)
@click.option("--authorization-holder", required=True, help="Authorized owner/operator name.")
@click.option("--authorization-scope", default="analysis-only", show_default=True)
@click.option("--allow-emulation", is_flag=True, help="Authorize isolated local emulation.")
@click.option("--vendor")
@click.option("--model")
@click.option("--version")
@click.option(
    "--run-id",
    help="Optional stable run identifier; used as a prefix when several inputs are given.",
)
@click.option("--json-output", is_flag=True, help="Emit one JSON object per input.")
@click.option(
    "--blind/--no-blind",
    default=False,
    show_default=True,
    help="Blind benchmark run: recurrence-only tools are force-disabled.",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    input_paths: tuple[Path, ...],
    input_type: str,
    depth: str,
    authorization_holder: str,
    authorization_scope: str,
    allow_emulation: bool,
    vendor: str | None,
    model: str | None,
    version: str | None,
    run_id: str | None,
    json_output: bool,
    blind: bool,
) -> None:
    """Analyze firmware images or already extracted ROOTFS directories.

    Each INPUT_PATH gets its own run directory. With one input, --run-id is
    the run identifier; with several, it becomes a prefix and every run is
    named <run-id>-<n>-<input>.
    """
    if run_id:
        try:
            validate_run_id(run_id)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc

    targets = _classify_inputs(input_paths, input_type)
    options = {
        "depth": depth,
        "authorization_holder": authorization_holder,
        "authorization_scope": authorization_scope,
        "allow_emulation": allow_emulation,
        "vendor": vendor,
        "model": model,
        "version": version,
        "run_id": run_id,
        "blind": blind,
    }

    results = []
    for index, (source, kind) in enumerate(targets):
        result = _analyse_one(ctx.obj["config"], source, kind, options, index, len(targets))
        results.append(result)
        _report_result(result, json_output, index, len(targets))

    if len(results) > 1 and not json_output:
        _report_summary(results)

    if any(item["status"] != "done" for item in results):
        raise click.exceptions.Exit(2)


def _classify_inputs(
    input_paths: tuple[Path, ...],
    input_type: str,
) -> list[tuple[Path, str]]:
    """Resolve every input and decide whether it is a firmware image or a rootfs."""
    targets: list[tuple[Path, str]] = []
    for raw in input_paths:
        source = raw.resolve()
        detected = "rootfs" if source.is_dir() else "firmware"
        kind = detected if input_type == "auto" else input_type
        if kind == "rootfs" and not source.is_dir():
            raise click.ClickException(f"--input-type rootfs requires a directory: {source}")
        if kind == "firmware" and not source.is_file():
            raise click.ClickException(f"--input-type firmware requires a file: {source}")
        targets.append((source, kind))
    return targets


def _run_id_for(base: str | None, index: int, total: int, source: Path) -> str:
    """Build a run identifier that stays unique and filesystem-safe."""
    if total == 1:
        return base or uuid.uuid4().hex[:12]
    prefix = base or uuid.uuid4().hex[:8]
    stem = source.stem if source.is_file() else source.name
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", stem).strip("-_").lower() or "input"
    return validate_run_id(f"{prefix}-{index + 1}-{slug}"[:64])


def _analyse_one(
    config_path: Path,
    source: Path,
    kind: str,
    options: dict[str, Any],
    index: int,
    total: int,
) -> dict[str, Any]:
    """Run one input and return a result record, never raising on analysis failure."""
    result: dict[str, Any] = {
        "status": "failed",
        "input": str(source),
        "input_type": kind,
        "run_id": "",
        "run_dir": "",
        "report": None,
        "final_verdict": None,
    }

    try:
        run_id = _run_id_for(options["run_id"], index, total, source)
        orchestrator = Orchestrator(config_path=config_path)
        orchestrator.policy.check_path(source)
        task_input: dict[str, Any] = {
            "task_id": run_id,
            "firmware_path": str(source),
            "vendor": options["vendor"],
            "model": options["model"],
            "version": options["version"],
            "depth": options["depth"],
            "blind": bool(options.get("blind", False)),
            "authorization": {
                "holder": options["authorization_holder"],
                "scope": options["authorization_scope"],
                "allow_emulation": options["allow_emulation"],
                "network_isolation": True,
            },
        }
        if kind == "rootfs":
            task_input["rootfs_path"] = str(source)
        task_card = orchestrator.planner.parse_task(task_input)
        structlog.get_logger().info(
            "analysis_started",
            run_id=task_card["task_id"],
            input_type=kind,
            depth=options["depth"],
        )
        state = orchestrator.run(task_card)
    except Exception as exc:  # noqa: BLE001
        structlog.get_logger().error("analysis_failed", error=str(exc), input=str(source))
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    runs_dir = Path(orchestrator.config["paths"]["runs"])
    result.update(
        {
            "status": state["status"],
            "run_id": state["run_id"],
            "run_dir": str(runs_dir / state["run_id"]),
            "report": state.get("artifacts", {}).get("report"),
            "final_verdict": state.get("artifacts", {}).get("final_verdict"),
        }
    )
    if state["status"] != "done":
        result["error"] = _format_state_error(state)
        result["failed_stages"] = state.get("failed_stages", [])
        hint = _failure_hint(state)
        if hint:
            result["hint"] = hint
    return result


def _format_state_error(state: dict[str, Any]) -> str:
    """Turn the persisted last_error into one readable line."""
    error = state.get("last_error") or {}
    stage = error.get("stage") or state.get("current_stage")
    reason = error.get("reason") or "run stopped before reaching DONE"
    return f"{stage}: {reason}" if stage else str(reason)


def _failure_hint(state: dict[str, Any]) -> str:
    """Suggest the next concrete step for the failures we know how to explain."""
    error = state.get("last_error") or {}
    stage = error.get("stage")
    reason = str(error.get("reason", "")).lower()

    if stage == "UNPACK" and "no rootfs" in reason:
        return (
            "no usable rootfs was produced: run 'fsa unpack-diagnose <firmware>' to see which "
            "layer failed, then install unsquashfs / sasquatch (docs/guide/install.md)"
        )
    if "encrypted" in reason:
        return (
            "the payload is encrypted and needs decryption material; "
            "see 'fsa unpack-diagnose <firmware>' and docs/guide/install.md"
        )
    if stage == "UNPACK":
        return (
            "unpack failed and its artifacts were kept; "
            "'fsa unpack-diagnose <firmware>' shows which layer broke"
        )
    if stage:
        return f"stage {stage} failed; artifacts were kept, resume with 'fsa resume <run_id>'"
    return ""


_RESULT_KEYS = ("status", "input", "input_type", "run_id", "run_dir", "report", "final_verdict")


def _report_result(
    result: dict[str, Any],
    as_json: bool,
    index: int,
    total: int,
) -> None:
    """Print one input's outcome, as JSONL or as coloured key/value lines."""
    if as_json:
        console.echo(json.dumps(result, ensure_ascii=False))
        return

    if total > 1:
        console.echo()
        console.echo(console.label(f"[{index + 1}/{total}] {result['input']}"))

    keys = _RESULT_KEYS if total > 1 else tuple(k for k in _RESULT_KEYS if k != "input_type")
    for key in keys:
        console.echo(f"{console.muted(key)}: {_render_value(key, result.get(key))}")

    if result.get("error"):
        console.echo(f"{console.muted('error')}: {console.bad(result['error'])}")
    if result.get("hint"):
        console.echo(f"{console.muted('hint')}: {console.warn(result['hint'])}")


def _report_summary(results: list[dict[str, Any]]) -> None:
    """One line per input, then the tally."""
    console.echo()
    console.echo(console.label("summary"))
    for item in results:
        console.echo(f"  {console.status(item['status'])}  {console.muted(item['input'])}")
    done = sum(1 for item in results if item["status"] == "done")
    tally = f"{done}/{len(results)} done"
    console.echo(f"  {console.good(tally) if done == len(results) else console.warn(tally)}")


@main.command()
@click.option("--include-external-probes", is_flag=True, help="Probe optional external analyzers.")
@click.option("--json-output", is_flag=True, help="Emit machine-readable readiness data.")
@click.pass_context
def doctor(ctx: click.Context, include_external_probes: bool, json_output: bool) -> None:
    """Check local readiness for running and testing the CLI."""
    try:
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        config = orchestrator.config
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc

    checks: dict[str, dict[str, Any]] = {}
    path_results: dict[str, str] = {}
    for name, value in config.get("paths", {}).items():
        path = Path(value)
        exists = path.exists()
        if name in {"runs", "temp"}:
            path.mkdir(parents=True, exist_ok=True)
            exists = path.exists()
        path_results[name] = "ok" if exists else "missing"
    checks["paths"] = {
        "status": "ok" if all(v == "ok" for v in path_results.values()) else "failed",
        "items": path_results,
    }

    schema_errors = validate_all_examples()
    checks["schemas"] = {
        "status": "ok" if not schema_errors else "failed",
        "invalid_examples": [name for name, _ in schema_errors],
    }

    models_cfg = load_yaml(config["paths"]["models"])
    runtime_name = config.get("runtime", {}).get("default", "")
    model_env = (
        models_cfg.get("runtimes", {})
        .get("openai_compatible", {})
        .get("api_key_env", "OPENAI_API_KEY")
    )
    checks["runtime"] = {
        "status": "ok" if runtime_name == "offline" else "degraded",
        "default": runtime_name,
        "model_api_key_env": model_env,
        "model_api_key_present": bool(os.environ.get(model_env)),
        "note": (
            "offline runtime is deterministic; online model gateway credentials "
            "are optional for local CLI tests"
        ),
    }

    required_commands = ["python"]
    optional_commands = ["docker", "binwalk", "unsquashfs", "sasquatch", "7z", "readelf", "klee"]
    command_checks = {cmd: bool(shutil.which(cmd)) for cmd in required_commands + optional_commands}
    missing_commands = [
        cmd for cmd in required_commands + optional_commands if not command_checks[cmd]
    ]
    checks["commands"] = {
        "status": "ok" if all(command_checks[cmd] for cmd in required_commands) else "failed",
        "available": command_checks,
        "missing": missing_commands,
        "install_hints": {cmd: hint for cmd in missing_commands if (hint := hint_for(cmd))},
    }

    platform_info = detect_platform()
    checks["platform"] = {
        "status": "ok" if platform_info.supported else "degraded",
        **platform_info.as_dict(),
        "note": (
            "any mainstream Linux distribution is supported"
            if platform_info.supported
            else "FirmHound targets Linux; on other hosts only the pure-Python analysis layer runs"
        ),
    }

    if include_external_probes:
        from tools.external.adapter import EXTERNAL_TOOLS, _build_analyzer, _load_global_external

        external = _load_global_external(config_path=ctx.obj["config"])
        tools: dict[str, dict[str, Any]] = {}
        for tool in EXTERNAL_TOOLS:
            cfg = dict(external.get(tool, {}) or {})
            analyzer = _build_analyzer(tool, cfg)
            if analyzer is None:
                tools[tool] = {
                    "status": "failed",
                    "available": False,
                    "limitation": "adapter could not be constructed",
                }
                continue
            try:
                probe = analyzer.probe()
                tools[tool] = {
                    "status": "ok" if probe.available else "degraded",
                    "available": probe.available,
                    "version": probe.version,
                    "backend": probe.backend,
                    "missing": probe.missing,
                    "limitation": probe.notes,
                }
            except Exception as exc:  # noqa: BLE001
                tools[tool] = {
                    "status": "failed",
                    "available": False,
                    "limitation": f"{type(exc).__name__}: {exc}",
                }
        checks["external"] = {"status": _status_from_checks(tools), "tools": tools}

    overall = _status_from_checks(checks)
    if json_output:
        _emit({"status": overall, "checks": checks}, True)
        return

    console.echo(f"{console.muted('status')}: {console.status(overall)}")
    console.echo(
        f"{console.muted('platform')}: {platform_info.family} · {platform_info.distro_name}"
        f" · {platform_info.package_manager} · {platform_info.libc}"
    )
    for name in ("paths", "schemas", "runtime", "commands"):
        item = checks.get(name)
        if item is None:
            continue
        console.echo(f"{console.muted(name)}: {console.status(item['status'])}")

        if name == "paths":
            for key, value in item.get("items", {}).items():
                if value != "ok":
                    console.echo(f"  {console.bad(f'{key}: {value}')}")
        elif name == "schemas" and item.get("invalid_examples"):
            joined = ", ".join(item["invalid_examples"])
            console.echo(f"  {console.bad('invalid examples: ' + joined)}")
        elif name == "commands" and item["missing"]:
            missing = ", ".join(item["missing"])
            console.echo(f"  {console.warn('missing optional tools: ' + missing)}")
            for cmd, hint in (item.get("install_hints") or {}).items():
                console.echo(f"  {console.muted(cmd)} → {console.paint(hint, console.CYAN)}")


@main.command(name="unpack-diagnose")
@click.argument("firmware_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True, help="Emit machine-readable diagnosis.")
@click.pass_context
def unpack_diagnose(ctx: click.Context, firmware_path: Path, json_output: bool) -> None:
    """Diagnose whether and how a firmware image can be unpacked."""
    try:
        source = firmware_path.resolve()
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        orchestrator.policy.check_path(source)
        diagnosis = diagnose_firmware(source)
    except Exception as exc:  # noqa: BLE001
        structlog.get_logger().error("unpack_diagnose_failed", error=str(exc))
        raise click.ClickException(str(exc)) from exc

    if json_output:
        _emit(diagnosis, True)
        return
    console.echo(f"{console.muted('status')}: {console.status(diagnosis['status'])}")
    console.echo(f"{console.muted('firmware')}: {diagnosis['firmware']}")
    console.echo(f"{console.muted('sha256')}: {console.muted(diagnosis['sha256'])}")
    console.echo(f"{console.muted('signature_count')}: {diagnosis['signature_count']}")
    console.echo(f"{console.muted('selected_strategy')}: {diagnosis['selected_strategy']}")
    console.echo(f"{console.muted('confidence')}: {diagnosis['confidence']}")
    console.echo(console.label("recommendations"))
    for item in diagnosis["recommendations"]:
        console.echo(f"- {item}")


@main.command(name="status")
@click.argument("run_id")
@click.option("--json-output", is_flag=True)
@click.pass_context
def show_status(ctx: click.Context, run_id: str, json_output: bool) -> None:
    """Show the persisted state of an analysis run."""
    try:
        validate_run_id(run_id)
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        run_dir = Path(orchestrator.config["paths"]["runs"]) / run_id
        orchestrator.policy.check_path(run_dir)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc
    path = run_dir / "state" / "run_state.json"
    if not path.is_file():
        raise click.ClickException(f"run not found: {run_id}")
    state = load_json(path)
    _emit(
        {
            "status": state["status"],
            "run_id": state["run_id"],
            "current_stage": state["current_stage"],
            "completed_stages": state["completed_stages"],
            "failed_stages": state["failed_stages"],
        },
        json_output,
    )


@main.command()
@click.argument("run_id")
@click.option("--candidate-id", help="Explain only one candidate.")
@click.option(
    "--limit",
    type=int,
    default=5,
    show_default=True,
    help="Maximum candidates to include when --candidate-id is omitted; use 0 for all.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional path to save the ledger JSON or Markdown.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown"]),
    default="json",
    show_default=True,
)
@click.option("--json-output", is_flag=True, help="Emit machine-readable ledger.")
@click.pass_context
def explain(
    ctx: click.Context,
    run_id: str,
    candidate_id: str | None,
    limit: int,
    output_path: Path | None,
    output_format: str,
    json_output: bool,
) -> None:
    """Render a vulnerability evidence ledger for a run or candidate."""
    try:
        validate_run_id(run_id)
        orchestrator = Orchestrator(config_path=ctx.obj["config"])
        run_dir = Path(orchestrator.config["paths"]["runs"]) / run_id
        orchestrator.policy.check_path(run_dir)
        if output_path is not None:
            output_path = output_path.resolve()
            orchestrator.policy.check_path(output_path.parent)
        ledger = build_evidence_ledger(
            run_dir,
            candidate_id=candidate_id,
            limit=None if limit == 0 else limit,
        )
    except Exception as exc:  # noqa: BLE001
        structlog.get_logger().error("explain_failed", error=str(exc))
        raise click.ClickException(str(exc)) from exc

    if output_format == "markdown":
        rendered = render_ledger_markdown(ledger)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
        click.echo(rendered)
        return

    if output_path:
        from fsa.utils.jsonio import save_json

        save_json(output_path, ledger)
    _emit(ledger, True if json_output else True)


@main.command()
@click.argument("run_id")
@click.option("--json-output", is_flag=True)
@click.pass_context
def resume(ctx: click.Context, run_id: str, json_output: bool) -> None:
    """Resume an interrupted run from its first incomplete stage."""
    try:
        state = Orchestrator(config_path=ctx.obj["config"]).resume(run_id)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(str(exc)) from exc
    _emit(
        {
            "status": state["status"],
            "run_id": state["run_id"],
            "current_stage": state["current_stage"],
        },
        json_output,
    )
    if state["status"] != "done":
        raise click.exceptions.Exit(2)


if __name__ == "__main__":
    main()
