"""ToolRegistry must validate declared args_schema before calling a tool."""

from __future__ import annotations

from pathlib import Path

from fsa.runtime.tool_registry import ToolRegistry, ToolSpec


def _registry() -> ToolRegistry:
    registry = ToolRegistry(registry_dir=Path("/nonexistent-registry"))
    registry.register(
        ToolSpec(
            name="tools.test.run_path",
            module_path="tools.pipeline_context",
            function_name="run_path",
            description="test",
            args_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {"run_dir": {"type": "string"}},
                "required": ["run_dir"],
            },
        )
    )
    return registry


def test_missing_required_argument_is_rejected(tmp_path: Path) -> None:
    result = _registry().call("tools.test.run_path", {})
    assert result.status == "error"
    assert "invalid arguments" in result.stderr


def test_extra_argument_is_rejected(tmp_path: Path) -> None:
    result = _registry().call("tools.test.run_path", {"run_dir": str(tmp_path), "extra": True})
    assert result.status == "error"


def test_valid_arguments_reach_the_tool(tmp_path: Path) -> None:
    result = _registry().call("tools.test.run_path", {"run_dir": str(tmp_path)})
    assert result.status == "success"
    assert "result" in result.output
