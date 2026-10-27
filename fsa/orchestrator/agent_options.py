"""Resolve and validate the bounded agent-loop configuration."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from fsa.schemas.loader import validate

TIERS = ("standard", "dynamic", "external")

DEFAULT_AGENT_OPTIONS: dict[str, Any] = {
    "enabled": False,
    "tier": "standard",
    "requested_tier": "standard",
    "runtime": "",
    "max_candidates": 10,
    "max_steps": 20,
    "max_steps_per_candidate": 4,
    "max_tool_calls": 40,
    "max_seconds": 120,
    "no_progress_limit": 2,
    "max_action_failures": 3,
    "max_binary_size_mb": 64,
    "disabled_reason": None,
    "limitations": [],
    "model": {
        "enabled": "auto",
        "max_calls": 8,
        "max_tokens": 4000,
        "allow_public": False,
    },
    "progress": {
        "every_steps": 10,
        "show_tokens": True,
        "show_model": False,
    },
    "dynamic": {
        "enabled": False,
        "require_authorized_emulation": True,
        "qemu_load_check": {"timeout_s": 30},
    },
    "external": {
        "enabled": False,
        "klee": {
            "enabled": False,
            "max_time_s": 600,
            "max_forks": 64,
            "max_depth": 200,
            "solver": "z3",
        },
        "bond": {"enabled": False},
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into ``base`` and return ``base``."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = deepcopy(value)
    return base


def resolve_agent_options(
    config_agent: dict[str, Any] | None,
    overrides: dict[str, Any] | None = None,
    *,
    blind: bool = False,
    allow_emulation: bool = False,
    external_enabled: bool = False,
) -> dict[str, Any]:
    """Merge defaults, config, and CLI overrides into an effective agent block.

    The returned dict is the contract stored in ``task_card["agent"]`` and in
    ``plan["agent"]``. It always validates against ``agent_options.schema.json``.
    """
    merged = deepcopy(DEFAULT_AGENT_OPTIONS)
    _deep_merge(merged, config_agent or {})
    _deep_merge(
        merged,
        {key: value for key, value in (overrides or {}).items() if value is not None},
    )

    limitations: list[str] = []
    requested_tier = str(merged.get("tier", "standard"))
    if requested_tier not in TIERS:
        raise ValueError(f"agent.tier must be one of {TIERS}, got {requested_tier!r}")
    merged["requested_tier"] = requested_tier

    if requested_tier == "dynamic":
        dynamic = merged.setdefault("dynamic", {})
        if not dynamic.get("enabled", False):
            limitations.append("agent.dynamic.enabled=false; tier downgraded to standard")
            merged["tier"] = "standard"
        elif dynamic.get("require_authorized_emulation", True) and not allow_emulation:
            limitations.append(
                "dynamic tier requires --allow-emulation; tier downgraded to standard"
            )
            merged["tier"] = "standard"

    if requested_tier == "external":
        external = merged.setdefault("external", {})
        klee = external.get("klee", {}) if isinstance(external, dict) else {}
        if not external_enabled or not external.get("enabled", False):
            limitations.append("external.enabled=false; tier downgraded to standard")
            merged["tier"] = "standard"
        elif not klee.get("enabled", False):
            limitations.append("agent.external.klee.enabled=false; tier downgraded to standard")
            merged["tier"] = "standard"

    if blind:
        merged["enabled"] = False
        merged["disabled_reason"] = "blind"
        limitations.append("blind run: agent and model action selection are disabled")
    elif not merged.get("enabled", False):
        if merged.get("disabled_reason") is None:
            merged["disabled_reason"] = "not requested"
    else:
        merged["disabled_reason"] = None

    merged["limitations"] = limitations
    validate(merged, schema_name="agent_options")
    return merged


def effective_runtime(options: dict[str, Any], config: dict[str, Any]) -> str:
    """Return the runtime name used for model-assisted action ranking."""
    return str(options.get("runtime") or config.get("runtime", {}).get("default", "offline"))
