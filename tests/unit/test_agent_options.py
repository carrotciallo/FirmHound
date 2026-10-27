"""Agent option merging, tier gating, and blind hard-disable."""

from __future__ import annotations

import jsonschema
import pytest

from fsa.orchestrator.agent_options import resolve_agent_options


def test_defaults_are_disabled() -> None:
    options = resolve_agent_options({})
    assert options["enabled"] is False
    assert options["tier"] == "standard"
    assert options["requested_tier"] == "standard"
    assert options["disabled_reason"] == "not requested"


def test_cli_override_beats_config() -> None:
    options = resolve_agent_options({"enabled": True}, {"enabled": False})
    assert options["enabled"] is False


def test_blind_forces_disable_even_when_requested() -> None:
    options = resolve_agent_options({"enabled": True}, {"enabled": True}, blind=True)
    assert options["enabled"] is False
    assert options["disabled_reason"] == "blind"
    assert any("blind" in item for item in options["limitations"])


def test_dynamic_tier_requires_authorized_emulation() -> None:
    options = resolve_agent_options(
        {"enabled": True, "tier": "dynamic", "dynamic": {"enabled": True}}
    )
    assert options["tier"] == "standard"
    assert options["requested_tier"] == "dynamic"
    assert any("allow-emulation" in item for item in options["limitations"])


def test_dynamic_tier_allowed_with_authorization() -> None:
    options = resolve_agent_options(
        {"enabled": True, "tier": "dynamic", "dynamic": {"enabled": True}},
        allow_emulation=True,
    )
    assert options["tier"] == "dynamic"


def test_external_tier_requires_both_switches() -> None:
    options = resolve_agent_options(
        {"enabled": True, "tier": "external", "external": {"enabled": True}}
    )
    assert options["tier"] == "standard"
    assert options["requested_tier"] == "external"


def test_external_tier_allowed_when_klee_enabled() -> None:
    options = resolve_agent_options(
        {
            "enabled": True,
            "tier": "external",
            "external": {"enabled": True, "klee": {"enabled": True}},
        },
        external_enabled=True,
    )
    assert options["tier"] == "external"


def test_invalid_tier_rejected() -> None:
    with pytest.raises(ValueError):
        resolve_agent_options({"tier": "all"})


def test_out_of_range_rejected() -> None:
    with pytest.raises(jsonschema.ValidationError):
        resolve_agent_options({"max_steps": 0})


def test_unknown_key_rejected() -> None:
    with pytest.raises(jsonschema.ValidationError):
        resolve_agent_options({"unexpected": True})


def test_progress_defaults_are_visible() -> None:
    options = resolve_agent_options({})
    assert options["progress"] == {
        "every_steps": 10,
        "show_tokens": True,
        "show_model": False,
    }


def test_progress_overrides_merge_with_defaults() -> None:
    options = resolve_agent_options(
        {},
        {"progress": {"every_steps": 25, "show_model": True}},
    )
    assert options["progress"] == {
        "every_steps": 25,
        "show_tokens": True,
        "show_model": True,
    }


def test_progress_out_of_range_rejected() -> None:
    with pytest.raises(jsonschema.ValidationError):
        resolve_agent_options({}, {"progress": {"every_steps": 0}})
