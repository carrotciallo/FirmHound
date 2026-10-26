"""Tests for runtime adapters."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from fsa.runtime import OfflineRuleRuntime, load_runtime
from fsa.runtime.base import Budget, ModelReply
from fsa.runtime.mock import MockRuntime
from fsa.runtime.openai_compatible import OpenAICompatibleRuntime
from fsa.utils.jsonio import load_yaml


@pytest.fixture
def models_config() -> dict[str, Any]:
    return load_yaml(Path(__file__).parent.parent.parent / "config" / "models.yaml")


def test_load_mock_runtime(models_config: dict[str, Any]) -> None:
    rt = load_runtime("mock", models_config)
    assert isinstance(rt, MockRuntime)


def test_load_offline_runtime(models_config: dict[str, Any]) -> None:
    rt = load_runtime("offline", models_config)
    assert isinstance(rt, OfflineRuleRuntime)


def test_load_openai_runtime(models_config: dict[str, Any]) -> None:
    rt = load_runtime("openai_compatible", models_config)
    assert isinstance(rt, OpenAICompatibleRuntime)
    assert rt.model == "deepseek-chat"


def test_mock_ask_model() -> None:
    rt = MockRuntime({})
    budget = Budget(max_total_tokens=1000, max_model_calls_per_stage=10)
    reply = rt.ask_model([{"role": "user", "content": "Please rank these candidates."}], budget)
    assert isinstance(reply, ModelReply)
    assert "no conclusion" in reply.content.lower()
    assert reply.metadata.get("reviewer") == "rule"
    assert reply.metadata.get("inference_performed") is False


def test_mock_ask_model_no_messages() -> None:
    rt = MockRuntime({})
    reply = rt.ask_model([], Budget())
    assert "No input" in reply.content
    assert reply.metadata["status"] == "degraded"


def test_mock_tool_safety() -> None:
    rt = MockRuntime({})
    safe = rt.call_tool("policy_check", {"command": "ls -la /tmp"})
    assert safe.status == "success"
    unsafe = rt.call_tool("policy_check", {"command": "rm -rf /"})
    assert unsafe.status == "unsafe"


def test_budget_enforcement() -> None:
    budget = Budget(max_total_tokens=10, max_model_calls_per_stage=1)
    assert budget.can_spend(5) is True
    budget.spend(5)
    assert budget.can_spend(10) is False


def test_budget_uses_cumulative_calls_and_stage_reset() -> None:
    budget = Budget(
        max_total_tokens=1000,
        max_tokens_per_stage=100,
        max_model_calls_per_stage=2,
    )
    assert budget.can_spend(40)
    budget.spend(40)
    assert budget.can_spend(40)
    budget.spend(40)
    assert budget.stage_tokens_used == 80
    assert budget.can_spend(20, calls=0)
    assert not budget.can_spend(21, calls=0)
    # Third call in the same stage is rejected by the cumulative call counter.
    assert not budget.can_spend(0, calls=1)
    budget.begin_stage()
    assert budget.stage_tokens_used == 0
    assert budget.stage_calls_used == 0
    assert budget.can_spend(0, calls=1)


def test_budget_rejects_stage_token_overflow() -> None:
    budget = Budget(max_total_tokens=1000, max_tokens_per_stage=10)
    budget.spend(10)
    assert not budget.can_spend(1)
    budget.begin_stage()
    assert budget.can_spend(1)


def test_openai_runtime_without_key() -> None:
    os.environ.pop("OPENAI_API_KEY", None)
    rt = OpenAICompatibleRuntime({"base_url": "http://localhost:8000/v1", "model": "test"})
    # Without openai package, asking should produce an error reply, not crash.
    reply = rt.ask_model([{"role": "user", "content": "hi"}], Budget())
    assert reply.finish_reason == "error"
