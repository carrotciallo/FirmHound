"""Model-assisted action ranking with a strict, closed output contract."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import jsonschema

from fsa.prompts.manager import PromptManager
from fsa.runtime.base import AgentRuntime, Budget
from fsa.safety.policy_engine import PolicyEngine, SafetyViolation
from fsa.utils.netcheck import is_private_ip

AGENT_ACTION_CHOICE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["action_id", "reason", "confidence"],
    "properties": {
        "action_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "reason": {"type": "string", "minLength": 1, "maxLength": 200},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
}


def _bound(text: Any, limit: int = 2000) -> str:
    """Coerce untrusted candidate data to a bounded, single-line string."""
    value = str(text or "").replace("\x00", " ").strip()
    return value[:limit]


def _local_or_private(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return is_private_ip(host)
    except Exception:  # noqa: BLE001 - malformed host degrades to public policy
        return False


def _forbidden_hit(text: str, policy: PolicyEngine) -> str | None:
    limits = policy.policy.model_limits if isinstance(policy.policy.model_limits, dict) else {}
    for phrase in limits.get("forbidden_requests", []) or []:
        if str(phrase).lower() in text.lower():
            return str(phrase)
    return None


def _model_host(runtime: AgentRuntime) -> str | None:
    base_url = getattr(runtime, "base_url", None)
    if not base_url:
        return None
    return urlparse(str(base_url)).hostname


def parse_model_choice(
    content: str, allowed_ids: set[str]
) -> tuple[dict[str, Any] | None, str | None]:
    """Parse and validate one model choice; never accept extra keys or IDs."""
    text = (content or "").strip()
    if not text:
        return None, "empty model reply"
    if text.startswith("```") or "```" in text:
        return None, "markdown fences are not accepted"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc.msg}"
    if not isinstance(payload, dict):
        return None, "model reply must be a JSON object"
    try:
        jsonschema.validate(payload, AGENT_ACTION_CHOICE_SCHEMA)
    except jsonschema.ValidationError as exc:
        return None, f"schema mismatch: {exc.message}"
    action_id = str(payload["action_id"])
    if action_id not in allowed_ids:
        return None, f"action {action_id!r} is not in the eligible set"
    return payload, None


def choose_with_model(
    runtime: AgentRuntime,
    budget: Budget,
    *,
    candidate: dict[str, Any],
    missing: set[str],
    actions: list[Any],
    policy: PolicyEngine,
    allow_public: bool,
    prompts: PromptManager | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Ask the model to choose among legal actions; return ``(choice, fallback_reason)``.

    A non-``None`` second element always means "use the rule selection".
    """
    host = _model_host(runtime)
    if host and not _local_or_private(host) and not allow_public:
        return None, f"model host {host!r} is public and allow_public=false"
    if host:
        try:
            policy.check_host(host)
        except SafetyViolation as exc:
            return None, f"model host rejected: {exc.detail}"

    payload = {
        "candidate_id": _bound(candidate.get("candidate_id"), 64),
        "vuln_class": _bound(candidate.get("vuln_class_hypothesis"), 64),
        "risk_score": float(candidate.get("risk_score", 0) or 0),
        "missing_facts": sorted(missing),
        "eligible_actions": [
            {
                "action_id": spec.action_id,
                "description": spec.description,
                "cost": spec.cost,
            }
            for spec in actions
        ],
    }
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    hit = _forbidden_hit(rendered, policy)
    if hit:
        return None, f"candidate text matched forbidden model phrase: {hit!r}"

    manager = prompts or PromptManager()
    messages = manager.render_messages(
        "agent_action_ranking",
        {
            "candidate": rendered,
            "missing_facts": ", ".join(sorted(missing)),
            "eligible_actions": ", ".join(spec.action_id for spec in actions),
        },
    )
    reply = runtime.ask_model(messages, budget)
    if reply.finish_reason in {"error", "fallback", "budget_exceeded"}:
        return None, f"model unavailable: {reply.finish_reason}"
    choice, reason = parse_model_choice(reply.content, {spec.action_id for spec in actions})
    return choice, reason
