"""Atomic run_state persistence and resume logic."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fsa.schemas.loader import validate
from fsa.utils.jsonio import load_json, save_json


class StateManager:
    """Manage run_state.json for a single analysis run."""

    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir)
        self.state_path = self.run_dir / "state" / "run_state.json"

    def init(self, task_card: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
        """Create an initial run_state and persist it."""
        state: dict[str, Any] = {
            "run_id": self.run_dir.name,
            "task_card_ref": str(self.run_dir / "state" / "task_card.json"),
            "status": "running",
            "current_stage": "INIT",
            "completed_stages": [],
            "failed_stages": [],
            "retry_count": {},
            "artifacts": {},
            "decisions": [],
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0},
            "resume_token": "init",
            "task_card": task_card,
            "plan": plan,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "metadata": {"resumed": False},
        }
        self.save(state)
        return state

    def load(self) -> dict[str, Any]:
        """Load run_state from disk, creating an empty stub if missing."""
        if not self.state_path.exists():
            return {"run_id": self.run_dir.name, "status": "missing"}
        state = load_json(self.state_path)
        validate(state, schema_name="run_state")
        return state

    def save(self, state: dict[str, Any]) -> None:
        """Persist run_state atomically and validate against schema."""
        validate(state, schema_name="run_state")
        state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_json(self.state_path, state)

    def mark_stage_complete(
        self, stage: str, artifacts: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Mark a stage as completed and merge artifacts."""
        state = self.load()
        if stage not in state["completed_stages"]:
            state["completed_stages"].append(stage)
        if stage in state["failed_stages"]:
            state["failed_stages"].remove(stage)
        state["current_stage"] = stage
        state["artifacts"] = {**(state.get("artifacts") or {}), **(artifacts or {})}
        self.save(state)
        return state

    def mark_stage_failed(self, stage: str, reason: str) -> dict[str, Any]:
        """Mark a stage as failed with a reason."""
        state = self.load()
        if stage not in state["failed_stages"]:
            state["failed_stages"].append(stage)
        state["last_error"] = {"stage": stage, "reason": reason}
        self.save(state)
        return state

    def rewind_to(
        self,
        stage: str,
        *,
        force: bool = False,
        active: bool | None = None,
    ) -> dict[str, Any]:
        """Reopen a run at ``stage`` so it and every later stage run again.

        Earlier completed stages are preserved; later stages are removed from
        ``completed_stages``. The pre-rewind state is backed up under
        ``state/run_state.rewind-*.json`` before anything is modified.

        ``active=False`` means the caller verified that no process holds the
        run lock; the stale ``running`` marker is then safe to rewind.
        ``active=None`` is unknown and keeps the conservative refusal.
        """
        state = self.load()
        stages = (state.get("plan") or {}).get("stages") or []
        if not stages:
            raise FileNotFoundError(f"Run state has no plan: {self.state_path}")
        if stage not in stages:
            raise ValueError(f"Unknown stage {stage!r}; choose from {stages}")
        if stage in {"INIT", "DONE"}:
            raise ValueError(f"Cannot rewind to {stage}; choose a real analysis stage")
        was_running = state.get("status") == "running"
        if was_running and not force and active is not False:
            raise RuntimeError(
                "Run is still marked running; stop the active process first or pass --force"
            )

        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup = self.run_dir / "state" / f"run_state.rewind-{stamp}.json"
        counter = 1
        while backup.exists():
            backup = self.run_dir / "state" / f"run_state.rewind-{stamp}-{counter}.json"
            counter += 1
        save_json(backup, state)

        index = stages.index(stage)
        completed = set(state.get("completed_stages", []))
        state["completed_stages"] = [item for item in stages[:index] if item in completed]
        state["failed_stages"] = [
            item for item in state.get("failed_stages", []) if item in stages[:index]
        ]
        last_error = state.get("last_error") or {}
        if last_error.get("stage") in stages[index:]:
            state.pop("last_error", None)
        state["status"] = "running"
        state["current_stage"] = stage
        metadata = state.setdefault("metadata", {})
        metadata["resumed"] = True
        metadata["last_rewind"] = {
            "from_stage": stage,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "backup": str(backup),
            "stale_running": bool(was_running and active is False and not force),
        }
        self.save(state)
        return state

    def resume(self) -> dict[str, Any]:
        """Return the next stage to execute based on completed stages."""
        state = self.load()
        state["metadata"] = state.get("metadata", {})
        state["metadata"]["resumed"] = True
        plan = state.get("plan", {})
        stages = plan.get("stages", [])
        completed = set(state.get("completed_stages", []))
        for stage in stages:
            if stage in {"INIT", "DONE"}:
                continue
            if stage not in completed:
                state["current_stage"] = stage
                self.save(state)
                return state
        state["current_stage"] = "DONE"
        state["status"] = "done"
        self.save(state)
        return state
