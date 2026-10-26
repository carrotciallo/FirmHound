"""Deterministic agent actions: facts, counterevidence, and no fabrication."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fsa.reporting.evidence_store import EvidenceStore
from fsa.utils.jsonio import save_json
from tools.audit import agent_actions


def _candidate(**overrides: Any) -> dict[str, Any]:
    candidate: dict[str, Any] = {
        "candidate_id": "cand-1",
        "binary_id": "bin-1",
        "surface_id": "surf-1",
        "entry": {"route": "/goform/x", "handler": "httpd"},
        "source": {"api": "getenv"},
        "sink": {"function": "system"},
        "call_chain": [],
        "validation": [],
        "authorization": {"required": None},
        "evidence": [],
        "counterevidence": [],
        "conclusion_category": "unknown",
        "status": "analyzing",
        "risk_level": "LOW",
    }
    candidate.update(overrides)
    return candidate


@pytest.fixture
def run(tmp_path: Path) -> Path:
    path = tmp_path / "runs" / "run-1"
    path.mkdir(parents=True)
    save_json(path / "artifacts" / "rootfs.json", {"rootfs_path": str(tmp_path / "rootfs")})
    return path


@pytest.fixture
def store(run: Path) -> EvidenceStore:
    return EvidenceStore(run)


def _summary(**overrides: Any) -> dict[str, Any]:
    payload = {
        "binary_id": "bin-1",
        "path": "bin/httpd",
        "architecture": "arm",
        "imports": ["getenv", "system"],
        "strings_summary": {"sample": ["QUERY_STRING"]},
    }
    payload.update(overrides)
    return payload


def test_cross_check_confirms_present_symbols(run: Path, store: EvidenceStore) -> None:
    candidate = _candidate()
    context = {"binary_summary": _summary()}
    outcome = agent_actions.action_cross_check_imports_strings(
        candidate, context=context, store=store, run_id=run.name
    )
    assert outcome["status"] == "ok"
    assert outcome["produced_facts"] == ["source_sink_cross_checked"]
    assert candidate["agent_facts"] == ["source_sink_cross_checked"]
    assert candidate["counterevidence"] == []
    assert outcome["evidence_ids"]


def test_cross_check_marks_missing_sink_without_fabricating(
    run: Path, store: EvidenceStore
) -> None:
    candidate = _candidate()
    context = {"binary_summary": _summary(imports=["getenv"], strings_summary={"sample": []})}
    outcome = agent_actions.action_cross_check_imports_strings(
        candidate, context=context, store=store, run_id=run.name
    )
    assert outcome["status"] == "degraded"
    assert "sink-not-imported" in candidate["counterevidence"]
    assert "source-not-imported" not in candidate["counterevidence"]


def test_cross_check_does_not_treat_generic_source_name_as_symbol(
    run: Path, store: EvidenceStore
) -> None:
    candidate = _candidate(source={"name": "http_query", "type": "http_query"})
    context = {"binary_summary": _summary()}
    outcome = agent_actions.action_cross_check_imports_strings(
        candidate, context=context, store=store, run_id=run.name
    )
    assert outcome["status"] == "ok"
    assert "source-not-imported" not in candidate["counterevidence"]
    assert any("no concrete api/string" in item for item in outcome["limitations"])


def test_startup_check_records_positive_and_negative(run: Path, store: EvidenceStore) -> None:
    candidate = _candidate()
    context = {"startup": {"grouped": {"httpd": [{"binary": "/bin/httpd"}]}}}
    outcome = agent_actions.action_check_handler_startup(
        candidate, context=context, store=store, run_id=run.name
    )
    assert outcome["status"] == "ok"
    assert candidate["agent_facts"] == ["handler_startup_checked", "handler_started"]

    negative = _candidate()
    outcome = agent_actions.action_check_handler_startup(
        negative, context={"startup": {"grouped": {}}}, store=store, run_id=run.name
    )
    assert outcome["status"] == "degraded"
    assert "handler-not-started" in negative["counterevidence"]


def test_evidence_cross_check_removes_dangling_refs(run: Path, store: EvidenceStore) -> None:
    valid = store.add(
        run_id=run.name,
        stage="STATIC_ANALYSIS",
        type="file_observation",
        observation="valid",
        tool="test",
        supports=["cand-1"],
    )
    candidate = _candidate(evidence=[str(valid["evidence_id"]), "ev-dead"])
    outcome = agent_actions.action_cross_check_evidence_store(
        candidate, context={}, store=store, run_id=run.name
    )
    assert outcome["status"] == "degraded"
    assert candidate["evidence"] == [valid["evidence_id"]]
    assert candidate["evidence_unresolved"] == ["ev-dead"]
    assert candidate["agent_facts"] == ["contradiction_checked"]


def test_recover_call_chain_uses_shared_enrichment(
    run: Path, store: EvidenceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_enrich(candidate, summary, rootfs, evidence_store, run_id, *, stage):
        candidate["call_chain"] = [
            {"addr": "0x1000", "func": "sub_1000", "note": "caller"},
            {"addr": "0x1004", "func": "system", "note": "sink"},
        ]
        item = evidence_store.add(
            run_id=run_id,
            stage=stage,
            type="decompile",
            observation="fake chain",
            tool="test",
            supports=[candidate["candidate_id"]],
        )
        candidate["evidence"].append(item["evidence_id"])

    monkeypatch.setattr(agent_actions, "_enrich_with_chain", fake_enrich)
    candidate = _candidate()
    outcome = agent_actions.action_recover_call_chain(
        candidate,
        context={"binary_summary": _summary(), "rootfs": "/tmp/rootfs"},
        store=store,
        run_id=run.name,
    )
    assert outcome["status"] == "ok"
    assert candidate["agent_facts"] == ["call_chain_reachable"]
    assert outcome["evidence_ids"]


def test_auth_hint_only_sets_required_when_confident(
    run: Path, store: EvidenceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        agent_actions,
        "classify_auth",
        lambda *args, **kwargs: SimpleNamespace(hint="auth", confidence=0.9),
    )
    candidate = _candidate()
    outcome = agent_actions.action_verify_auth_hint(
        candidate, context={"binary_summary": _summary()}, store=store, run_id=run.name
    )
    assert outcome["status"] == "ok"
    assert candidate["authorization"]["required"] is True
    assert candidate["agent_facts"] == ["auth_known"]

    monkeypatch.setattr(
        agent_actions,
        "classify_auth",
        lambda *args, **kwargs: SimpleNamespace(hint="preauth", confidence=0.5),
    )
    unresolved = _candidate()
    outcome = agent_actions.action_verify_auth_hint(
        unresolved, context={"binary_summary": _summary()}, store=store, run_id=run.name
    )
    assert outcome["status"] == "degraded"
    assert unresolved["authorization"]["required"] is None


def test_enrich_from_registration(
    run: Path, store: EvidenceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        agent_actions,
        "recover_chains",
        lambda *args, **kwargs: {"registration": {"formX": 0x1000}},
    )
    candidate = _candidate(entry={}, surface_id="unmapped-surface")
    outcome = agent_actions.action_enrich_from_recovered_handlers(
        candidate,
        context={"binary_summary": _summary(), "rootfs": "/tmp/rootfs"},
        store=store,
        run_id=run.name,
    )
    assert outcome["status"] == "ok"
    assert candidate["entry"]["handler"] == "formX"
    assert candidate["agent_facts"] == ["entry_mapped"]


def test_qemu_load_check_requires_authorization(
    run: Path, store: EvidenceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        agent_actions,
        "run_l1_load_check",
        lambda *args, **kwargs: {"status": "success", "load_ok": True, "qemu": "qemu-arm"},
    )
    candidate = _candidate()
    skipped = agent_actions.action_qemu_load_check(
        candidate,
        context={"allow_emulation": False, "rootfs": "/tmp/rootfs", "arch": "arm"},
        store=store,
        run_id=run.name,
    )
    assert skipped["status"] == "skipped"

    ok = agent_actions.action_qemu_load_check(
        candidate,
        context={"allow_emulation": True, "rootfs": "/tmp/rootfs", "arch": "arm"},
        store=store,
        run_id=run.name,
    )
    assert ok["status"] == "ok"
    assert candidate["agent_facts"] == ["dynamic_load_checked"]


def test_klee_consumes_existing_symex_only(run: Path, store: EvidenceStore) -> None:
    candidate = _candidate()
    missing = agent_actions.action_klee_feasibility(
        candidate, context={"unified_candidates": {}}, store=store, run_id=run.name
    )
    assert missing["status"] == "skipped"

    unified = {
        "candidates": [
            {
                "candidate_id": "cand-1",
                "symex": {"reason": "infeasible", "detail": "guard false"},
            }
        ]
    }
    outcome = agent_actions.action_klee_feasibility(
        candidate, context={"unified_candidates": unified}, store=store, run_id=run.name
    )
    assert outcome["status"] == "ok"
    assert "klee-infeasible" in candidate["counterevidence"]
    assert candidate["agent_facts"] == ["symex_feasibility_checked"]
