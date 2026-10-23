"""Tests for skill loader."""

from __future__ import annotations

from pathlib import Path

from fsa.runtime import MockRuntime, SkillLoader
from tools.report.generate import _SECTIONS


def test_load_all_skills() -> None:
    loader = SkillLoader()
    skills = loader.list_skills()
    assert "01-unpack" in skills
    assert "02-attack-surface" in skills
    assert "03-binary-decompile" in skills
    assert "04-audit" in skills
    assert "04-audit-command-injection" in skills
    assert "04-audit-buffer-overflow" in skills
    assert "06-dynamic-validation-qemu-service-bootstrap" in skills
    assert "06-dynamic-validation" in skills
    assert "07-report" in skills
    assert "05-candidate-verifier" in skills
    assert "00-orchestrator" in skills


def test_every_skill_has_complete_frontmatter() -> None:
    """每个技能卡都要能按 id/title/tags 被检索，不靠目录名兜底。"""
    loader = SkillLoader()
    for name in loader.list_skills():
        skill = loader.get(name)
        assert skill.frontmatter.get("id") == name, f"{skill.path} 的 id 与加载名不一致"
        assert skill.frontmatter.get("title"), f"{skill.path} 缺 title"
        assert skill.frontmatter.get("tags"), f"{skill.path} 缺 tags"


def test_skill_directory_names_match_ids() -> None:
    """目录名与 id 保持一致（子技能允许带父级前缀）。"""
    loader = SkillLoader()
    for name in loader.list_skills():
        directory = Path(str(loader.get(name).path)).parent.name
        assert directory in name, f"{directory} 与 id {name} 不匹配"


def test_orchestrator_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("00-orchestrator")
    assert "orchestrator" in skill.frontmatter.get("tags", [])
    steps = skill.workflow_steps()
    assert any("解析任务卡" in s for s in steps)
    assert any("反证审查" in s for s in steps)
    fallbacks = skill.failure_fallbacks()
    assert any("required 阶段 error" in f["scenario"] for f in fallbacks)


def test_binary_decompile_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("03-binary-decompile")
    assert "binary" in skill.frontmatter.get("tags", [])
    fallbacks = skill.failure_fallbacks()
    assert any("Ghidra" in f["scenario"] for f in fallbacks)


def test_static_analysis_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("04-audit")
    assert "dataflow" in skill.frontmatter.get("tags", [])
    steps = skill.workflow_steps()
    assert any("路由" in s for s in steps)
    # 父级只做路由，漏洞类细节留在子技能里
    assert "04-audit-command-injection" in skill.raw
    assert "04-audit-buffer-overflow" in skill.raw


def test_get_skill_metadata() -> None:
    loader = SkillLoader()
    skill = loader.get("05-candidate-verifier")
    assert skill.frontmatter.get("id") == "05-candidate-verifier"
    assert "候选漏洞反证审查" in skill.frontmatter.get("title", "")


def test_workflow_steps() -> None:
    loader = SkillLoader()
    skill = loader.get("05-candidate-verifier")
    steps = skill.workflow_steps()
    assert any("加载输入" in s for s in steps)
    assert any("10 问审查" in s for s in steps)


def test_failure_fallbacks() -> None:
    loader = SkillLoader()
    skill = loader.get("01-unpack")
    fallbacks = skill.failure_fallbacks()
    assert any("binwalk 无签名" in f["scenario"] for f in fallbacks)


def test_acceptance_criteria() -> None:
    loader = SkillLoader()
    skill = loader.get("02-attack-surface")
    criteria = skill.acceptance_criteria()
    assert any("formexeCommand" in c for c in criteria)


def test_audit_command_injection_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("04-audit-command-injection")
    assert "command_injection" in skill.frontmatter.get("tags", [])
    steps = skill.workflow_steps()
    assert any("入口定位" in s for s in steps)


def test_dynamic_qemu_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("06-dynamic-validation-qemu-service-bootstrap")
    assert "qemu" in skill.frontmatter.get("tags", [])


def test_local_validation_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("06-dynamic-validation")
    assert "emulation" in skill.frontmatter.get("tags", [])
    steps = skill.workflow_steps()
    assert any("安全门" in s for s in steps)


def test_report_skill() -> None:
    loader = SkillLoader()
    skill = loader.get("07-report")
    assert "report" in skill.frontmatter.get("tags", [])
    steps = skill.workflow_steps()
    assert any("脱敏" in s for s in steps)
    assert any("合规扫描" in s for s in steps)


def test_report_skill_skeleton_matches_code() -> None:
    """技能卡里的报告骨架必须与 tools/report/generate.py::_SECTIONS 一致。"""
    loader = SkillLoader()
    skill = loader.get("07-report")
    lines = skill.raw.splitlines()

    start = next(i for i, line in enumerate(lines) if line.startswith("## 报告") and "骨架" in line)
    items: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        if line[:1].isdigit() and ". " in line:
            items.append(line.split(". ", 1)[1].strip())

    assert len(items) == len(_SECTIONS)
    assert items == list(_SECTIONS)


def test_offline_runtime_loads_skill_metadata_without_claiming_execution() -> None:
    runtime = MockRuntime({})
    result = runtime.run_skill("05-candidate-verifier", {})
    assert result.status == "partial"
    assert result.deliverables["mode"] == "offline_metadata_only"
    assert "workflow_steps" in result.deliverables
