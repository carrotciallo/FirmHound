# AGENTS.md — 工程约定（给所有 AI 代理 / 协作者）

FirmHound（固件猎犬）：IoT 固件漏洞挖掘自动化流水线。本文件只写约束，不写介绍；
背景与用法见 `README.md`，架构细节见 `docs/`。`CLAUDE.md` 与本文件必须同步修改。

## 0. 环境前提

- **只支持 Linux 原生环境，且不绑定发行版**（Debian/Ubuntu、Fedora/RHEL、Arch、openSUSE、
  Alpine 容器均需可用）。Windows、WSL 适配层已移除，不要再引入路径翻译、`.bat` 壳、
  `wsl -d ...` 之类的代码或文档。
- 文档里写安装步骤时不要只给 `apt`：按发行版并列给出，或指向 `README.md` 的依赖矩阵。
- Python 3.11–3.13（上限由 PyO3 依赖决定，3.14 暂不支持）；一律用项目内的 `.venv`，
  不要往系统 Python 装包。入口是 `make`：
  `make dev` 建环境并 editable 安装，其余目标都走 `.venv/bin/python`。
- 解包与动态验证依赖系统工具：`binwalk`、`unsquashfs`、`sasquatch`、`qemu-*`。
  缺失时工具必须降级，不得让主链路崩。

## 1. 常用命令

```bash
make dev        # 建 .venv + 装依赖 + editable 安装
make doctor     # 环境自检（发行版 / 路径 / Schema / 工具）
make test       # 单元测试（CI 主门）
make test-all   # 单元 + 宿主集成（缺工具自动 skip）
make lint       # ruff
make smoke      # 走正式 CLI 的最小冒烟

# 等价的手动写法：.venv/bin/python scripts/dev.py <test|lint|smoke>

fsa analyze <firmware|rootfs> --input-type rootfs \
  --authorization-holder "设备所有者" --depth standard --run-id hunt1
fsa explain <run-id> --format markdown
fsa status <run-id> ; fsa resume <run-id>
fsa resume <run-id> --from-stage REPORT   # 已完成的 run 也可回退重跑某阶段及后续
```

## 2. 代码结构与职责边界

| 路径 | 职责 | 不要做的事 |
|---|---|---|
| `fsa/cli.py` | click 命令组，仅做参数解析与结果输出 | 不写业务逻辑 |
| `fsa/orchestrator/` | 阶段机、任务卡、状态持久化、反证审查、受控 Agent 循环 | 不直接调用系统工具 |
| `fsa/runtime/` | 运行时适配（offline / openai_compatible）、工具注册表、Skill 加载 | 不伪造模型结论 |
| `tools/` | 确定性分析工具（纯函数优先，可单测） | 不做流程编排 |
| `schemas/` | 跨阶段数据契约 | 不绕过校验 |
| `config/` | `dev.yaml` / `models.yaml` / `safety.yaml` | 不硬编码路径与密钥 |
| `skills/` | 领域知识与执行契约（给模型/人看） | 不写可执行代码 |

新增分析能力时：先定 Schema → 写 `tools/<domain>/` 的纯函数 → 在 `tools/registry/*.yaml`
注册 → 由 `Planner.build_plan` 的 `stage_configs` 绑定到阶段。**不要**在 `engine.py` 里写特例分支。

## 3. 硬约束（违反即视为 bug）

1. **状态契约**：每个被注册的工具必须返回 dict，且带 `status ∈ {ok, degraded, failed, partial, skipped}`
   （或失败时 `failed/unsafe`）。引擎据此决定继续 / 回退 / 中止，见 `fsa/orchestrator/engine.py::_execute_stage`。
   抛异常会被兜底成 `error`，等同于失败——**不要靠抛异常做流程控制**。
2. **Schema 先行**：跨阶段产物必须能被 `schemas/*.schema.json` 校验；改 Schema 必须同步
   `schemas/examples/`，否则 `fsa doctor` 与 CI 会红。
3. **安全红线**：`config/safety.yaml` 中的路径白名单、命令黑名单、私网限制不可绕过。
   所有文件路径先过 `PolicyEngine.check_path`；动态验证目标必须是私网 IP；
   任何 PoC 出栈前必须过 `tools/external/bond/sanitize.py::sanitize_poc`。
4. **不编造**：缺工具、缺数据、超时 → 返回 `degraded/skipped/partial` 并写 `limitation`。
   禁止生成"看起来合理"的模型结论、反编译结果或验证结论。
5. **证据可追溯**：结论必须能指回 `evidence/ev-*.json`；候选必须带 `counterevidence`
   与 `decisive_missing_fact`。新增判断逻辑时同时写反证，而不只是加分证据。
6. **Agent 边界**：`AGENT_LOOP` 默认关闭；Blind Run 强制禁用；模型只能对规则筛选出的
   合法动作排序/选择，不得生成工具名、路径、参数或漏洞结论；Agent 动作不得修改
   `conclusion_category` / `status` / `risk_level`。
7. **幂等与续跑**：阶段产物写到 `runs/<run_id>/artifacts/`，已存在则覆盖为最新且可重复执行；
   中断后 `fsa resume` 必须能从第一个未完成阶段继续；`--from-stage` 回退前必须备份
   `run_state.json`，且回退只影响目标阶段及其后续。

## 4. 改动守则

- 修 bug 先写/改测试；`tests/unit` 必须全绿，`ruff check fsa tools scripts tests` 必须无告警。
- 不要在测试里依赖真实固件、Docker、KLEE、Ghidra；用 `tests/fixtures/elf_builder.py` 合成 ELF。
- 日志用 `structlog`（JSONL），不要 `print`（`scripts/` 下的命令行脚本可例外）。
- 外部工具调用一律经 `fsa/utils/proc.run_command`（永不抛异常、有超时、可注入 `env`）；
  解析工具输出时把 locale 固定为 `LC_ALL=C`，否则中文环境下字段名会被本地化。
- 文档与代码同步：改了阶段、Schema、配置项或安全边界，必须同时更新 `README.md` 与相关 `docs/`。

## 5. 提交前检查

```bash
make lint
make test
make doctor
```

三项都干净再提交。提交信息用 `feat: / fix: / docs: / refactor: / test:` 前缀。

**提交时禁止 agent 署名**，这是硬性约定：

- commit message 里不写 `Co-Authored-By: Claude / Codex / Copilot` 之类的共同作者行；
- 不写 `Generated with ...`、`Made by ...`、`🤖`、工具名、模型名等尾注；
- `git commit` 不加 `--author`，作者信息用本机配置的开发者身份；
- 需要说明改动来源时写内容本身（改了什么、为什么改），不写"由谁生成"。
