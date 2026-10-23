# BOND 外部分析器 — Benchmark 与接入说明

> 工具定位：约束导向定向验证，尝试为 KLEE 保活候选取得真实仿真响应证据（CONSTRAINED_VALIDATION 阶段）
> 安全模型：仅 `emulation` 目标 + 私有网段，PoC 必经 `sanitize_poc`

## 1. 本目录结构

```
benchmarks/external/bond/
  README.md            # 本文件
  comparison.md        # 与上游 BOND 的能力对照 + 降级映射
  plan_a_assessment.md # Plan A（上游 BOND 真机）可行性评估与为何走 Plan B
  raw/                 # 真实运行落盘区（待有公网与 Docker 的目标机补跑）
    README.md
```

## 2. 实现状态

| 项目 | 状态 |
|---|---|
| runner / parser / adapter / registry 集成 | ✅ 完成（代码+单测） |
| mini-BOND 三件套（M1/M2/M3 + scheduler） | ✅ 完成（代码+单测） |
| 6 类产物解析（action_find/constraints/fuzz_log/crash/timeout/version-diff） | ✅ 完成（单测 6 分支） |
| 私有网段安全闸（4 道硬闸，零出站保证） | ✅ 完成（单测覆盖） |
| 统一 PoC 脱敏器 `sanitize_poc` | ✅ 完成（红线全覆） |
| KLEE 保活候选 → BOND 验证闭环 | ✅ 完成（接口连通，真实传输由本机回环服务单测） |
| SKILL + 文档 | ✅ 完成 |
| 真实 fuzz 运行（仿真器/真机） | ⚠️ 未跑（待有公网与 Docker 的目标机补跑） |

## 3. 仿真运行（当前未跑）

开发机没有可用的仿真环境，**真实 fuzz 尚未跑**。代码与契约已就绪：

- 机器上置 `config/dev.yaml` 的 `bond.authorized/local_lab/baseline_ready=true`、`simulate=false`、`target_ip=192.168.x.x`（私有）。
- 准备可达的隔离仿真 HTTP 服务；需要入口图时另行安装 Ghidra headless 并设 `use_ghidra=true`。
- `scripts/run_external.py --tool bond --run-dir <dir>` 直接起，无需改代码。
- 真实 `Bond_result/`、`fuzz_log/` 落盘到 `benchmarks/external/bond/raw/`。

## 4. 红线（硬性要求）

1. **绝不打真机**：代码层硬断言 `target=emulation` + `is_private_ip`，违反即零出站。
2. **PoC 必脱敏**：`poc_sanitized==false` 的 finding 直接丢弃，不进 `fused.json`。
3. **不伪造触发**：模拟模式直接跳过；真实响应没有标记时 `triggered=false`，宁可漏报不误报。
