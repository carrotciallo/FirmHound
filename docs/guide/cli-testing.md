# CLI 自测方案

> 目的：在交付/演示前证明 CLI **可运行、可解释、可降级**，并说清哪些能力依赖真实环境
> （Docker、KLEE、仿真目标、模型网关）。全部命令在项目根目录、已激活 venv 的 Linux shell 中执行。

## 1. 环境自检

```bash
fsa doctor --json-output
fsa doctor --include-external-probes --json-output
```

通过标准：

- `paths.status=ok`、`schemas.status=ok`
- `runtime.default=offline` 时允许完全离线测试；要用在线模型时再确认 `model_api_key_present=true`
- 外部工具缺失只能是 `degraded`，命令不得异常退出（退出码为 0）

## 2. 任务理解

```bash
fsa plan \
  --task "分析厂商为 Tenda、型号 AC15 的固件，授权测试，完整分析。" \
  --firmware-path firmware_samples/AC15.bin \
  --authorization-holder team1 \
  --json-output
```

通过标准：

- 输出 `status=ok`
- 能抽出或保留 `vendor / model / depth`
- `depth=full` 时 `stages` 包含 `EXTERNAL_ANALYSIS / FUSION / SYMEX_PRUNE / CONSTRAINED_VALIDATION`
- 缺授权或缺固件时输出 `requires_human_gate=true` 并列出原因，**不会**伪造继续执行

## 3. 冒烟（走正式 CLI 入口）

```bash
make smoke
```

通过标准：

- 内部实际调用 `fsa analyze`
- 运行目录为 `runs/dev-smoke-*`
- `state/run_state.json` 中 `status=done`
- 生成 `report.md`、`final_verdict.json`、`artifacts/report_compliance.json`

## 4. 真实固件

已解包 rootfs：

```bash
fsa analyze <ROOTFS_DIR> \
  --input-type rootfs \
  --depth standard \
  --authorization-holder "<授权人或团队名>" \
  --vendor "<厂商>" --model "<型号>" \
  --json-output
```

固件镜像（需要可用的 binwalk/sasquatch）：

```bash
fsa analyze <FIRMWARE_BIN_OR_CHK> \
  --input-type firmware \
  --depth standard \
  --authorization-holder "<授权人或团队名>" \
  --json-output
```

通过标准：

- 主链 `status=done`
- `artifacts/rootfs.json` 记录输入类型与 rootfs 来源
- `artifacts/` 下依次出现 `firmware_baseline.json`、`binary_summaries.json`、`candidates.json`、
  `ranking.json`、`verdict.json`
- 报告「外部分析器结果」一节写清缺哪些工具、哪些结论因此受限，**不写假命中**

## 5. Full Depth 降级

```bash
fsa analyze <ROOTFS_DIR> --input-type rootfs --depth full \
  --authorization-holder "<授权人或团队名>" --json-output
```

通过标准（四器默认全关的情况下）：

- 仍然 `status=done`
- `artifacts/external_findings/` 存在，或阶段产物记录 `skipped/degraded` 与 `limitation`
- FirmRec 的结果不进入 `unified_candidates.json`
- 没有 `poc_sanitized=true` 的证据不能把候选确认为真漏洞

## 6. 打开真实外部工具

逐个打开 `config/dev.yaml` 的 `external.enabled` 与对应工具开关，**一次只开一个**，
排查干净再开下一个：

| 工具 | 依赖 | 备注 |
|---|---|---|
| SaTC | Docker 镜像、Ghidra/angr | 需要一个 Web 固件 rootfs |
| KLEE | `backend: local`（LLVM 16 + Z3）或 `docker` | 无源码时走 S2 harness |
| BOND | 隔离仿真目标 | 必须私有网段 IP + 授权 + baseline + 无害 marker |
| FirmRec | Docker + PostgreSQL + 已知漏洞签名 | 仅复发专项，Blind Run 必须关闭 |

通过标准：

- 可用时 `status=ok`，不可用时 `degraded/skipped` + 明确 `limitation`
- 所有 PoC/请求证据均已脱敏，不出现真实攻击载荷

## 7. 测试前需要准备

- 至少 1 个有授权分析的真实固件文件，或已解包的 rootfs 目录
- 厂商 / 型号 / 版本（不知道可留空）
- 授权说明：自有设备、实验室授权、公开固件离线分析等
- 是否允许本地隔离仿真；允许则给出仿真目标私有 IP、端口、无害 marker
- 若测在线模型：网关地址、API key 环境变量名、模型名、调用规范
- 若测 FirmRec：已知漏洞签名来源，并确认属于复发检测专项（不计入零先验指标）

## 8. 验收对照

| 关注点 | 怎么证明 |
|---|---|
| 任务理解与执行设计 | `fsa plan` 展示自然语言/压缩包 → 任务卡与阶段计划 |
| 可部署、可运行、可恢复 | `doctor` → `smoke` → `analyze` → `status` / `resume` |
| 决策逻辑与可解释性 | `decisions/`、`evidence/`、`fsa explain <run-id>`、`report.md` |
| 工具协同与扩展 | `--depth full` 展示四器开关、汇聚与降级 |
| 附加价值的数据支撑 | 真实固件 run 的 External-Only Hits、FP Prune Rate、Confirm Uplift |
