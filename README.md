<div align="center">

# FirmHound 固件猎犬

**IoT 固件漏洞挖掘自动化流水线** · 解包 → 攻击面 → 二进制分析 → 静态审计 → 十维评分 → 反证验证 → 动态验证 → 证据报告

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-2F6FAD)](#环境配置linux)
[![Tests](https://img.shields.io/badge/tests-339%20passed%20%7C%201%20skipped-1D9E75)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CVE Benchmark](https://img.shields.io/badge/benchmark-9%20CVEs-534AB7)](benchmarks/CVEs)
[![Skills](https://img.shields.io/badge/skills-9%20packs-0F6E56)](skills)

*本地运行，默认离线；工具缺失时降级，不中断主链*

</div>

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [快速开始（60 秒）](#快速开始60-秒)
- [系统架构](#系统架构)
- [环境配置（Linux）](#环境配置linux)
- [拿到固件后怎么做（完整流程）](#拿到固件后怎么做完整流程)
  - [第 1 步 · 放置固件](#第-1-步--放置固件)
  - [第 2 步 · 解包固件](#第-2-步--解包固件)
  - [第 3 步 · 静态分析](#第-3-步--静态分析)
  - [第 4 步 · 解读报告](#第-4-步--解读报告)
  - [第 5 步 · 人工审计（10 问）](#第-5-步--人工审计10-问)
  - [第 6 步 · 动态验证（可选）](#第-6-步--动态验证可选)
- [CLI 命令参考](#cli-命令参考)
- [配置说明](#配置说明)
- [项目结构](#项目结构)
- [Skill 体系](#skill-体系)
- [评分与结论模型](#评分与结论模型)
- [安全与合规](#安全与合规)
- [测试](#测试)
- [常见问题（FAQ）](#常见问题faq)
- [文档导航](#文档导航)
- [许可证](#许可证)

---

## 项目简介

**FirmHound（固件猎犬）** 是面向 IoT 固件漏洞挖掘的命令行流水线。解包、攻击面排查、二进制分析、静态数据流审计、风险评分、反证验证、动态验证、报告生成串成一条链：阶段机负责调度与恢复，Skill 提供判断规则，Python 工具负责确定性执行。

**设计目标**：不依赖 CVE 特征硬编码，靠通用规则和可复用 Skill 在未见过的固件上完成首轮筛查。

命名取自 **Firm**（Firmware）+ **Hound**（猎犬），指在固件里循迹追踪。

## 核心特性

| 特性 | 说明 |
|---|---|
| 🐾 全流程自动化 | M0–M14 模块化，阶段机驱动（`fsa/orchestrator/engine.py`），支持断点续跑 |
| 🎯 零 CVE 先验 | 通用规则 + Skill 知识驱动，不硬编码 CVE 特征，适配未见过的固件 |
| 🐍 纯 Python 分析 | pyelftools + capstone 解析 ELF，Linux 原生运行，不强制依赖 Ghidra/objdump |
| 🔌 双运行时 | `offline`（确定性离线规则，不生成模型结论） / `openai_compatible`（OpenAI 兼容端点） |
| 🛡️ 反证优先验证 | 10 问清单 + 12 条硬规则，五分类结论模型 |
| 📊 十维风险评分 | P-I-U-D-C-S-W-K-V-T 十维、满分 30，阈值分级 CRITICAL/HIGH/MEDIUM/LOW |
| 🔒 动态验证安全门 | 四项硬门（AUTHORIZED / LOCAL_LAB / PRIVATE_NETWORK / BASELINE_READY），仅无害探针 |
| 📜 证据链可审计 | EvidenceStore / DecisionStore 全量落盘，报告 22 节骨架，静态结论保留反证与限制 |
| ✅ 金标准回归 | `benchmarks/CVEs/` 9 个历史 CVE fixture，339 项单元测试持续守护 |

## 快速开始（60 秒）

```bash
# ① 建 .venv、装依赖、自检
make dev
make doctor
source .venv/bin/activate        # 让 fsa 进 PATH（fish: source .venv/bin/activate.fish）

# ② 分析已解包 rootfs（授权主体为必填项）
fsa analyze tmp/unpacked/squashfs-root --input-type rootfs \
  --authorization-holder "设备所有者" --depth standard --run-id hunt1

# ③ 或直接提交固件镜像（需要已配置可用的解包工具）
fsa analyze firmware_samples/router.bin --input-type firmware \
  --authorization-holder "设备所有者" --depth full
```

> ⚠️ CLI 只接受 `config/safety.yaml` 白名单内的输入路径，且只支持 Linux 原生环境。

## 系统架构

```
                    ┌──────────────────────────────────────────┐
                    │           WorkBuddy / 智能体              │
                    │  Orchestrator（阶段机 + 决策记录）         │
                    │  Planner / StateManager / HumanGate       │
                    └───────────────┬──────────────────────────┘
                                    │ 统一 Runtime Adapter
                    ┌───────────────▼──────────────────────────┐
                    │ fsa/runtime offline │ openai_compatible  │
                    │   SkillLoader / ToolRegistry / Budget     │
                    └───────────────┬──────────────────────────┘
        ┌───────────┬───────────────┼────────────────┬──────────┐
        ▼           ▼               ▼                ▼          ▼
   skills/       tools/          fsa/safety       fsa/schemas  fsa/reporting
   (01-07 流程   (确定性工具：     (安全红线         (9 个 JSON    (EvidenceStore
   知识沉淀)     解包/攻击面/      PolicyEngine)    Schema 校验)   DecisionStore)
                二进制/审计/
                仿真验证)
        └───────────┴───────────────┴────────────────┴──────────┘
                                    ▼
                          runs/<run_id>/ 产物目录
              state/ evidence/ decisions/ artifacts/ + report.md
```

**阶段机流转**：`INIT → BASELINE → UNPACK → SURFACE → BINARY_TRIAGE → DECOMPILE → STATIC_ANALYSIS → RANK → VERIFY_TOP_K → {LOCAL_VALIDATION | REPORT} → DONE`

- `UNPACK` 部分失败 → fallback 到 `BINARY_TRIAGE`（无 rootfs 也能做 ELF 级分析）
- 任一 required 阶段失败 → `ABORTED`，保留产物，可 `resume()` 续跑

---

## 环境配置（Linux）

> 支持主流 Linux 发行版，glibc 与 musl 均可：Debian/Ubuntu、Fedora/RHEL/CentOS Stream/Rocky/Alma、Arch/Manjaro、openSUSE Leap/Tumbleweed、Alpine（容器）。
> 静态分析层是纯 Python（pyelftools/capstone），不依赖系统包；解包与动态验证依赖下表的宿主工具，缺失只会让对应阶段降级，不会中断。

### 1. 依赖能力矩阵

| 依赖 | 用途 | 必需性 | Debian/Ubuntu | Fedora/RHEL 系 | Arch/Manjaro | openSUSE | Alpine |
|---|---|---|---|---|---|---|---|
| `binwalk` | 固件签名扫描与自动解包 | 必需 | `binwalk` | `binwalk` | AUR `binwalk` | `pipx install binwalk` | `pipx install binwalk` |
| `unsquashfs` | 标准 SquashFS 解包 | 必需 | `squashfs-tools` | `squashfs-tools` | `squashfs-tools` | `squashfs` | `squashfs-tools` |
| `sasquatch` | 非标准 SquashFS（多数路由固件） | 强烈建议 | 源码编译 | 源码编译 | AUR `sasquatch` | 源码编译 | 源码编译 |
| `cpio` | initramfs、部分容器格式 | 必需 | `cpio` | `cpio` | `cpio` | `cpio` | `cpio` |
| `7z` | ZIP / 7z / LZMA 容器 | 建议 | `p7zip-full` | `p7zip p7zip-plugins` | `p7zip` | `p7zip` | `p7zip` |
| `file` | 文件类型识别 | 必需 | `file` | `file` | `file` | `file` | `file` |
| `readelf` `strings` | ELF 头解析、字符串提取 | 必需 | `binutils` | `binutils` | `binutils` | `binutils` | `binutils` |
| `qemu-<arch>-static` | 用户态动态验证 | 可选 | `qemu-user-static` | `qemu-user-static` | AUR `qemu-user-static` | `qemu-linux-user` | `qemu-arm` `qemu-mipsel` … |
| `gcc` `make` | 编译 sasquatch / harness | 必需 | `build-essential` | `gcc make` | `base-devel` | `gcc make` | `build-base` |
| `python3` + venv | 运行 CLI | 必需 | `python3 python3-venv python3-dev` | `python3 python3-devel` | `python` | `python3 python3-devel` | `python3 py3-pip` |

### 2. 一条命令装齐（按发行版选一行）

```bash
# Debian / Ubuntu（含 Kali、Raspberry Pi OS）
sudo apt update && sudo apt install -y \
    binwalk squashfs-tools cpio p7zip-full file binutils \
    build-essential qemu-user-static python3 python3-venv python3-dev git pipx

# Fedora / RHEL / CentOS Stream / Rocky / AlmaLinux
sudo dnf install -y binwalk squashfs-tools cpio p7zip p7zip-plugins file binutils \
    gcc make qemu-user-static python3 python3-devel git pipx

# Arch / Manjaro（binwalk 与 qemu-user-static 在 AUR）
sudo pacman -S --needed squashfs-tools cpio p7zip file binutils base-devel python git
yay -S --needed binwalk sasquatch qemu-user-static

# openSUSE Leap / Tumbleweed
sudo zypper install -y squashfs cpio p7zip file binutils gcc make qemu-linux-user \
    python3 python3-devel git
pipx install binwalk

# Alpine（容器内）
apk add squashfs-tools cpio p7zip file binutils build-base python3 py3-pip git \
    qemu-arm qemu-aarch64 qemu-mipsel
pipx install binwalk
```

> 包名以各发行版仓库实际为准；`dnf` 在 RHEL 8 上可能需先 `subscription-manager` 或启用 EPEL。
> 容器内跑完整流程时建议用 `debian:12` / `ubuntu:24.04` 基础镜像，工具链最齐；Alpine 适合只要静态分析的轻量场景。

### 3. 安装 sasquatch（非标准 SquashFS，强烈建议）

```bash
git clone --depth 1 https://github.com/onekey-sec/sasquatch.git /tmp/sasquatch
cd /tmp/sasquatch && make && sudo make install
```

> 多数路由固件用非标准 SquashFS（`squashfs:little endian` 变体），`unsquashfs` 解不了，必须用 sasquatch。Arch 可直接从 AUR 装，免编译。

### 4. 安装 Python 与项目依赖

```bash
cd <项目路径>
make dev          # 创建 .venv + 装 requirements + pip install -e .
```

`make dev` 做三件事：`python3 -m venv .venv`、装 `requirements.txt`、以 editable 方式装本项目。
之后所有目标都在 `.venv` 内执行，不污染系统 Python；换解释器用 `make dev PYTHON=python3.12`。

手动等价写法：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
```

Debian/Ubuntu 若报 `ensurepip is not available`，先装 `python3-venv`；Alpine 装 `python3 py3-pip` 即可（musl 下 `capstone` 有预编译 wheel，`pyelftools` 纯 Python）。

只想装命令、不开发源码时，用 pipx 隔离安装：

```bash
pipx install .
```

### 5. 验证

```bash
make doctor                         # 路径、Schema、运行时、外部工具
make test                           # 单元测试
for t in binwalk unsquashfs sasquatch strings readelf 7z; do
    printf '%-12s %s\n' "$t" "$(command -v "$t" || echo MISSING)"
done
```

`fsa doctor` 的输出里会带当前发行版信息（`platform.family` / `package_manager` / `libc`）；
缺工具时按**当前发行版**给出安装提示（如 Fedora 上是 `dnf: squashfs-tools`，openSUSE 上是 `zypper: squashfs`），
并且只报 degraded，静态分析照常可用。

```bash
fsa doctor --json-output | python3 -m json.tool | sed -n '1,40p'
```

### 6. 常见问题

| 问题 | 原因 | 解决 |
|---|---|---|
| `binwalk -e` 解不出内容 | 固件加密 / 自定义头 | 换 `sasquatch` 手动解；或 `binwalk --extract --signature` 逐段看签名 |
| `ModuleNotFoundError: No module named 'capstone'` | 依赖没装 | `pip install -r requirements.txt` 重装 |
| `Permission denied` 运行脚本 | 可执行位缺失 | `chmod +x scripts/*.sh` |
| QEMU 缺架构 | 不同架构固件需不同 qemu | Debian 系装 `qemu-user-static`；Alpine 按架构装 `qemu-<arch>`；或用 `fsa` 的 `emulation` 阶段内置镜像 |
| `pip` 报 externally-managed-environment | PEP 668 保护（Debian/Ubuntu/Fedora 均有） | 用 venv 或 pipx，不要 `--break-system-packages` 污染系统 |
| `binwalk: command not found` | 未装或不在 PATH | `pipx install binwalk`；`~/.local/bin` 加进 PATH |
| `unsquashfs: command not found` | 包名随发行版不同 | Debian/Fedora/Arch/Alpine 装 `squashfs-tools`，openSUSE 装 `squashfs` |
| 解包目录里有打不开的符号链接 | 固件含指向 `/dev/null` 的悬空链接 | 属正常现象，CLI 已做符号链接容错（`fsa/utils/traverse.py`） |
| 能在 Windows / macOS 上跑吗 | 解包与仿真工具链是 Linux 原生 | 用容器或远程 Linux 主机；本项目不提供 Windows/WSL 适配层 |

---

## 拿到固件后怎么做（完整流程）

> 这是最核心的一节。假设你刚从官网下载了一个固件（如 `DIR859_FW102b03.bin`），按下面 6 步走。

### 第 1 步 · 放置固件

把固件文件放到项目目录下的 **`firmware_samples/`** 文件夹：

```
<项目根目录>/
├── firmware_samples/
│   └── DIR859_FW102b03.bin     ← 你的固件放这里
├── tmp/                        ← 解包产物（自动创建）
└── runs/                       ← 分析报告（自动创建）
```

> **为什么必须放这里？** 安全策略（`config/safety.yaml`）只允许工具读写白名单目录：`runs/`、`tmp/`、`tests/fixtures/`、`firmware_samples/`。放别处会被 `Policy rejected` 拦截。

### 第 2 步 · 解包固件

固件是"打包文件"，先解出里面的文件系统（rootfs）。

```bash
cd <项目路径>
binwalk -e -M firmware_samples/DIR859_FW102b03.bin -C tmp/unpacked
```

参数说明：
- `-e` 提取；`-M` 递归提取（固件里可能有嵌套压缩层）
- `-C` 指定输出目录

**找到 rootfs**：解包后通常出现 `tmp/unpacked/_DIR859_FW102b03.bin-0.extracted/squashfs-root`，里面应有 `bin/`、`etc/`、`usr/`、`www/`（或 `htdocs/`）等目录，**这就是分析目标 rootfs**。

```bash
# 找不到 squashfs-root 时，列出解包结果
ls tmp/unpacked/_DIR859_FW102b03.bin-0.extracted/

# 备用：sasquatch 手动解
sasquatch -d tmp/squashfs-root firmware_samples/DIR859_FW102b03.bin
```

### 第 3 步 · 静态分析

纯 Python 静态分析，直接跑：

```bash
fsa analyze "tmp/unpacked/_DIR859_FW102b03.bin-0.extracted/squashfs-root" \
  --input-type rootfs --authorization-holder "设备所有者" --run-id dir859_run1
```

运行结束会打印报告，并保存到 `runs/dir859_run1/report.md`。

### 第 4 步 · 解读报告

打开 `runs/dir859_run1/report.md`，重点看三块：

```markdown
# 固件端到端静态分析报告
- ELF 二进制: 113        ← 固件里有多少可执行程序
- 检出候选: 29           ← 疑似漏洞数量

## 检出候选（命令注入）
| 候选 | 二进制 | Sink | 分数 | 等级 |
| e2e-elf-fileaccess.cgi | htdocs\fileaccess.cgi | system | 23 | HIGH |
| e2e-elf-httpd          | sbin\httpd           | system | 23 | HIGH |
```

**判读口诀**：
- **分数**：≥24 CRITICAL / 18–23 HIGH / 12–17 MEDIUM / <12 LOW
- **Sink**：`system` / `popen` / `eval` 是命令执行信号；`strcpy` / `sprintf` 是溢出信号
- **优先审 HIGH 以上**：通常 29 个候选里只有少数是真漏洞，其余是系统程序自带的正常 `system` 调用（误报），需要人工过滤

### 第 5 步 · 人工审计（10 问）

CLI 负责"找可疑点"，**人工审计负责"确认真漏洞"**。对每个 HIGH 以上候选逐条回答：

| # | 问题 | 验证手段 |
|---|---|---|
| 1 | 输入真的来自外部？ | HTTP 参数 / Header / Cookie / SOAP？还是常量？ |
| 2 | 攻击者能控制吗？ | 请求里能否任意设置该值？ |
| 3 | 真的到危险函数了？ | 反汇编：`objdump -d fileaccess.cgi | grep -A5 "jal.*system"` |
| 4 | 中间有过滤吗？ | 白名单 / 黑名单 / 长度检查？ |
| 5 | 调用链可达吗？ | 该 handler 被 httpd 路由注册了吗？ |
| 6 | 程序启动了吗？ | `etc/init.d/` 或 `rcS` 里有它吗？ |
| 7 | 需要认证吗？ | 登录后才可达？有认证绕过？ |
| 8 | 是调试功能吗？ | 函数名含 debug/test/diag？ |
| 9 | 有平台限制吗？ | 编译开关 / 特定硬件才走此路径？ |
| 10 | 有矛盾证据吗？ | 证据库里有没有反证？ |

**辅助命令**：

```bash
strings <binary> | grep -E "system|popen|%s|reboot"   # 找命令模板
objdump -d <binary> | grep -A5 "jal.*system"           # 找调用点（MIPS）
readelf -s <binary> | grep system                       # 确认导入
```

**判定规则**：
- 10 问全过 → `confirmed-issue`（确认漏洞）
- 有认证/过滤但可绕过 → `high-confidence-candidate`
- 任一项不满足 → 降级或 `false-positive`，**别硬报**

### 第 6 步 · 动态验证（可选）

想在 QEMU 里证明漏洞真的能触发：

```bash
# qemu 用户态模式（适合单程序）
qemu-mipsel-static -L tmp/squashfs-root tmp/squashfs-root/htdocs/fileaccess.cgi
```

**红线（必须遵守）**：
- 只打自己下载的固件，目标 IP 必须私有网段（`192.168.x.x` / `10.x.x.x`）
- 只发无害 payload（`id`、`touch /tmp/lab_marker`）
- **禁止**反弹 shell、持久化、下载执行、真实攻击流量

---

## CLI 命令参考

| 命令 | 用途 | 产物 |
|---|---|---|
| `fsa doctor [--include-external-probes]` | 检查本机路径、Schema、运行时、外部工具可用性 | readiness 状态，缺外部工具时降级说明 |
| `fsa plan --task <自然语言任务> [--task-package task.zip]` | 只解析任务并展示执行计划，不运行分析 | task_card 摘要与阶段列表 |
| `fsa analyze <固件或rootfs> --authorization-holder <授权主体>` | **正式分析入口**；自动识别文件/目录 | `runs/<run-id>/` 全量证据、状态、报告 |
| `fsa unpack-diagnose <firmware>` | 诊断固件是否可解包、卡在哪一层、需要什么解密/提取材料 | 签名、魔数、提取器、建议下一步 |
| `fsa explain <run-id> [--candidate-id <id>]` | 输出漏洞证据账本，解释候选从哪里来、为何可疑、有什么反证 | 候选 source/sink/call_chain/十维评分/下一步 |
| `fsa status <run-id>` | 查看持久化阶段状态 | 当前阶段 / 成功与失败阶段 |
| `fsa resume <run-id>` | 从第一个未完成阶段恢复 | 更新原运行目录 |
| `make smoke` | 通过正式 `fsa analyze` 入口跑最小 rootfs 冒烟 | `runs/dev-smoke-*` |
| `make test` | 跑全部单元测试 | — |
| `make test-all` | 单元测试 + 主机相关集成测试 | — |
| `make ext-smoke` | 探测 SaTC/FirmRec/KLEE/BOND，可缺失降级 | JSONL 状态 |
| `make lint` | ruff 代码检查 | — |
| `make format` | 自动格式化 | — |
| `python scripts/run_pipeline.py --benchmark-fixtures ...` | 金标准回归脚本（必须显式确认 fixture 模式） | fixture 回归产物 |
| `python scripts/run_e2e.py --fixture-mode ...` | 合成样本回归（必须显式确认 fixture 模式） | 演练产物 |
| `python scripts/demo_rank.py ...` | 独立评分示例（测试用途） | 示例排序产物 |

## 配置说明

| 文件 | 作用 | 默认即用？ |
|---|---|---|
| `config/dev.yaml` | 主配置：runtime / 路径 / 日志 | ✅ |
| `config/models.yaml` | 模型运行时（offline / openai_compatible）与预算 | ✅（offline 默认） |
| `config/safety.yaml` | 安全红线（路径白名单 / 命令黑名单 / 网络白名单） | ✅（**不要改**） |
| `.env` | 模型 API Key 等环境变量（参考 `.env.example`） | 可选 |

**启用 LLM 运行时**（可选，默认离线）：

```yaml
# config/models.yaml
runtimes:
  openai_compatible:
    provider: openai
    base_url: https://api.deepseek.com/v1   # 或你的国内备案模型端点
    model: deepseek-chat
    api_key_env: OPENAI_API_KEY
```

```bash
export OPENAI_API_KEY=sk-xxx
```

## 项目结构

```
.
├── fsa/                    # 核心包：orchestrator / runtime / safety / schemas / reporting / prompts / utils
├── tools/                  # 确定性工具：firmware(解包) / filesystem / web(攻击面) / binary / analysis / emulation
├── skills/                 # Skill 知识库：00-08，父级给模型，子级给具体漏洞类/工具
├── legacy/                 # 早期单文件 Skill 与打包产物（历史存档，不参与运行）
├── schemas/                # JSON Schema + examples（含 external_finding）
├── config/                 # dev.yaml / models.yaml / safety.yaml
├── benchmarks/CVEs/        # 9 个历史 CVE 金标准 fixture
├── scripts/                # 开发、回归与环境辅助脚本（正式 CLI 位于 fsa/cli.py）
├── firmware_samples/       # ← 固件放置目录
├── tmp/                    # 解包产物
├── runs/                   # 分析报告与 JSON 产物
├── tests/                  # 单元 / 集成测试（CI 不依赖外部重型工具）
└── docs/                   # 文档（索引见 docs/README.md）
    ├── guide/              #   部署与演示、挖洞教程、CLI 测试方案
    ├── external/           #   外部分析器：总纲、数据集、真机测试
    ├── design/             #   设计决策记录
    └── archive/            #   历史运行记录：回归、检出效果、四器接入核验
```

## Skill 体系

| Skill | 领域 | 关键知识 |
|---|---|---|
| 00-orchestrator | 总控编排 | 阶段机、深度档位、决策可审计 |
| 01-unpack | 固件解包 | binwalk 降级、魔数表、rootfs 评分 |
| 02-attack-surface | 攻击面 | Web/UPnP/CGI 枚举、认证矩阵三层交叉 |
| 03-binary-decompile | 二进制分析 | 架构识别、Ghidra 降级路径 |
| 04-audit | 静态审计 | 数据流模型、七层模板、误报五规则；子技能 command-injection / buffer-overflow |
| 05-candidate-verifier | 反证审查 | 10 问清单、12 条硬判定 |
| 06-dynamic-validation | 动态验证 | L0–L3 分层、qemu-user 三大坑、安全门 |
| 07-report | 报告生成 | 22 节骨架、8 项合规扫描、脱敏 |
| 08-external-analyzers | 双轨外部分析 | SaTC/FirmRec/KLEE/BOND、汇聚、降级与先验隔离 |

## 外部分析器双轨链

`--depth full` 使用固定顺序：SaTC/FirmRec 上游分析 → FUSION → KLEE 保守剪枝 →
RANK/Verifier → mini-BOND 约束验证。FirmRec 是已知漏洞复发扫描旁路，Blind Run
会被代码强制关闭，结果独立保存且不计入零先验指标。

四器全部是可选增强：总开关和单工具开关默认关闭；缺镜像、缺 KLEE、超时或解析失败
都必须返回结构化 `status + limitation`，不能阻断主报告。安装、能力边界和复现状态见
`docs/external/README.md`。

## 评分与结论模型

**十维评分**（每维 0–3，满分 30）：`P` 预认证可达性 · `I` 输入来源 · `U` 用户可控性 · `D` 危险函数可达 · `C` 字符串拼接 · `S` Shell 上下文 · `W` 文件写入 · `K` 配置持久化 · `V` 输入验证(反向) · `T` 可测试性。

阈值：**≥24 CRITICAL / 18–23 HIGH / 12–17 MEDIUM / <12 LOW**。

**五分类结论**：`confirmed-issue`（确认） / `high-confidence-candidate`（高置信） / `false-positive`（误报） / `unknown`（未知） / `observation`（观察）。

**裁决动作**：`ACCEPT`（采纳） / `DOWNGRADE`（降级） / `REJECT`（拒绝） / `NEED_DYNAMIC`（需动态验证）。

## 安全与合规

1. **命令黑名单**：`rm -rf`、`curl/wget`、`bash -i` 一律拒绝
2. **路径白名单**：仅 `runs/`、`tmp/`、`tests/fixtures/`、`firmware_samples/`；`.env`/`secrets/` 禁止读写
3. **网络隔离**：仅私有网段与 `127.0.0.1`；动态验证目标非私有 → `ABORT_DYNAMIC_VALIDATION`
4. **动态验证四门**：`AUTHORIZED && LOCAL_LAB && PRIVATE_NETWORK && BASELINE_READY`
5. **非武器化探针**：只允许 `touch/echo/id/uname`；反弹 shell / 持久化 / 下载执行一律拒绝
6. **报告合规 8 项**：原 7 项 + 外部 PoC 必须 `poc_sanitized=true`

## 测试

```bash
make test      # 确定性单元测试（CI 主门）
make test-all  # 含可选宿主工具集成测试
make lint      # ruff 全绿
```

- 单元测试覆盖：Schema / 工具 / 编排 / Verifier / 评分 / 动态验证 / Skill 加载 / e2e
- 金标准回归：9 个 CVE fixture 全部通过 Schema 校验
- 集成测试：`tests/integration/`（解包/攻击面，依赖宿主工具缺失时自动 skip）

## 常见问题（FAQ）

**Q1：为什么只支持 Linux？**
解包（binwalk/sasquatch）与动态验证（QEMU）本身就是 Linux 工具链；移除 Windows/WSL 适配层后，代码里不再有路径翻译与 `.bat` 壳，行为更可预测。Windows 用户可用容器或远程 Linux 主机。

**Q2：解包时遇到打不开的符号链接？**
真实固件 rootfs 含指向 `/dev/null` 的悬空链接。CLI 已做符号链接容错（`fsa/utils/traverse.py`），直接分析即可，无需手动清理。

**Q3：怎么接入国产大模型？**
编辑 `config/models.yaml` 的 `openai_compatible` 段，设置 `OPENAI_API_KEY` 环境变量，`config/dev.yaml` 的 `runtime.default` 改为 `openai_compatible`。模型不可用时只返回明确的 degraded 状态，不生成替代模型结论。

**Q4：面对一个完全陌生的固件，系统能发现漏洞吗？**
能。系统不依赖 CVE 特征硬编码：`run_e2e.py` 的端到端演练证明零先验可检出植入的命令注入。标准流程 = 放置固件 → 解包 → 分析 → 人工审计 → 报告。

**Q5：报告里会不会出现可武器化内容？**
不会。Skill 07 强制 8 项合规扫描 + 脱敏渲染，真实 IP / 反弹 shell 等以占位符替代；未标记 `poc_sanitized=true` 的外部验证证据会被拒绝。

**Q6：怎么查看报告？**
`runs/<任务名>/report.md` 是 Markdown；`analysis.json` 是结构化结果。也可以把 report.md 交给 WorkBuddy 渲染成网页。

## 文档导航

完整索引见 [`docs/README.md`](docs/README.md)。按目的分四类：

| 我想… | 看这里 |
|---|---|
| 在 Linux 上从零装好并录制演示 | [`docs/guide/deployment.md`](docs/guide/deployment.md)（含 7 个演示脚本与常见问题） |
| 用 CLI 从固件挖到漏洞 | [`docs/guide/hunting-workflow.md`](docs/guide/hunting-workflow.md)（选目标 → 解包 → 分析 → 10 问审计） |
| 提交前跑一遍自测 | [`docs/guide/cli-testing.md`](docs/guide/cli-testing.md) |
| 接入 SaTC / FirmRec / KLEE / BOND | [`docs/external/README.md`](docs/external/README.md)（编排、开关、降级边界） |
| 准备外部工具的机器与固件 | [`docs/external/field-testing.md`](docs/external/field-testing.md) + [`dataset.md`](docs/external/dataset.md) |
| 查某个工具的方法与踩坑 | `skills/08-external-analyzers/<tool>/SKILL.md`（satc / firmrec / klee / bond） |
| 查某个设计为什么这么做 | [`docs/design/design-rationale.md`](docs/design/design-rationale.md) |
| 看历史运行记录 | [`docs/archive/`](docs/archive/)（只读，不代表当前实现） |

## 许可证

MIT © FirmHound Contributors

---

*FirmHound · 固件猎犬 — 用确定性工具发现漏洞，用证据链赢得信任。*
