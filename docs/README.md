# FirmHound 文档索引

> 文档按**用途**分四类，不按作者、不按日期。新文档先想清楚属于哪一类，再落盘。

```
docs/
├── guide/            上手与操作：装、跑、演示、自测
├── external/         外部分析器：总纲 + 数据集 + 真机测试 + 四工具细则
├── design/           设计与交付文档纲目（01–09）
└── archive/          历史记录与已过时的规划（只读，不代表当前实现）
```

---

## 1. 按目的找

| 我想… | 文档 | 说明 |
|---|---|---|
| 在任意 Linux 发行版上装好并演示 | [`guide/deployment.md`](guide/deployment.md) | 五类发行版的依赖矩阵 → sasquatch → venv → 7 个演示脚本 → 录屏顺序 |
| 从固件挖到第一个漏洞 | [`guide/hunting-workflow.md`](guide/hunting-workflow.md) | 选目标 → 解包 → `fsa analyze` → 读报告 → 10 问人工审计 |
| 交付前做一次完整自测 | [`guide/cli-testing.md`](guide/cli-testing.md) | doctor / plan / analyze / 降级 / 安全策略的验收标准 |
| 理解外部分析器怎么编进流水线 | [`external/README.md`](external/README.md) | 固定编排顺序、开关、能力边界、诚实降级、安全红线 |
| 准备外部工具的运行环境 | [`external/field-testing.md`](external/field-testing.md) | 硬件要求、镜像、四器逐个跑通步骤与踩坑 |
| 查固件样本清单与来源 | [`external/dataset.md`](external/dataset.md) | L1/L2/L3 三档数据集、SHA256、架构、下载脚本 |
| 接入/维护某个外部工具 | [`satc.md`](external/satc.md) · [`firmrec.md`](external/firmrec.md) · [`klee.md`](external/klee.md) · [`bond.md`](external/bond.md) | 每个：目标 → 输入输出 → 执行流程 → 命令 → 验收降级 → 踩坑表 |
| 写设计 / 开发 / 测试 / 手册 / 技术报告 | [`design/`](design/) | 01–09 编号纲目，每份说清"写给谁、写什么、怎么算写到位" |
| 做技术汇报或对外介绍 | [`design/06-review-deck-outline.md`](design/06-review-deck-outline.md) · [`design/09-design-rationale.md`](design/09-design-rationale.md) | 汇报结构 + 设计取舍与常见质疑的答法 |
| 回看某次回归或盲测到底发生了什么 | [`archive/`](archive/) | 带日期的记录，**仅作历史证据，不代表当前行为** |

---

## 2. 各类文档的边界

**`guide/` 讲"人怎么用"**：面向第一次接触项目的人，命令可直接复制执行。
不写内部实现细节，不写未来计划。发行版差异只在这里列，其他文档不重复。

**`external/` 讲"这四个工具怎么接、怎么降级"**：产品级契约（顺序、开关、状态、红线）
放 `README.md`，单个工具的工程细节放各自文件。四个文件结构统一，便于对照。

**`design/` 讲"系统怎么设计、怎么实现、怎么验证"**：01–05 是设计/开发/测试/手册/技术报告的
编写纲目，06–09 是汇报材料、数据统计口径、产品化路线与设计取舍。都是提纲与要点，尚未定稿；
引用具体数字前先核对代码与 `runs/` 产物。

**`archive/` 讲"当时是什么样"**：团队分工总纲、按日期的回归/盲测记录、能力差距自查。
其中的环境、路径、开关可能与当前实现不一致（例如仍会提到 WSL），**排障时不要照抄**。

---

## 3. 维护约定

- 新增面向用户的操作文档 → `guide/`；外部工具相关 → `external/`；设计与交付类纲目 →
  `design/`；一次性的实验记录 → `archive/<主题>-YYYY-MM-DD.md`。
- 文件名用 `kebab-case` 英文，标题（H1）用中文；同一目录内不要出现两套命名风格。
- 文档里引用代码位置时写**文件 + 符号**（如 `fsa/orchestrator/engine.py::_execute_stage`），
  不要只写行号。
- 阶段顺序、Schema 字段、配置项、安全边界一旦改动，同步改本文索引涉及的那一份，
  并在 `README.md` 的项目结构里保持目录名一致。
- 被替代的文档不删除，移入 `archive/` 并在文件开头加一行"已过时，替代者是 X"。
