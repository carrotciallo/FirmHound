# FirmHound 开发入口。只支持 Linux，所有命令都在项目内的 .venv 里跑。
#
#   make          列出可用目标
#   make setup    建 .venv、装依赖、editable 安装、跑一次自检
#   make test     单元测试
#
# 宿主依赖（binwalk / unsquashfs / sasquatch / qemu 等）按发行版安装，
# 命令与坑见 docs/guide/install.md。
# 换解释器：make setup PYTHON=python3.13
# Python 版本范围：3.11–3.13（3.14 暂不支持，PyO3 依赖要求 <=3.13）

PYTHON ?= python3
VENV   ?= .venv
PY     := $(VENV)/bin/python

.DEFAULT_GOAL := help
.PHONY: help venv install dev setup test test-all ext-smoke firmrec-doctor firmrec-smoke firmrec-venv firmrec-deps lint format smoke doctor clean clean-venv

help: ## 列出可用目标
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  宿主依赖安装：docs/guide/install.md"

venv: $(PY) ## 创建本地虚拟环境 .venv（已存在则跳过）

$(PY):
	@$(PYTHON) -c 'import sys; raise SystemExit(0 if (3, 11) <= sys.version_info[:2] <= (3, 13) else 1)' || { \
		echo "FirmHound 需要 Python 3.11–3.13（当前 $(PYTHON)；3.14 暂不支持 PyO3 依赖）"; \
		echo "  改用：make setup PYTHON=python3.13"; \
		exit 1; }
	@$(PYTHON) -m venv $(VENV) || { \
		echo "创建 .venv 失败：$(PYTHON) 缺 venv 模块或版本不在 3.11–3.13 范围"; \
		echo "  按发行版安装 Python 与 venv：docs/guide/install.md"; \
		exit 1; }
	@$(PY) -m pip install -q --upgrade pip

install: venv ## 安装运行依赖
	$(PY) scripts/dev.py install

dev: venv ## 安装依赖并 editable 安装本项目
	$(PY) scripts/dev.py dev

setup: dev ## 一条命令跑起来：装依赖 + 环境自检
	$(PY) -m fsa.cli doctor

test: venv ## 单元测试
	$(PY) scripts/dev.py test

test-all: venv ## 单元 + 宿主集成测试（缺工具自动跳过）
	$(PY) scripts/dev.py test-all

ext-smoke: venv ## 探测四个外部分析器是否可用
	$(PY) scripts/dev.py ext-smoke

firmrec-doctor: venv ## 检查 FirmRec 原生后端依赖
	$(PY) scripts/dev.py firmrec-doctor

firmrec-smoke: venv ## 对已有 run 跑一次 FirmRec（RUN_DIR=runs/<id>）
	@test -n "$(RUN_DIR)" || { echo "usage: make firmrec-smoke RUN_DIR=runs/<id>"; exit 1; }
	$(PY) scripts/dev.py firmrec-smoke --run-dir "$(RUN_DIR)"

FIRMREC_PYTHON ?= python3.9
FIRMREC_VENV ?= .venv-firmrec

firmrec-venv: ## 创建 FirmRec 专用 Python 环境
	$(FIRMREC_PYTHON) -m venv $(FIRMREC_VENV)
	$(FIRMREC_VENV)/bin/pip install -q --upgrade pip

firmrec-deps: firmrec-venv ## 安装 FirmRec 上游 Python 依赖
	$(FIRMREC_VENV)/bin/pip install -r requirements-firmrec.txt

lint: venv ## ruff 检查
	$(PY) scripts/dev.py lint

format: venv ## ruff 格式化
	$(PY) scripts/dev.py format

smoke: venv ## 用合成 rootfs 跑一次端到端
	$(PY) scripts/dev.py smoke

doctor: venv ## 环境自检（发行版、工具、Schema）
	$(PY) -m fsa.cli doctor

clean: ## 清理构建与缓存产物（保留 .venv）
	rm -rf build dist *.egg-info .pytest_cache .coverage .ruff_cache
	find fsa tools scripts tests -type d -name __pycache__ -prune -exec rm -rf {} +

clean-venv: ## 删除 .venv
	rm -rf $(VENV)
