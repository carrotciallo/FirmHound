# FirmHound 开发入口。只支持 Linux，所有命令都在项目内的 .venv 里跑。
#
#   make          列出可用目标
#   make dev      建 .venv、装依赖、editable 安装
#   make test     单元测试
#
# 换解释器：make dev PYTHON=python3.12

PYTHON ?= python3
VENV   ?= .venv
PY     := $(VENV)/bin/python

.DEFAULT_GOAL := help
.PHONY: help venv install dev test test-all ext-smoke lint format smoke doctor clean clean-venv

help: ## 列出可用目标
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv: $(PY) ## 创建本地虚拟环境 .venv（已存在则跳过）

$(PY):
	@$(PYTHON) -m venv $(VENV) || { \
		echo "创建 .venv 失败：$(PYTHON) 缺 venv 模块"; \
		echo "  Debian/Ubuntu: sudo apt install python3-venv"; \
		echo "  Alpine: apk add python3 py3-pip"; \
		exit 1; }
	@$(PY) -m pip install -q --upgrade pip

install: venv ## 安装运行依赖
	$(PY) scripts/dev.py install

dev: venv ## 安装依赖并 editable 安装本项目
	$(PY) scripts/dev.py dev

test: venv ## 单元测试
	$(PY) scripts/dev.py test

test-all: venv ## 单元 + 宿主集成测试（缺工具自动跳过）
	$(PY) scripts/dev.py test-all

ext-smoke: venv ## 探测四个外部分析器是否可用
	$(PY) scripts/dev.py ext-smoke

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
