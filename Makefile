# 开发快捷命令。`make help` 列出全部目标。
PY ?= python
SOURCES := voxhound tests scripts

.DEFAULT_GOAL := help
.PHONY: help install install-gui test cov lint fmt demo run gui shots hpack pcap clean

help:  ## 显示帮助
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## 以可编辑模式安装引擎与开发工具
	$(PY) -m pip install -e ".[dev]"

install-gui:  ## 额外安装 Qt 桌面端依赖
	$(PY) -m pip install -e ".[gui]"

test:  ## 运行测试（仅引擎，不需要 Qt）
	$(PY) -m pytest -q

cov:  ## 运行测试并输出覆盖率
	$(PY) -m pytest -q --cov=voxhound --cov-report=term-missing

lint:  ## 静态检查（含格式）
	$(PY) -m ruff check $(SOURCES)
	$(PY) -m ruff format --check $(SOURCES)

fmt:  ## 自动修复并统一格式
	$(PY) -m ruff check $(SOURCES) --fix
	$(PY) -m ruff format $(SOURCES)

demo:  ## 运行内置模拟器并输出全部格式
	$(PY) -m voxhound demo --report out/demo-report.html --json out/demo.json \
		--markdown out/demo.md --csv out/flows.csv --ndjson out/events.ndjson \
		--store out/demo.db --artifacts out/artifacts --write out/demo.pcap

run:  ## 启动桌面端
	$(PY) -m voxhound gui

gui: run

pcap:  ## 只写出模拟抓包（可作夹具）
	$(PY) -m voxhound demo --quiet --write out/demo.pcap

shots:  ## 从真实会话重新生成 README 截图
	$(PY) scripts/screenshot.py docs/screenshots

hpack:  ## 从 RFC 7541 重建 HPACK Huffman 表
	$(PY) scripts/gen_hpack_huffman.py

clean:  ## 清理构建与测试产物（不会碰抓包）
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage htmlcov out
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
