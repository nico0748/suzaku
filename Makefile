.PHONY: help install test lint format typecheck check clean

PY ?= python3

help:
	@echo "Suzaku — Phase 1 MVP"
	@echo ""
	@echo "  make install     # pip install -e .[dev]"
	@echo "  make test        # pytest"
	@echo "  make lint        # ruff check"
	@echo "  make format      # ruff format"
	@echo "  make typecheck   # mypy strict"
	@echo "  make check       # lint + typecheck + test"
	@echo "  make clean       # remove caches"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests

format:
	$(PY) -m ruff format src tests

typecheck:
	$(PY) -m mypy src

check: lint typecheck test

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
