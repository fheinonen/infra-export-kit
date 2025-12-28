.PHONY: install install-dev sync lint format type-check test test-cov clean build

install:
	uv pip install -e .

install-dev:
	uv sync --dev
	uv run pre-commit install

sync:
	uv sync --dev

lint:
	uv run ruff check src tests

lint-fix:
	uv run ruff check --fix src tests

format:
	uv run ruff format src tests

format-check:
	uv run ruff format --check src tests

type-check:
	uv run mypy src

test:
	uv run pytest tests -v

test-single:
	@echo "Usage: make test-single TEST=tests/test_transformer.py::TestTerraformTransformer::test_transform_empty_state"
	uv run pytest $(TEST) -v

test-cov:
	uv run pytest tests --cov=infra_export_kit --cov-report=term-missing --cov-report=html

test-fast:
	uv run pytest tests -v -x --tb=short

clean:
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov .coverage
	rm -rf .venv
	find . -type d -name __pycache__ -exec rm -rf {} +

build:
	uv build

check: lint type-check test

all: format lint type-check test
