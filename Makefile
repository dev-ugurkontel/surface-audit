.PHONY: help install format lint typecheck test coverage security build docker clean all

PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin

help:                 ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

install: $(BIN)/python ## Install project in editable mode with dev extras
	$(BIN)/pip install -e ".[dev]"
	$(BIN)/pre-commit install

format: ## Auto-format the codebase
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

lint: ## Run linters (no changes)
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck: ## Run mypy --strict
	$(BIN)/mypy src

security: ## Run bandit static analysis
	$(BIN)/bandit -q -r src -c pyproject.toml

test: ## Run the test suite
	$(BIN)/pytest

coverage: ## Run tests with coverage HTML report
	$(BIN)/pytest --cov-report=html
	@echo "open htmlcov/index.html"

build: ## Build sdist + wheel
	$(BIN)/python -m pip install --upgrade build
	$(BIN)/python -m build

docker: ## Build docker image
	docker build -t surface-audit:local .

all: lint typecheck security test ## Run every quality gate

clean: ## Remove caches and build artifacts
	rm -rf build dist htmlcov .coverage coverage.xml \
	       .mypy_cache .ruff_cache .pytest_cache \
	       src/*.egg-info src/**/__pycache__ tests/**/__pycache__
