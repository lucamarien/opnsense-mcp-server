.PHONY: lint format format-check typecheck test test-domain security audit validate clean install build docker

install:  ## Install project with dev dependencies
	pip install -e ".[dev]"

lint:  ## Run ruff linter (includes bandit security rules)
	ruff check src/ tests/

format:  ## Format code with ruff
	ruff format src/ tests/

format-check:  ## Check formatting without modifying files
	ruff format --check src/ tests/

typecheck:  ## Run mypy strict type checking
	mypy src/

test:  ## Run test suite
	pytest -v --tb=short

test-domain:  ## Run tests for a specific domain (usage: make test-domain DOMAIN=system)
	pytest tests/test_tools/test_$(DOMAIN).py -v --tb=long
	ruff check src/opnsense_mcp/tools/$(DOMAIN).py
	mypy src/opnsense_mcp/tools/$(DOMAIN).py

security:  ## Run security-specific checks
	ruff check src/ --select S105,S106,S107 --no-fix
	ruff check src/ --select S501 --no-fix

audit:  ## Run dependency vulnerability audit
	pip-audit

validate: lint format-check security typecheck test audit  ## Run full CI pipeline locally
	@echo "All checks passed!"

build:  ## Build wheel and sdist
	python -m build

docker:  ## Build Docker image locally
	docker build -t opnsense-mcp-server .

clean:  ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
