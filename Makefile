.PHONY: help install dev test demo serve lint docker clean

PYTHON ?= python3
OUT    ?= reports

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install runtime dependencies
	$(PYTHON) -m pip install -r requirements.txt

dev:  ## Install the package (editable) with dev + optional extras
	$(PYTHON) -m pip install -e ".[dev]"

test:  ## Run the offline test suite
	$(PYTHON) -m pytest -q

demo:  ## Run a scan against the offline stub and print the report path
	@PYTHONPATH=src $(PYTHON) -m llm_security_scanner run --target stub --out $(OUT) || true
	@echo ""
	@echo "Report ready. Open it with:"
	@echo "  open $(OUT)/report.html        # macOS"
	@echo "  xdg-open $(OUT)/report.html    # Linux"
	@echo ""
	@echo "Governance package:"
	@echo "  $(OUT)/model_card.md"
	@echo "  $(OUT)/risk_register.csv"
	@printf "\nReport path: %s\n" "$(abspath $(OUT)/report.html)"

serve:  ## Run the offline web report viewer (needs the [viewer] extra)
	@echo "Starting viewer on http://127.0.0.1:8000  (Ctrl+C to stop)"
	@PYTHONPATH=src $(PYTHON) -m llm_security_scanner serve

docker:  ## Build the Docker image
	docker build -t llm-security-scanner .

clean:  ## Remove generated artifacts and caches
	rm -rf $(OUT) .pytest_cache **/__pycache__ src/**/__pycache__ \
		build dist *.egg-info src/*.egg-info
