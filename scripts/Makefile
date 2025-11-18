# Makefile for FGCom-mumble scripts
# Build and testing automation scripts

# Project configuration
SCRIPTS_DIR = $(shell pwd)
PYTHON = python3
BASH = bash

# Default target
all: check-scripts

# Check all scripts for syntax errors
check-scripts:
	@echo "Checking script syntax..."
	@for file in *.sh; do \
		if [ -f "$$file" ]; then \
			echo "Checking $$file..."; \
			$(BASH) -n "$$file" && echo "✅ $$file syntax OK" || echo "❌ $$file has syntax errors"; \
		fi; \
	done
	@for file in *.py; do \
		if [ -f "$$file" ]; then \
			echo "Checking $$file..."; \
			$(PYTHON) -m py_compile "$$file" && echo "✅ $$file syntax OK" || echo "❌ $$file has syntax errors"; \
		fi; \
	done

# Run all setup scripts
setup: check-scripts
	@echo "Running setup scripts..."
	@if [ -f "setup_environment.sh" ]; then \
		echo "Running setup_environment.sh..."; \
		./setup_environment.sh; \
	fi
	@if [ -f "setup_build_environment.sh" ]; then \
		echo "Running setup_build_environment.sh..."; \
		./setup_build_environment.sh; \
	fi

# Run testing scripts
test-scripts: check-scripts
	@echo "Running testing scripts..."
	@if [ -f "run_all_tests.sh" ]; then \
		echo "Running run_all_tests.sh..."; \
		./run_all_tests.sh; \
	fi

# Run analysis scripts
analysis: check-scripts
	@echo "Running analysis scripts..."
	@if [ -d "analysis" ]; then \
		cd analysis && for file in *.sh; do \
			if [ -f "$$file" ]; then \
				echo "Running $$file..."; \
				./$$file; \
			fi; \
		done; \
	fi

# Run validation scripts
validation: check-scripts
	@echo "Running validation scripts..."
	@if [ -d "validation" ]; then \
		cd validation && for file in *.sh; do \
			if [ -f "$$file" ]; then \
				echo "Running $$file..."; \
				./$$file; \
			fi; \
		done; \
	fi

# Run API testing scripts
api-test: check-scripts
	@echo "Running API testing scripts..."
	@if [ -d "api_testing" ]; then \
		cd api_testing && for file in *.py; do \
			if [ -f "$$file" ]; then \
				echo "Running $$file..."; \
				$(PYTHON) "$$file"; \
			fi; \
		done; \
	fi

# Install dependencies
install-deps:
	@echo "Installing script dependencies..."
	@if [ -f "requirements.txt" ]; then \
		$(PYTHON) -m pip install -r requirements.txt; \
	fi

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	@find . -name "*.tmp" -delete
	@find . -name "*.log" -delete
	@find . -name "*.pid" -delete
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Make scripts executable
make-executable:
	@echo "Making scripts executable..."
	@chmod +x *.sh
	@find . -name "*.sh" -exec chmod +x {} \;

# Check script dependencies
check-deps:
	@echo "Checking script dependencies..."
	@which bash > /dev/null && echo "✅ Bash is available" || echo "❌ Bash not found"
	@which python3 > /dev/null && echo "✅ Python3 is available" || echo "❌ Python3 not found"
	@which make > /dev/null && echo "✅ Make is available" || echo "❌ Make not found"
	@which cmake > /dev/null && echo "✅ CMake is available" || echo "❌ CMake not found"

# Run specific script category
run-setup: setup
run-test: test-scripts
run-analysis: analysis
run-validation: validation
run-api: api-test

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Check all scripts for syntax errors"
	@echo "  check-scripts    - Check all scripts for syntax errors"
	@echo "  setup            - Run setup scripts"
	@echo "  test-scripts     - Run testing scripts"
	@echo "  analysis         - Run analysis scripts"
	@echo "  validation       - Run validation scripts"
	@echo "  api-test         - Run API testing scripts"
	@echo "  install-deps      - Install script dependencies"
	@echo "  clean            - Clean temporary files"
	@echo "  make-executable  - Make scripts executable"
	@echo "  check-deps       - Check script dependencies"
	@echo "  run-setup        - Run setup scripts"
	@echo "  run-test         - Run testing scripts"
	@echo "  run-analysis     - Run analysis scripts"
	@echo "  run-validation   - Run validation scripts"
	@echo "  run-api          - Run API testing scripts"
	@echo "  help             - Show this help"

.PHONY: all check-scripts setup test-scripts analysis validation api-test install-deps clean make-executable check-deps run-setup run-test run-analysis run-validation run-api help
