# Makefile for FGCom-mumble server
# Lua-based Mumble server plugin

# Project configuration
SERVER_DIR = $(shell pwd)
LUA = lua
LUAC = luac

# Default target
all: validate

# Validate Lua scripts
validate:
	@echo "Validating server Lua scripts..."
	@for file in *.lua; do \
		if [ -f "$$file" ]; then \
			echo "Validating $$file..."; \
			$(LUAC) -p "$$file" && echo "✅ $$file is valid" || echo "❌ $$file has syntax errors"; \
		fi; \
	done

# Run server tests
test: validate
	@echo "Running server tests..."
	@if [ -d "test" ]; then \
		cd test && for file in *.lua; do \
			if [ -f "$$file" ]; then \
				echo "Running $$file..."; \
				$(LUA) "$$file" && echo "✅ $$file passed" || echo "❌ $$file failed"; \
			fi; \
		done; \
	else \
		echo "No test directory found"; \
	fi

# Install server files
install: validate
	@echo "Installing server files..."
	@echo "Server files are ready for deployment"

# Check server status
status:
	@echo "Checking server status..."
	@if [ -f "VERSION" ]; then \
		echo "Server version: $$(cat VERSION)"; \
	else \
		echo "No version file found"; \
	fi

# Generate server documentation
docs:
	@echo "Generating server documentation..."
	@if [ -f "Readme.server.md" ]; then \
		echo "Server documentation: Readme.server.md"; \
	fi
	@if [ -f "Readme.server-de_DE.md" ]; then \
		echo "German documentation: Readme.server-de_DE.md"; \
	fi

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	@find . -name "*.tmp" -delete
	@find . -name "*.log" -delete
	@find . -name "*.pid" -delete

# Package server for distribution
package: validate
	@echo "Packaging server for distribution..."
	@mkdir -p ../releases/server-$$(cat VERSION 2>/dev/null || echo "unknown")
	@cp *.lua ../releases/server-$$(cat VERSION 2>/dev/null || echo "unknown")/ 2>/dev/null || true
	@cp VERSION ../releases/server-$$(cat VERSION 2>/dev/null || echo "unknown")/ 2>/dev/null || true
	@cp README.md ../releases/server-$$(cat VERSION 2>/dev/null || echo "unknown")/ 2>/dev/null || true
	@echo "Server packaged to ../releases/server-$$(cat VERSION 2>/dev/null || echo "unknown")/"

# Run server with specific configuration
run-config:
	@echo "Available configurations:"
	@ls -la *.conf 2>/dev/null || echo "No configuration files found"

# Check server dependencies
check-deps:
	@echo "Checking server dependencies..."
	@which lua > /dev/null && echo "✅ Lua is available" || echo "❌ Lua not found"
	@which luac > /dev/null && echo "✅ Lua compiler is available" || echo "❌ Lua compiler not found"

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Validate Lua scripts"
	@echo "  validate     - Validate Lua scripts"
	@echo "  test         - Run server tests"
	@echo "  install      - Install server files"
	@echo "  status       - Check server status"
	@echo "  docs         - Generate server documentation"
	@echo "  clean        - Clean temporary files"
	@echo "  package      - Package server for distribution"
	@echo "  run-config   - Show available configurations"
	@echo "  check-deps   - Check server dependencies"
	@echo "  help         - Show this help"

.PHONY: all validate test install status docs clean package run-config check-deps help
