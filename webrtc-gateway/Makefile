# Makefile for webrtc-gateway
# Node.js WebRTC Gateway Server for FGCom-mumble

# Project configuration
PROJECT_NAME = fgcom-mumble-webrtc-gateway
NODE_VERSION = 18
NPM = npm
NODE = node

# Default target
all: install build

# Install dependencies
install:
	$(NPM) install

# Build the project
build: install
	$(NPM) run build

# Start the gateway server
start: build
	$(NPM) start

# Start in development mode
dev: install
	$(NPM) run dev

# Run tests
test: install
	$(NPM) test

# Clean node_modules and build artifacts
clean:
	rm -rf node_modules
	rm -rf dist
	rm -rf build
	rm -f package-lock.json

# Clean everything including logs
distclean: clean
	rm -rf logs
	rm -f *.log
	rm -f gateway.pid

# Install dependencies and build
install-deps: install build

# Check Node.js version
check-version:
	@echo "Checking Node.js version..."
	@node --version
	@echo "Required: v$(NODE_VERSION)+"

# Run with specific environment
start-prod: build
	NODE_ENV=production $(NPM) start

start-dev: install
	NODE_ENV=development $(NPM) run dev

# Health check
health:
	@echo "Checking gateway health..."
	@if [ -f gateway.pid ]; then \
		echo "Gateway PID: $$(cat gateway.pid)"; \
		ps -p $$(cat gateway.pid) > /dev/null && echo "Gateway is running" || echo "Gateway is not running"; \
	else \
		echo "No PID file found"; \
	fi

# Stop gateway
stop:
	@if [ -f gateway.pid ]; then \
		kill $$(cat gateway.pid) 2>/dev/null && echo "Gateway stopped" || echo "Gateway was not running"; \
		rm -f gateway.pid; \
	else \
		echo "No PID file found"; \
	fi

# Restart gateway
restart: stop start

# Show logs
logs:
	@if [ -f gateway.log ]; then \
		tail -f gateway.log; \
	else \
		echo "No log file found"; \
	fi

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Install dependencies and build"
	@echo "  install      - Install npm dependencies"
	@echo "  build        - Build the project"
	@echo "  start        - Start the gateway server"
	@echo "  dev          - Start in development mode"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean node_modules and build artifacts"
	@echo "  distclean    - Clean everything including logs"
	@echo "  install-deps - Install dependencies and build"
	@echo "  check-version- Check Node.js version"
	@echo "  start-prod   - Start in production mode"
	@echo "  start-dev    - Start in development mode"
	@echo "  health       - Check gateway health"
	@echo "  stop         - Stop gateway"
	@echo "  restart      - Restart gateway"
	@echo "  logs         - Show logs"
	@echo "  help         - Show this help"

.PHONY: all install build start dev test clean distclean install-deps check-version start-prod start-dev health stop restart logs help
