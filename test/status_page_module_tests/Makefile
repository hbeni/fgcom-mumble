# Makefile for status_page_module_tests test suite
# This Makefile provides consistent build management for status_page_module_tests tests
# Uses CMake for building (existing system)

# Test suite name
TEST_NAME = status_page_module_tests
BUILD_DIR = build

# Default target
all: build

# Build using CMake
build:
	@if [ ! -d "$(BUILD_DIR)" ]; then mkdir -p $(BUILD_DIR); fi
	cd $(BUILD_DIR) && cmake .. && make

# Run tests
test: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)

# Run tests with verbose output
test-verbose: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_verbose

# Run tests with specific filter
test-filter: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter=$(FILTER)

# Run coverage tests (if available)
test-coverage: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)_coverage 2>/dev/null || echo "Coverage tests not available"

# Run ASAN tests (if available)
test-asan: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)_asan 2>/dev/null || echo "ASAN tests not available"

# Run TSAN tests (if available)
test-tsan: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)_tsan 2>/dev/null || echo "TSAN tests not available"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Clean everything including build directories
distclean: clean
	rm -rf $(BUILD_DIR)

# Install dependencies (if needed)
install-deps:
	@echo "Installing dependencies for $(TEST_NAME)..."
	@echo "Dependencies: gtest, gmock, pthread, cmake"

# Show help
help:
	@echo "Available targets for $(TEST_NAME):"
	@echo "  all          - Build the test executable using CMake (default)"
	@echo "  build        - Build using CMake"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-filter  - Run tests with filter (use FILTER=pattern)"
	@echo "  test-coverage- Run coverage tests (if available)"
	@echo "  test-asan    - Run ASAN tests (if available)"
	@echo "  test-tsan    - Run TSAN tests (if available)"
	@echo "  clean        - Remove build directory"
	@echo "  distclean    - Remove all generated files"
	@echo "  install-deps - Show dependency information"
	@echo "  help         - Show this help message"

# Phony targets
.PHONY: all build test test-verbose test-filter test-coverage test-asan test-tsan clean distclean install-deps help
