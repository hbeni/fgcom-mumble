# Makefile for edge_case_coverage_tests test suite
# This Makefile provides consistent build management for edge_case_coverage_tests tests
# Uses CMake for building (existing system)

# Test suite name
TEST_NAME = edge_case_coverage_tests
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
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_output=xml:coverage.xml

# Run with valgrind
test-valgrind: build
	cd $(BUILD_DIR) && valgrind --leak-check=full ./$(TEST_NAME)

# Run with address sanitizer
test-asan: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)

# Run with thread sanitizer
test-tsan: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)

# Clean and rebuild
rebuild: clean build

# Install dependencies (if needed)
deps:
	@echo "Dependencies should be installed at system level"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the test suite (default)"
	@echo "  build        - Build using CMake"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-filter  - Run tests with filter (use FILTER=pattern)"
	@echo "  test-coverage- Run tests with coverage output"
	@echo "  test-valgrind- Run tests with valgrind"
	@echo "  test-asan    - Run tests with address sanitizer"
	@echo "  test-tsan    - Run tests with thread sanitizer"
	@echo "  clean        - Clean build directory"
	@echo "  rebuild      - Clean and rebuild"
	@echo "  deps         - Install dependencies"
	@echo "  help         - Show this help"

# Phony targets
.PHONY: all build test test-verbose test-filter test-coverage test-valgrind test-asan test-tsan clean rebuild deps help
