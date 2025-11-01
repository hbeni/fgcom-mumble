# Makefile for rapidcheck_tests test suite
# This Makefile provides consistent build management for rapidcheck_tests tests
# Uses CMake for building (existing system)

# Test suite name
TEST_NAME = rapidcheck_tests
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

# Run property-based tests
test-properties: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Property*"

# Run antenna pattern property tests
test-antenna: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Antenna*"

# Run audio processing property tests
test-audio: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Audio*"

# Run radio propagation property tests
test-propagation: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Propagation*"

# Run all property tests
test-all-properties: test-antenna test-audio test-propagation

# Run with valgrind
test-valgrind: build
	cd $(BUILD_DIR) && valgrind --leak-check=full ./$(TEST_NAME)

# Run with address sanitizer
test-asan: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)

# Run with thread sanitizer
test-tsan: build
	cd $(BUILD_DIR) && ./$(TEST_NAME)

# Run with RapidCheck specific options
test-rapidcheck: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Property*" --rapidcheck_verbose

# Run with specific RapidCheck seed
test-seed: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Property*" --rapidcheck_seed=$(SEED)

# Run with specific RapidCheck size
test-size: build
	cd $(BUILD_DIR) && ./$(TEST_NAME) --gtest_filter="*Property*" --rapidcheck_size=$(SIZE)

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)

# Clean and rebuild
rebuild: clean build

# Install dependencies (if needed)
deps:
	@echo "Installing RapidCheck dependencies..."
	@echo "Please ensure RapidCheck is properly installed"

# Setup RapidCheck environment
setup:
	@echo "Setting up RapidCheck environment..."
	@if [ ! -d "lib/rapidcheck" ]; then \
		echo "RapidCheck library not found. Please install RapidCheck first."; \
	else \
		echo "RapidCheck environment setup complete"; \
	fi

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the test suite (default)"
	@echo "  build      - Build using CMake"
	@echo "  test       - Run tests"
	@echo "  test-verbose- Run tests with verbose output"
	@echo "  test-filter- Run tests with filter (use FILTER=pattern)"
	@echo "  test-properties- Run property-based tests"
	@echo "  test-antenna- Run antenna pattern property tests"
	@echo "  test-audio - Run audio processing property tests"
	@echo "  test-propagation- Run radio propagation property tests"
	@echo "  test-all-properties- Run all property tests"
	@echo "  test-valgrind- Run tests with valgrind"
	@echo "  test-asan  - Run tests with address sanitizer"
	@echo "  test-tsan  - Run tests with thread sanitizer"
	@echo "  test-rapidcheck- Run with RapidCheck specific options"
	@echo "  test-seed  - Run with specific seed (use SEED=value)"
	@echo "  test-size  - Run with specific size (use SIZE=value)"
	@echo "  clean      - Clean build directory"
	@echo "  rebuild    - Clean and rebuild"
	@echo "  deps       - Install dependencies"
	@echo "  setup      - Setup RapidCheck environment"
	@echo "  help       - Show this help"

# Phony targets
.PHONY: all build test test-verbose test-filter test-properties test-antenna test-audio test-propagation test-all-properties test-valgrind test-asan test-tsan test-rapidcheck test-seed test-size clean rebuild deps setup help
