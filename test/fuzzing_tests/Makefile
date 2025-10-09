# Makefile for fuzzing_tests test suite
# This Makefile provides consistent build management for fuzzing_tests tests
# Uses CMake for building (existing system)

# Test suite name
TEST_NAME = fuzzing_tests
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

# Run AFL++ fuzzing
test-afl: build
	@echo "Running AFL++ fuzzing tests..."
	@if [ -d "afl++" ]; then \
		cd afl++ && ./run_fuzzing.sh; \
	else \
		echo "AFL++ directory not found. Please set up AFL++ first."; \
	fi

# Run Mull mutation testing
test-mull: build
	@echo "Running Mull mutation testing..."
	@if [ -d "mull" ]; then \
		cd mull && ./run_mull_tests.sh; \
	else \
		echo "Mull directory not found. Please set up Mull first."; \
	fi

# Run corpus-based fuzzing
test-corpus: build
	@echo "Running corpus-based fuzzing..."
	@if [ -d "corpus" ]; then \
		cd corpus && ./run_corpus_tests.sh; \
	else \
		echo "Corpus directory not found. Please set up corpus first."; \
	fi

# Run all fuzzing tests
test-fuzz: test-afl test-mull test-corpus

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

# Clean fuzzing outputs
clean-fuzz:
	rm -rf outputs/
	rm -rf afl++/outputs/
	rm -rf mull/outputs/

# Clean and rebuild
rebuild: clean build

# Install dependencies (if needed)
deps:
	@echo "Installing fuzzing dependencies..."
	@echo "Please ensure AFL++, Mull, and other fuzzing tools are installed"

# Setup fuzzing environment
setup:
	@echo "Setting up fuzzing environment..."
	@mkdir -p outputs
	@mkdir -p corpus
	@echo "Fuzzing environment setup complete"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the test suite (default)"
	@echo "  build        - Build using CMake"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-filter  - Run tests with filter (use FILTER=pattern)"
	@echo "  test-afl     - Run AFL++ fuzzing tests"
	@echo "  test-mull    - Run Mull mutation testing"
	@echo "  test-corpus  - Run corpus-based fuzzing"
	@echo "  test-fuzz    - Run all fuzzing tests"
	@echo "  test-valgrind- Run tests with valgrind"
	@echo "  test-asan    - Run tests with address sanitizer"
	@echo "  test-tsan    - Run tests with thread sanitizer"
	@echo "  clean        - Clean build directory"
	@echo "  clean-fuzz  - Clean fuzzing outputs"
	@echo "  rebuild      - Clean and rebuild"
	@echo "  deps         - Install dependencies"
	@echo "  setup        - Setup fuzzing environment"
	@echo "  help         - Show this help"

# Phony targets
.PHONY: all build test test-verbose test-filter test-afl test-mull test-corpus test-fuzz test-valgrind test-asan test-tsan clean clean-fuzz rebuild deps setup help
