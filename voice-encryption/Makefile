# Voice Encryption Module Makefile

# Variables
BUILD_DIR = build
TEST_BUILD_DIR = tests/build
INSTALL_DIR = /usr/local
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -g
INCLUDES = -Iinclude -Isrc
LIBS = -lpthread -lm

# Default target
all: build

# Build the library
build: $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. && make

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build tests
test: $(TEST_BUILD_DIR)
	cd $(TEST_BUILD_DIR) && cmake .. && make

# Create test build directory
$(TEST_BUILD_DIR):
	mkdir -p $(TEST_BUILD_DIR)

# Run tests
run-tests: test
	cd $(TEST_BUILD_DIR) && ./voice_encryption_tests

# Run tests with verbose output
run-tests-verbose: test
	cd $(TEST_BUILD_DIR) && ./voice_encryption_tests --gtest_verbose

# Clean build directories
clean:
	rm -rf $(BUILD_DIR) $(TEST_BUILD_DIR)

# Install
install: build
	cd $(BUILD_DIR) && make install

# Uninstall
uninstall:
	rm -f $(INSTALL_DIR)/lib/libvoice_encryption.a
	rm -rf $(INSTALL_DIR)/include/voice_encryption

# Check code style
check-style:
	@echo "Checking code style..."
	@find src include tests -name "*.cpp" -o -name "*.h" | xargs clang-format --dry-run --Werror

# Format code
format:
	@echo "Formatting code..."
	@find src include tests -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Run static analysis
analyze:
	@echo "Running static analysis..."
	@find src include tests -name "*.cpp" -o -name "*.h" | xargs cppcheck --enable=all --std=c++17

# Generate documentation
docs:
	@echo "Generating documentation..."
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen not found, skipping documentation generation"

# Package
package: clean build test
	@echo "Creating package..."
	@tar -czf voice-encryption-$(shell date +%Y%m%d).tar.gz \
		--exclude=build \
		--exclude=tests/build \
		--exclude=.git \
		.

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the library"
	@echo "  test           - Build tests"
	@echo "  run-tests      - Run tests"
	@echo "  run-tests-verbose - Run tests with verbose output"
	@echo "  clean          - Clean build directories"
	@echo "  install        - Install the library"
	@echo "  uninstall      - Uninstall the library"
	@echo "  check-style    - Check code style"
	@echo "  format         - Format code"
	@echo "  analyze        - Run static analysis"
	@echo "  docs           - Generate documentation"
	@echo "  package        - Create source package"
	@echo "  help           - Show this help"

# Phony targets
.PHONY: all build test run-tests run-tests-verbose clean install uninstall check-style format analyze docs package help
