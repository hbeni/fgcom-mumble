# Makefile for error_handling_tests test suite
# This Makefile provides consistent build management for error_handling_tests tests

# Test suite name
TEST_NAME = error_handling_tests
TEST_DIR = $(shell pwd)

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
INCLUDES = -I$(TEST_DIR) -I../../client/mumble-plugin/lib
LIBS = -lgtest -lgmock -lgtest_main -pthread

# Test source files
TEST_SOURCES = $(wildcard test_*.cpp)
TEST_OBJECTS = $(addprefix build/, $(TEST_SOURCES:.cpp=.o))
TEST_EXECUTABLE = build/$(TEST_NAME)

# Default target
all: $(TEST_EXECUTABLE)

# Build the test executable
$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

# Compile source files
build/%.o: %.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Run tests
test: $(TEST_EXECUTABLE)
	cd build && ./$(TEST_NAME)

# Run tests with verbose output
test-verbose: $(TEST_EXECUTABLE)
	cd build && ./$(TEST_NAME) --gtest_verbose

# Run tests with specific filter
test-filter: $(TEST_EXECUTABLE)
	cd build && ./$(TEST_NAME) --gtest_filter=$(FILTER)

# Clean build artifacts
clean:
	rm -f $(TEST_OBJECTS) $(TEST_EXECUTABLE)

# Clean everything including build directories
distclean: clean
	rm -rf build/

# Install dependencies (if needed)
install-deps:
	@echo "Installing dependencies for $(TEST_NAME)..."
	@echo "Dependencies: gtest, gmock, pthread"

# Show help
help:
	@echo "Available targets for $(TEST_NAME):"
	@echo "  all          - Build the test executable (default)"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-filter  - Run tests with filter (use FILTER=pattern)"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove all generated files"
	@echo "  install-deps - Show dependency information"
	@echo "  help         - Show this help message"

# Phony targets
.PHONY: all test test-verbose test-filter clean distclean install-deps help
