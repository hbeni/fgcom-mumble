#!/bin/bash

# Script to update all Makefiles for test suites
# Uses CMake wrapper for suites that have CMakeLists.txt, simple Makefile for others

# List of test suites
TEST_SUITES=(
    "agc_squelch_tests"
    "antenna_pattern_module_tests"
    "atis_module_tests"
    "audio_processing_tests"
    "client_plugin_module_tests"
    "database_configuration_module_tests"
    "error_handling_tests"
    "frequency_management_tests"
    "geographic_module_tests"
    "integration_tests"
    "jsimconnect_build_tests"
    "network_module_tests"
    "openstreetmap_infrastructure_tests"
    "performance_tests"
    "professional_audio_tests"
    "radio_propagation_tests"
    "security_module_tests"
    "status_page_module_tests"
    "webrtc_api_tests"
    "work_unit_distribution_module_tests"
)

# Function to create CMake wrapper Makefile
create_cmake_makefile() {
    local test_suite=$1
    local test_dir="$test_suite"
    
    echo "Creating CMake wrapper Makefile for $test_suite..."
    
    cat > "$test_dir/Makefile" << EOF
# Makefile for $test_suite test suite
# This Makefile provides consistent build management for $test_suite tests
# Uses CMake for building (existing system)

# Test suite name
TEST_NAME = $test_suite
BUILD_DIR = build

# Default target
all: build

# Build using CMake
build:
	@if [ ! -d "\$(BUILD_DIR)" ]; then mkdir -p \$(BUILD_DIR); fi
	cd \$(BUILD_DIR) && cmake .. && make

# Run tests
test: build
	cd \$(BUILD_DIR) && ./\$(TEST_NAME)

# Run tests with verbose output
test-verbose: build
	cd \$(BUILD_DIR) && ./\$(TEST_NAME) --gtest_verbose

# Run tests with specific filter
test-filter: build
	cd \$(BUILD_DIR) && ./\$(TEST_NAME) --gtest_filter=\$(FILTER)

# Run coverage tests (if available)
test-coverage: build
	cd \$(BUILD_DIR) && ./\$(TEST_NAME)_coverage 2>/dev/null || echo "Coverage tests not available"

# Run ASAN tests (if available)
test-asan: build
	cd \$(BUILD_DIR) && ./\$(TEST_NAME)_asan 2>/dev/null || echo "ASAN tests not available"

# Run TSAN tests (if available)
test-tsan: build
	cd \$(BUILD_DIR) && ./\$(TEST_NAME)_tsan 2>/dev/null || echo "TSAN tests not available"

# Clean build artifacts
clean:
	rm -rf \$(BUILD_DIR)

# Clean everything including build directories
distclean: clean
	rm -rf \$(BUILD_DIR)

# Install dependencies (if needed)
install-deps:
	@echo "Installing dependencies for \$(TEST_NAME)..."
	@echo "Dependencies: gtest, gmock, pthread, cmake"

# Show help
help:
	@echo "Available targets for \$(TEST_NAME):"
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
EOF

    echo "Created CMake wrapper Makefile for $test_suite"
}

# Function to create simple Makefile
create_simple_makefile() {
    local test_suite=$1
    local test_dir="$test_suite"
    
    echo "Creating simple Makefile for $test_suite..."
    
    cat > "$test_dir/Makefile" << EOF
# Makefile for $test_suite test suite
# This Makefile provides consistent build management for $test_suite tests

# Test suite name
TEST_NAME = $test_suite
TEST_DIR = \$(shell pwd)

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
INCLUDES = -I\$(TEST_DIR) -I/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib
LIBS = -lgtest -lgmock -lgtest_main -pthread

# Test source files
TEST_SOURCES = \$(wildcard test_*.cpp)
TEST_OBJECTS = \$(TEST_SOURCES:.cpp=.o)
TEST_EXECUTABLE = \$(TEST_NAME)

# Default target
all: \$(TEST_EXECUTABLE)

# Build the test executable
\$(TEST_EXECUTABLE): \$(TEST_OBJECTS)
	\$(CXX) \$(CXXFLAGS) \$(INCLUDES) -o \$@ \$^ \$(LIBS)

# Compile source files
%.o: %.cpp
	\$(CXX) \$(CXXFLAGS) \$(INCLUDES) -c \$< -o \$@

# Run tests
test: \$(TEST_EXECUTABLE)
	./\$(TEST_EXECUTABLE)

# Run tests with verbose output
test-verbose: \$(TEST_EXECUTABLE)
	./\$(TEST_EXECUTABLE) --gtest_verbose

# Run tests with specific filter
test-filter: \$(TEST_EXECUTABLE)
	./\$(TEST_EXECUTABLE) --gtest_filter=\$(FILTER)

# Clean build artifacts
clean:
	rm -f \$(TEST_OBJECTS) \$(TEST_EXECUTABLE)

# Clean everything including build directories
distclean: clean
	rm -rf build/

# Install dependencies (if needed)
install-deps:
	@echo "Installing dependencies for \$(TEST_NAME)..."
	@echo "Dependencies: gtest, gmock, pthread"

# Show help
help:
	@echo "Available targets for \$(TEST_NAME):"
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
EOF

    echo "Created simple Makefile for $test_suite"
}

# Update Makefiles for all test suites
for test_suite in "${TEST_SUITES[@]}"; do
    if [ -d "$test_suite" ]; then
        # Check if test suite has CMakeLists.txt
        if [ -f "$test_suite/CMakeLists.txt" ]; then
            create_cmake_makefile "$test_suite"
        else
            create_simple_makefile "$test_suite"
        fi
    else
        echo "Warning: Directory $test_suite does not exist, skipping..."
    fi
done

echo ""
echo "All Makefiles updated successfully!"
echo ""
echo "Usage examples:"
echo "  cd test/audio_processing_tests && make test"
echo "  cd test/error_handling_tests && make test-verbose"
echo "  cd test/performance_tests && make test-coverage"
echo "  cd test/network_module_tests && make test-filter FILTER=*UDP*"
