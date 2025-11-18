# ATIS Weather Integration Tests Makefile
# Builds and runs ATIS weather integration tests

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -Werror -O2 -g
INCLUDES = -I../../../scripts/tts -I../../../client/mumble-plugin -I../../../server -I../../../test
LIBS = -lgtest -lgmock -lrapidcheck -lnlohmann_json -lpthread

# Source files
SOURCES = test_atis_weather_integration.cpp
TARGET = atis_weather_integration_tests
BUILD_DIR = build

# Default target
all: $(BUILD_DIR)/$(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build test executable
$(BUILD_DIR)/$(TARGET): $(SOURCES) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

# Run all tests
test: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET)

# Run property-based tests
property-tests: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET) --gtest_filter="*Property*"

# Run integration tests
integration-tests: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET) --gtest_filter="*Integration*"

# Run unit tests
unit-tests: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET) --gtest_filter="*Test*"

# Run with verbose output
verbose: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET) --gtest_verbose

# Run with XML output
xml: $(BUILD_DIR)/$(TARGET)
	./$(BUILD_DIR)/$(TARGET) --gtest_output=xml:test_results.xml

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f test_results.xml

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libgtest-dev libgmock-dev librapidcheck-dev nlohmann-json3-dev

# Install dependencies (CentOS/RHEL)
install-deps-centos:
	sudo yum install -y gtest-devel gmock-devel rapidcheck-devel nlohmann-json-devel

# Install dependencies (macOS)
install-deps-macos:
	brew install googletest gmock rapidcheck nlohmann-json

# Help target
help:
	@echo "Available targets:"
	@echo "  all              - Build test executable"
	@echo "  test             - Run all tests"
	@echo "  property-tests   - Run property-based tests"
	@echo "  integration-tests - Run integration tests"
	@echo "  unit-tests       - Run unit tests"
	@echo "  verbose          - Run tests with verbose output"
	@echo "  xml              - Run tests with XML output"
	@echo "  clean            - Clean build artifacts"
	@echo "  install-deps     - Install dependencies (Ubuntu/Debian)"
	@echo "  install-deps-centos - Install dependencies (CentOS/RHEL)"
	@echo "  install-deps-macos - Install dependencies (macOS)"
	@echo "  help             - Show this help message"

.PHONY: all test property-tests integration-tests unit-tests verbose xml clean install-deps install-deps-centos install-deps-macos help
