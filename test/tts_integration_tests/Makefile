# TTS Integration Tests Makefile
# This Makefile builds and runs TTS integration tests
#
# @author FGcom-mumble Development Team
# @date 2025
# @see test/tts_integration_tests/

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -g
INCLUDES = -I../../scripts/tts \
           -I../../scripts/tts/atis_templates

# Libraries
LIBS = -lgtest -lgmock -lpthread -lm

# Source files
SOURCES = test_tts_integration.cpp \
          test_piper_tts.cpp \
          test_atis_generation.cpp \
          test_tts_configuration.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Target executable
TARGET = tts_integration_tests

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Compile source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Run tests
test: $(TARGET)
	./$(TARGET)

# Run tests with verbose output
test-verbose: $(TARGET)
	./$(TARGET) --gtest_verbose

# Run tests with specific filter
test-filter: $(TARGET)
	./$(TARGET) --gtest_filter="*TTS*"

# Run tests with AddressSanitizer
test-asan: clean
	$(CXX) $(CXXFLAGS) -fsanitize=address -fno-omit-frame-pointer $(INCLUDES) -o $(TARGET)_asan $(SOURCES) $(LIBS)
	./$(TARGET)_asan

# Run tests with ThreadSanitizer
test-tsan: clean
	$(CXX) $(CXXFLAGS) -fsanitize=thread -fno-omit-frame-pointer $(INCLUDES) -o $(TARGET)_tsan $(SOURCES) $(LIBS)
	./$(TARGET)_tsan

# Run tests with Valgrind
test-valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET)

# Run tests with coverage
test-coverage: clean
	$(CXX) $(CXXFLAGS) -fprofile-arcs -ftest-coverage $(INCLUDES) -o $(TARGET)_coverage $(SOURCES) $(LIBS)
	./$(TARGET)_coverage
	gcov $(SOURCES)
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage

# Build with CMake
cmake-build:
	mkdir -p build
	cd build && cmake ..
	cd build && make

# Run CMake tests
cmake-test: cmake-build
	cd build && ./tts_integration_tests

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET) $(TARGET)_asan $(TARGET)_tsan $(TARGET)_coverage
	rm -f *.gcov *.gcda *.gcno coverage.info
	rm -rf coverage build

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libgtest-dev libgmock-dev cmake make g++

# Check for required tools
check-deps:
	@echo "Checking dependencies..."
	@which g++ > /dev/null || echo "ERROR: g++ not found"
	@which cmake > /dev/null || echo "ERROR: cmake not found"
	@which make > /dev/null || echo "ERROR: make not found"
	@pkg-config --exists gtest || echo "ERROR: libgtest-dev not found"
	@pkg-config --exists gmock || echo "ERROR: libgmock-dev not found"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build the test executable"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-filter  - Run tests with specific filter"
	@echo "  test-asan    - Run tests with AddressSanitizer"
	@echo "  test-tsan    - Run tests with ThreadSanitizer"
	@echo "  test-valgrind- Run tests with Valgrind"
	@echo "  test-coverage- Run tests with coverage analysis"
	@echo "  cmake-build  - Build using CMake"
	@echo "  cmake-test   - Run CMake tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install dependencies"
	@echo "  check-deps   - Check for required tools"
	@echo "  help         - Show this help"

# Phony targets
.PHONY: all test test-verbose test-filter test-asan test-tsan test-valgrind test-coverage cmake-build cmake-test clean install-deps check-deps help
