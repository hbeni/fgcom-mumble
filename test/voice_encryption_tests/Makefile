# Voice Encryption Tests Makefile
# This Makefile builds and runs voice encryption tests
#
# @author FGcom-mumble Development Team
# @date 2025
# @see test/voice_encryption_tests/

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -g
INCLUDES = -I../../voice-encryption/systems/yachta-t219/include \
           -I../../voice-encryption/systems/yachta-t219/src \
           -I../../voice-encryption/systems/vinson-ky57/include \
           -I../../voice-encryption/systems/vinson-ky57/src \
           -I../../voice-encryption/systems/granit/include \
           -I../../voice-encryption/systems/granit/src \
           -I../../voice-encryption/systems/stanag-4197/include \
           -I../../voice-encryption/systems/stanag-4197/src \
           -I../../voice-encryption/systems/freedv/include \
           -I../../voice-encryption/systems/freedv/src \
           -I../../voice-encryption/systems/melpe/include \
           -I../../voice-encryption/systems/melpe/src

# Libraries
LIBS = -lgtest_main -lgtest -lgmock -lpthread -lm

# Source files
SOURCES = test_yachta_t219.cpp \
          test_vinson_ky57.cpp \
          test_granit.cpp \
          test_stanag_4197.cpp \
          test_freedv.cpp \
          test_melpe.cpp \
          ../../voice-encryption/systems/yachta-t219/src/yachta_t219.cpp \
          ../../voice-encryption/systems/vinson-ky57/src/vinson_ky57.cpp \
          ../../voice-encryption/systems/granit/src/granit.cpp \
          ../../voice-encryption/systems/stanag-4197/src/stanag_4197.cpp \
          ../../voice-encryption/systems/freedv/src/freedv.cpp \
          ../../voice-encryption/systems/melpe/src/melpe.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Target executable
TARGET = voice_encryption_tests

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
	./$(TARGET) --gtest_filter="*Voice*"

# Run tests for specific encryption systems
test-yachta: $(TARGET)
	./$(TARGET) --gtest_filter="*Yachta*"

test-vinson: $(TARGET)
	./$(TARGET) --gtest_filter="*Vinson*"

test-granit: $(TARGET)
	./$(TARGET) --gtest_filter="*Granit*"

test-stanag: $(TARGET)
	./$(TARGET) --gtest_filter="*STANAG*"

test-freedv: $(TARGET)
	./$(TARGET) --gtest_filter="*FreeDV*"

test-melpe: $(TARGET)
	./$(TARGET) --gtest_filter="*MELPe*"

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
	cd build && ./voice_encryption_tests

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
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-filter  - Run tests with specific filter"
	@echo "  test-yachta  - Run Yachta T-219 tests"
	@echo "  test-vinson  - Run VINSON KY-57 tests"
	@echo "  test-granit  - Run Granit tests"
	@echo "  test-stanag  - Run STANAG 4197 tests"
	@echo "  test-freedv  - Run FreeDV tests"
	@echo "  test-melpe   - Run MELPe tests"
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
.PHONY: all test test-verbose test-filter test-yachta test-vinson test-granit test-stanag test-freedv test-melpe test-asan test-tsan test-valgrind test-coverage cmake-build cmake-test clean install-deps check-deps help
