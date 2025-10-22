# Makefile for error_handling_tests
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
INCLUDES = -I$(CURDIR) -I../../client/mumble-plugin/lib -I../rapidcheck_tests/lib/rapidcheck/include
LDFLAGS = -lgtest -lgtest_main -lpthread -L../rapidcheck_tests/lib/rapidcheck/build -lrapidcheck

# Source files
SOURCES = test_error_handling_main.cpp test_error_handling_tests_properties.cpp test_error_logging.cpp test_graceful_degradation.cpp
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = error_handling_tests

# Default target
all: $(TARGET)

# Build the test executable
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Run tests
test: $(TARGET)
	./$(TARGET)

# Run with valgrind
valgrind: $(TARGET)
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./$(TARGET)

# Run with cppcheck
cppcheck:
	cppcheck --enable=all --inconclusive --std=c++17 .

# Run with clang-tidy
clang-tidy:
	clang-tidy $(SOURCES) -- -std=c++17

# Coverage analysis
coverage: CXXFLAGS += -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += -lgcov
coverage: clean $(TARGET)
	./$(TARGET)
	gcov -r *.gcno
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage_html

.PHONY: all clean test valgrind cppcheck clang-tidy coverage