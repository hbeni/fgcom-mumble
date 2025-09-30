#!/bin/bash

# Comprehensive Database/Configuration Module Test Suite Runner
# Uses all installed development tools for thorough testing

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
BUILD_DIR="build"
TEST_RESULTS_DIR="test_results"
COVERAGE_DIR="coverage"
SANITIZER_DIR="sanitizer_results"

# Create directories
mkdir -p $BUILD_DIR $TEST_RESULTS_DIR $COVERAGE_DIR $SANITIZER_DIR

echo -e "${BLUE}=== Database/Configuration Module Comprehensive Test Suite ===${NC}"
echo "Using development tools:"
echo "  - Google Test/Mock: Unit testing"
echo "  - Valgrind: Memory leak detection"
echo "  - AddressSanitizer: Memory error detection"
echo "  - ThreadSanitizer: Race condition detection"
echo "  - Gcov/Lcov: Code coverage"
echo "  - CppCheck: Static analysis"
echo "  - Clang-Tidy: Static analysis"
echo ""

# Function to print section headers
print_section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check required tools
print_section "Checking Required Tools"

REQUIRED_TOOLS=("g++" "cmake" "make" "gtest" "valgrind" "cppcheck" "clang-tidy" "lcov")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool found"
    else
        echo -e "${RED}✗${NC} $tool not found"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${RED}Missing required tools: ${MISSING_TOOLS[*]}${NC}"
    echo "Please install missing tools before running tests"
    exit 1
fi

# Build tests
print_section "Building Database/Configuration Module Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests
print_section "Running Basic Database/Configuration Module Unit Tests"

echo "Running Google Test suite for database/configuration module..."
./database_configuration_module_tests --gtest_output=xml:../$TEST_RESULTS_DIR/database_configuration_module_basic_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic database/configuration module tests passed${NC}"
else
    echo -e "${RED}✗ Basic database/configuration module tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis for Database/Configuration Module"

echo "Running CppCheck on database/configuration module..."
cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
    --output-file=../$TEST_RESULTS_DIR/database_configuration_module_cppcheck.xml \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unmatchedSuppression \
    ../../client/mumble-plugin/lib/amateur_radio.cpp \
    ../../client/mumble-plugin/lib/radio_config.cpp \
    ../../client/mumble-plugin/lib/power_management.cpp \
    ../../client/mumble-plugin/lib/feature_toggles.cpp

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed for database/configuration module${NC}"
else
    echo -e "${YELLOW}⚠ CppCheck found issues in database/configuration module (see report)${NC}"
fi

echo "Running Clang-Tidy on database/configuration module..."
clang-tidy -checks='*' -header-filter='.*' \
    ../../client/mumble-plugin/lib/amateur_radio.cpp \
    ../../client/mumble-plugin/lib/radio_config.cpp \
    ../../client/mumble-plugin/lib/power_management.cpp \
    ../../client/mumble-plugin/lib/feature_toggles.cpp \
    -- -std=c++17 -I../../client/mumble-plugin/lib -I../../client/mumble-plugin > ../$TEST_RESULTS_DIR/database_configuration_module_clang-tidy.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed for database/configuration module${NC}"
else
    echo -e "${YELLOW}⚠ Clang-Tidy found issues in database/configuration module (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind for Database/Configuration Module"

echo "Running Valgrind memory leak detection on database/configuration module tests..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=../$TEST_RESULTS_DIR/database_configuration_module_valgrind.xml \
    ./database_configuration_module_tests --gtest_output=xml:../$TEST_RESULTS_DIR/database_configuration_module_valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed for database/configuration module${NC}"
else
    echo -e "${YELLOW}⚠ Valgrind found memory issues in database/configuration module (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests for Database/Configuration Module"

echo "Running AddressSanitizer memory error detection on database/configuration module..."
./database_configuration_module_tests_asan --gtest_output=xml:../$TEST_RESULTS_DIR/database_configuration_module_asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed for database/configuration module${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors in database/configuration module${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests for Database/Configuration Module"

echo "Running ThreadSanitizer race condition detection on database/configuration module..."
./database_configuration_module_tests_tsan --gtest_output=xml:../$TEST_RESULTS_DIR/database_configuration_module_tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed for database/configuration module${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions in database/configuration module${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis for Database/Configuration Module"

echo "Running coverage tests for database/configuration module..."
./database_configuration_module_tests_coverage --gtest_output=xml:../$TEST_RESULTS_DIR/database_configuration_module_coverage_tests.xml

echo "Generating coverage report for database/configuration module..."
lcov --capture --directory . --output-file ../$COVERAGE_DIR/database_configuration_module_coverage.info
lcov --remove ../$COVERAGE_DIR/database_configuration_module_coverage.info '/usr/*' --output-file ../$COVERAGE_DIR/database_configuration_module_coverage_filtered.info
genhtml ../$COVERAGE_DIR/database_configuration_module_coverage_filtered.info --output-directory ../$COVERAGE_DIR/database_configuration_module_html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated for database/configuration module${NC}"
    echo "Database/Configuration module coverage report available at: $COVERAGE_DIR/database_configuration_module_html/index.html"
else
    echo -e "${YELLOW}⚠ Coverage report generation failed for database/configuration module${NC}"
fi

# 7. Performance Tests
print_section "Running Performance Tests for Database/Configuration Module"

echo "Running performance benchmarks for database/configuration module..."
time ./database_configuration_module_tests --gtest_filter="*Performance*" > ../$TEST_RESULTS_DIR/database_configuration_module_performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed for database/configuration module${NC}"
else
    echo -e "${YELLOW}⚠ Performance tests had issues for database/configuration module${NC}"
fi

# 8. Stress Tests
print_section "Running Stress Tests for Database/Configuration Module"

echo "Running stress tests with high load for database/configuration module..."
for i in {1..5}; do
    echo "Database/Configuration module stress test iteration $i/5"
    ./database_configuration_module_tests --gtest_filter="*Stress*" --gtest_repeat=10 > ../$TEST_RESULTS_DIR/database_configuration_module_stress_$i.txt 2>&1
done

echo -e "${GREEN}✓ Stress tests completed for database/configuration module${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Database/Configuration Module Test Report"

cat > ../$TEST_RESULTS_DIR/database_configuration_module_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Database/Configuration Module Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Database/Configuration Module Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: Database/Configuration Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>CSV File Parsing Tests:</strong> Amateur radio band segments CSV, header parsing, data type validation, missing field handling, comment line skipping, quote handling, delimiter detection</li>
            <li><strong>Configuration File Tests:</strong> INI file parsing, section handling, key-value pair extraction, comment handling, default value handling, invalid syntax handling</li>
            <li><strong>Unit Tests:</strong> Google Test framework</li>
            <li><strong>Memory Analysis:</strong> Valgrind + AddressSanitizer</li>
            <li><strong>Thread Safety:</strong> ThreadSanitizer</li>
            <li><strong>Code Coverage:</strong> Gcov/Lcov</li>
            <li><strong>Static Analysis:</strong> CppCheck + Clang-Tidy</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Results</h2>
        <p>Detailed results available in individual files:</p>
        <ul>
            <li><a href="database_configuration_module_basic_tests.xml">Basic Database/Configuration Module Tests (XML)</a></li>
            <li><a href="database_configuration_module_valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="database_configuration_module_asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="database_configuration_module_tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="database_configuration_module_cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="database_configuration_module_clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="database_configuration_module_performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="../coverage/database_configuration_module_html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>CSV File Parsing Tests:</strong> Amateur radio band segments CSV, header parsing, data type validation, missing field handling, comment line skipping, quote handling, delimiter detection</li>
            <li><strong>Configuration File Tests:</strong> INI file parsing, section handling, key-value pair extraction, comment handling, default value handling, invalid syntax handling</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat ../$TEST_RESULTS_DIR/database_configuration_module_performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive database/configuration module test report generated${NC}"

# 10. Summary
print_section "Database/Configuration Module Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/database_configuration_module_html/index.html"
echo "Test report: $TEST_RESULTS_DIR/database_configuration_module_test_report.html"

echo -e "\n${GREEN}=== All Database/Configuration Module Tests Completed ===${NC}"
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/database_configuration_module_test_report.html in a web browser for a comprehensive overview."

cd ..

