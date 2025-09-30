#!/bin/bash

# Comprehensive AGC/Squelch Test Suite Runner
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

echo -e "${BLUE}=== AGC/Squelch Comprehensive Test Suite ===${NC}"
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
print_section "Building Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests
print_section "Running Basic Unit Tests"

echo "Running Google Test suite..."
./agc_squelch_tests --gtest_output=xml:../$TEST_RESULTS_DIR/basic_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic tests passed${NC}"
else
    echo -e "${RED}✗ Basic tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis"

echo "Running CppCheck..."
cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
    --output-file=../$TEST_RESULTS_DIR/cppcheck.xml \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unmatchedSuppression \
    ../../client/mumble-plugin/lib/agc_squelch.cpp \
    ../../client/mumble-plugin/lib/agc_squelch.h

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed${NC}"
else
    echo -e "${YELLOW}⚠ CppCheck found issues (see report)${NC}"
fi

echo "Running Clang-Tidy..."
clang-tidy -checks='*' -header-filter='.*' \
    ../../client/mumble-plugin/lib/agc_squelch.cpp \
    -- -std=c++17 -I../../client/mumble-plugin/lib > ../$TEST_RESULTS_DIR/clang-tidy.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed${NC}"
else
    echo -e "${YELLOW}⚠ Clang-Tidy found issues (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind"

echo "Running Valgrind memory leak detection..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=../$TEST_RESULTS_DIR/valgrind.xml \
    ./agc_squelch_tests --gtest_output=xml:../$TEST_RESULTS_DIR/valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed${NC}"
else
    echo -e "${YELLOW}⚠ Valgrind found memory issues (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests"

echo "Running AddressSanitizer memory error detection..."
./agc_squelch_tests_asan --gtest_output=xml:../$TEST_RESULTS_DIR/asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests"

echo "Running ThreadSanitizer race condition detection..."
./agc_squelch_tests_tsan --gtest_output=xml:../$TEST_RESULTS_DIR/tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis"

echo "Running coverage tests..."
./agc_squelch_tests_coverage --gtest_output=xml:../$TEST_RESULTS_DIR/coverage_tests.xml

echo "Generating coverage report..."
lcov --capture --directory . --output-file ../$COVERAGE_DIR/coverage.info
lcov --remove ../$COVERAGE_DIR/coverage.info '/usr/*' --output-file ../$COVERAGE_DIR/coverage_filtered.info
genhtml ../$COVERAGE_DIR/coverage_filtered.info --output-directory ../$COVERAGE_DIR/html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated${NC}"
    echo "Coverage report available at: $COVERAGE_DIR/html/index.html"
else
    echo -e "${YELLOW}⚠ Coverage report generation failed${NC}"
fi

# 7. Performance Tests
print_section "Running Performance Tests"

echo "Running performance benchmarks..."
time ./agc_squelch_tests --gtest_filter="*Performance*" > ../$TEST_RESULTS_DIR/performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed${NC}"
else
    echo -e "${YELLOW}⚠ Performance tests had issues${NC}"
fi

# 8. Stress Tests
print_section "Running Stress Tests"

echo "Running stress tests with high load..."
for i in {1..5}; do
    echo "Stress test iteration $i/5"
    ./agc_squelch_tests --gtest_filter="*Stress*" --gtest_repeat=10 > ../$TEST_RESULTS_DIR/stress_$i.txt 2>&1
done

echo -e "${GREEN}✓ Stress tests completed${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Test Report"

cat > ../$TEST_RESULTS_DIR/test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>AGC/Squelch Test Report</title>
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
        <h1>AGC/Squelch Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: AGC/Squelch Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>Unit Tests:</strong> Google Test framework</li>
            <li><strong>Memory Analysis:</strong> Valgrind + AddressSanitizer</li>
            <li><strong>Thread Safety:</strong> ThreadSanitizer</li>
            <li><strong>Code Coverage:</strong> Gcov/Lcov</li>
            <li><strong>Static Analysis:</strong> CppCheck + Clang-Tidy</li>
            <li><strong>Performance:</strong> Benchmark tests</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Results</h2>
        <p>Detailed results available in individual files:</p>
        <ul>
            <li><a href="basic_tests.xml">Basic Unit Tests (XML)</a></li>
            <li><a href="valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="../coverage/html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat ../$TEST_RESULTS_DIR/performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive test report generated${NC}"

# 10. Summary
print_section "Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/html/index.html"
echo "Test report: $TEST_RESULTS_DIR/test_report.html"

echo -e "\n${GREEN}=== All Tests Completed ===${NC}"
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/test_report.html in a web browser for a comprehensive overview."

cd ..

