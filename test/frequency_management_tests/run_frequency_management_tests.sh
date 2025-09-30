#!/bin/bash

# Comprehensive Frequency Management Test Suite Runner
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

echo -e "${BLUE}=== Frequency Management Comprehensive Test Suite ===${NC}"
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
print_section "Building Frequency Management Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests
print_section "Running Basic Frequency Management Unit Tests"

echo "Running Google Test suite for frequency management..."
./frequency_management_tests --gtest_output=xml:../$TEST_RESULTS_DIR/frequency_management_basic_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic frequency management tests passed${NC}"
else
    echo -e "${RED}✗ Basic frequency management tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis for Frequency Management"

echo "Running CppCheck on frequency management modules..."
cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
    --output-file=../$TEST_RESULTS_DIR/frequency_management_cppcheck.xml \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unmatchedSuppression \
    ../../client/mumble-plugin/lib/amateur_radio.cpp \
    ../../client/mumble-plugin/lib/radio_model.cpp

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed for frequency management${NC}"
else
    echo -e "${YELLOW}⚠ CppCheck found issues in frequency management (see report)${NC}"
fi

echo "Running Clang-Tidy on frequency management modules..."
clang-tidy -checks='*' -header-filter='.*' \
    ../../client/mumble-plugin/lib/amateur_radio.cpp \
    ../../client/mumble-plugin/lib/radio_model.cpp \
    -- -std=c++17 -I../../client/mumble-plugin/lib > ../$TEST_RESULTS_DIR/frequency_management_clang-tidy.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed for frequency management${NC}"
else
    echo -e "${YELLOW}⚠ Clang-Tidy found issues in frequency management (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind for Frequency Management"

echo "Running Valgrind memory leak detection on frequency management tests..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=../$TEST_RESULTS_DIR/frequency_management_valgrind.xml \
    ./frequency_management_tests --gtest_output=xml:../$TEST_RESULTS_DIR/frequency_management_valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed for frequency management${NC}"
else
    echo -e "${YELLOW}⚠ Valgrind found memory issues in frequency management (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests for Frequency Management"

echo "Running AddressSanitizer memory error detection on frequency management..."
./frequency_management_tests_asan --gtest_output=xml:../$TEST_RESULTS_DIR/frequency_management_asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed for frequency management${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors in frequency management${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests for Frequency Management"

echo "Running ThreadSanitizer race condition detection on frequency management..."
./frequency_management_tests_tsan --gtest_output=xml:../$TEST_RESULTS_DIR/frequency_management_tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed for frequency management${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions in frequency management${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis for Frequency Management"

echo "Running coverage tests for frequency management..."
./frequency_management_tests_coverage --gtest_output=xml:../$TEST_RESULTS_DIR/frequency_management_coverage_tests.xml

echo "Generating coverage report for frequency management..."
lcov --capture --directory . --output-file ../$COVERAGE_DIR/frequency_management_coverage.info
lcov --remove ../$COVERAGE_DIR/frequency_management_coverage.info '/usr/*' --output-file ../$COVERAGE_DIR/frequency_management_coverage_filtered.info
genhtml ../$COVERAGE_DIR/frequency_management_coverage_filtered.info --output-directory ../$COVERAGE_DIR/frequency_management_html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated for frequency management${NC}"
    echo "Frequency management coverage report available at: $COVERAGE_DIR/frequency_management_html/index.html"
else
    echo -e "${YELLOW}⚠ Coverage report generation failed for frequency management${NC}"
fi

# 7. Performance Tests
print_section "Running Performance Tests for Frequency Management"

echo "Running performance benchmarks for frequency management..."
time ./frequency_management_tests --gtest_filter="*Performance*" > ../$TEST_RESULTS_DIR/frequency_management_performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed for frequency management${NC}"
else
    echo -e "${YELLOW}⚠ Performance tests had issues for frequency management${NC}"
fi

# 8. Stress Tests
print_section "Running Stress Tests for Frequency Management"

echo "Running stress tests with high load for frequency management..."
for i in {1..5}; do
    echo "Frequency management stress test iteration $i/5"
    ./frequency_management_tests --gtest_filter="*Stress*" --gtest_repeat=10 > ../$TEST_RESULTS_DIR/frequency_management_stress_$i.txt 2>&1
done

echo -e "${GREEN}✓ Stress tests completed for frequency management${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Frequency Management Test Report"

cat > ../$TEST_RESULTS_DIR/frequency_management_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Frequency Management Test Report</title>
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
        <h1>Frequency Management Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: Frequency Management Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>Band Segment Validation:</strong> Amateur radio, ITU regions, country-specific regulations</li>
            <li><strong>Aviation Frequencies:</strong> Civil VHF, military, emergency, guard frequencies</li>
            <li><strong>Maritime Frequencies:</strong> HF bands, distress, working, coast station frequencies</li>
            <li><strong>Frequency Offsets:</strong> BFO, SSB, CW tone, drift, crystal accuracy</li>
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
            <li><a href="frequency_management_basic_tests.xml">Basic Frequency Management Tests (XML)</a></li>
            <li><a href="frequency_management_valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="frequency_management_asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="frequency_management_tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="frequency_management_cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="frequency_management_clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="frequency_management_performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="../coverage/frequency_management_html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>Band Segment Validation Tests:</strong> Amateur radio band segments, ITU region detection, country-specific regulations</li>
            <li><strong>Aviation Frequency Tests:</strong> Civil VHF (118-137 MHz), military VHF/UHF, emergency (121.5 MHz), guard (243.0 MHz)</li>
            <li><strong>Maritime Frequency Tests:</strong> Maritime HF bands, distress frequencies, working frequencies, coast station frequencies</li>
            <li><strong>Frequency Offset Tests:</strong> BFO simulation, SSB frequency offset, CW tone injection, frequency drift, crystal accuracy</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat ../$TEST_RESULTS_DIR/frequency_management_performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive frequency management test report generated${NC}"

# 10. Summary
print_section "Frequency Management Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/frequency_management_html/index.html"
echo "Test report: $TEST_RESULTS_DIR/frequency_management_test_report.html"

echo -e "\n${GREEN}=== All Frequency Management Tests Completed ===${NC}"
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/frequency_management_test_report.html in a web browser for a comprehensive overview."

cd ..

