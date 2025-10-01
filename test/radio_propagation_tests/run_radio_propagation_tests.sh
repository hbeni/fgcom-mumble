#!/bin/bash

# Comprehensive Radio Propagation Test Suite Runner
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

echo -e "${BLUE}=== Radio Propagation Comprehensive Test Suite ===${NC}"
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

REQUIRED_TOOLS=("g++" "cmake" "make" "valgrind" "cppcheck" "clang-tidy" "lcov")
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
print_section "Building Radio Propagation Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests
print_section "Running Basic Radio Propagation Unit Tests"

echo "Running Google Test suite for radio propagation..."
./radio_propagation_tests --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_basic_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic radio propagation tests passed${NC}"
else
    echo -e "${RED}✗ Basic radio propagation tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis for Radio Propagation"

echo "Running CppCheck on radio propagation modules..."
# Check if source files exist before running CppCheck
SOURCE_FILES=(
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/terrain_elevation.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/radio_model_vhf.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/radio_model_uhf.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/radio_model_hf.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/antenna_ground_system.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/antenna_orientation_calculator.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/pattern_interpolation.cpp"
)

EXISTING_FILES=()
for file in "${SOURCE_FILES[@]}"; do
    if [ -f "$file" ]; then
        EXISTING_FILES+=("$file")
    fi
done

if [ ${#EXISTING_FILES[@]} -gt 0 ]; then
    cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
        --output-file=/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_cppcheck.xml \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unmatchedSuppression \
        "${EXISTING_FILES[@]}"
else
    echo "No source files found for CppCheck analysis"
    echo "CppCheck analysis skipped" > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_cppcheck.xml
fi

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed for radio propagation${NC}"
else
    echo -e "${YELLOW}⚠ CppCheck found issues in radio propagation (see report)${NC}"
fi

echo "Running Clang-Tidy on radio propagation modules..."
# Check if source files exist before running Clang-Tidy
CLANG_FILES=(
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/terrain_elevation.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/radio_model_vhf.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/radio_model_uhf.cpp"
    "/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/radio_model_hf.cpp"
)

EXISTING_CLANG_FILES=()
for file in "${CLANG_FILES[@]}"; do
    if [ -f "$file" ]; then
        EXISTING_CLANG_FILES+=("$file")
    fi
done

if [ ${#EXISTING_CLANG_FILES[@]} -gt 0 ]; then
    clang-tidy -checks='*' -header-filter='.*' \
        "${EXISTING_CLANG_FILES[@]}" \
        -- -std=c++17 -I/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_clang-tidy.txt
else
    echo "No source files found for Clang-Tidy analysis"
    echo "Clang-Tidy analysis skipped" > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_clang-tidy.txt
fi

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed for radio propagation${NC}"
else
    echo -e "${YELLOW}⚠ Clang-Tidy found issues in radio propagation (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind for Radio Propagation"

echo "Running Valgrind memory leak detection on radio propagation tests..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_valgrind.xml \
    ./radio_propagation_tests --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed for radio propagation${NC}"
else
    echo -e "${YELLOW}⚠ Valgrind found memory issues in radio propagation (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests for Radio Propagation"

echo "Running AddressSanitizer memory error detection on radio propagation..."
./radio_propagation_tests_asan --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed for radio propagation${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors in radio propagation${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests for Radio Propagation"

echo "Running ThreadSanitizer race condition detection on radio propagation..."
./radio_propagation_tests_tsan --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed for radio propagation${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions in radio propagation${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis for Radio Propagation"

echo "Running coverage tests for radio propagation..."
./radio_propagation_tests_coverage --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_coverage_tests.xml

echo "Generating coverage report for radio propagation..."
lcov --capture --directory . --output-file /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/radio_propagation_coverage.info
lcov --remove /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/radio_propagation_coverage.info '/usr/*' --output-file /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/radio_propagation_coverage_filtered.info
genhtml /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/radio_propagation_coverage_filtered.info --output-directory /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/radio_propagation_html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated for radio propagation${NC}"
    echo "Radio propagation coverage report available at: $COVERAGE_DIR/radio_propagation_html/index.html"
else
    echo -e "${YELLOW}⚠ Coverage report generation failed for radio propagation${NC}"
fi

# 7. Performance Tests
print_section "Running Performance Tests for Radio Propagation"

echo "Running performance benchmarks for radio propagation..."
time ./radio_propagation_tests --gtest_filter="*Performance*" > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed for radio propagation${NC}"
else
    echo -e "${YELLOW}⚠ Performance tests had issues for radio propagation${NC}"
fi

# 8. Stress Tests
print_section "Running Stress Tests for Radio Propagation"

echo "Running stress tests with high load for radio propagation..."
for i in {1..5}; do
    echo "Radio propagation stress test iteration $i/5"
    ./radio_propagation_tests --gtest_filter="*Stress*" --gtest_repeat=10 > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_stress_$i.txt 2>&1
done

echo -e "${GREEN}✓ Stress tests completed for radio propagation${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Radio Propagation Test Report"

cat > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Radio Propagation Test Report</title>
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
        <h1>Radio Propagation Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: Radio Propagation Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>Line-of-Sight Tests:</strong> Direct LOS, terrain obstruction, earth curvature</li>
            <li><strong>Frequency Propagation:</strong> VHF, UHF, HF propagation characteristics</li>
            <li><strong>Antenna Patterns:</strong> Omnidirectional, directional, polarization</li>
            <li><strong>Environmental Effects:</strong> Weather, temperature, humidity, pressure</li>
            <li><strong>Noise Floor:</strong> Atmospheric, man-made, galactic noise</li>
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
            <li><a href="radio_propagation_basic_tests.xml">Basic Radio Propagation Tests (XML)</a></li>
            <li><a href="radio_propagation_valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="radio_propagation_asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="radio_propagation_tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="radio_propagation_cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="radio_propagation_clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="radio_propagation_performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="/home/haaken/github-projects/fgcom-mumble/test/coverage/radio_propagation_html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>Line-of-Sight Tests:</strong> Direct LOS calculation, terrain obstruction detection, earth curvature effects</li>
            <li><strong>Frequency Propagation Tests:</strong> VHF (118-137 MHz), UHF (225-400 MHz), HF (3-30 MHz) propagation</li>
            <li><strong>Antenna Pattern Tests:</strong> Omnidirectional, directional (Yagi), vertical/horizontal polarization</li>
            <li><strong>Environmental Effects Tests:</strong> Weather impact, temperature, humidity, atmospheric pressure</li>
            <li><strong>Noise Floor Tests:</strong> Atmospheric noise (ITU-R P.372), man-made noise, galactic noise</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/radio_propagation_performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive radio propagation test report generated${NC}"

# 10. Summary
print_section "Radio Propagation Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/radio_propagation_html/index.html"
echo "Test report: $TEST_RESULTS_DIR/radio_propagation_test_report.html"

echo -e "\n${GREEN}=== All Radio Propagation Tests Completed ===${NC}"
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/radio_propagation_test_report.html in a web browser for a comprehensive overview."

cd ..

