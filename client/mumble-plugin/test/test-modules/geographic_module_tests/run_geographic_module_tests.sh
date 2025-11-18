#!/bin/bash

# Comprehensive Geographic Module Test Suite Runner
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

echo -e "${BLUE}=== Geographic Module Comprehensive Test Suite ===${NC}"
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

# Check for gtest via pkg-config
if pkg-config --exists gtest; then
    echo -e "${GREEN}✓${NC} gtest found"
else
    echo -e "${RED}✗${NC} gtest not found"
    MISSING_TOOLS+=("gtest")
fi

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${RED}Missing required tools: ${MISSING_TOOLS[*]}${NC}"
    echo "Please install missing tools before running tests"
    exit 1
fi

# Build tests
print_section "Building Geographic Module Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests
print_section "Running Basic Geographic Module Unit Tests"

echo "Running Google Test suite for geographic module..."
./geographic_module_tests --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_basic_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic geographic module tests passed${NC}"
else
    echo -e "${RED}✗ Basic geographic module tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis for Geographic Module"

echo "Running CppCheck on geographic module..."
cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
    --output-file=/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_cppcheck.xml \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unmatchedSuppression \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/terrain_elevation.cpp \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/terrain_environmental_api.cpp \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/vehicle_dynamics.cpp

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed for geographic module${NC}"
else
    echo -e "${YELLOW}WARNING: CppCheck found issues in geographic module (see report)${NC}"
fi

echo "Running Clang-Tidy on geographic module..."
clang-tidy -checks='modernize-*,readability-*,performance-*,cppcoreguidelines-*' -header-filter='^client/mumble-plugin/lib/.*' \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/terrain_elevation.cpp \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/terrain_environmental_api.cpp \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/vehicle_dynamics.cpp \
    -- -std=c++17 -I/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_clang-tidy.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed for geographic module${NC}"
else
    echo -e "${YELLOW}WARNING: Clang-Tidy found issues in geographic module (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind for Geographic Module"

echo "Running Valgrind memory leak detection on geographic module tests..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_valgrind.xml \
    ./geographic_module_tests --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed for geographic module${NC}"
else
    echo -e "${YELLOW}WARNING: Valgrind found memory issues in geographic module (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests for Geographic Module"

echo "Running AddressSanitizer memory error detection on geographic module..."
./geographic_module_tests_asan --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed for geographic module${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors in geographic module${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests for Geographic Module"

echo "Running ThreadSanitizer race condition detection on geographic module..."
./geographic_module_tests_tsan --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed for geographic module${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions in geographic module${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis for Geographic Module"

echo "Running coverage tests for geographic module..."
./geographic_module_tests_coverage --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_coverage_tests.xml

echo "Generating coverage report for geographic module..."
lcov --capture --directory . --output-file /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/geographic_module_coverage.info
lcov --remove /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/geographic_module_coverage.info '/usr/*' --output-file /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/geographic_module_coverage_filtered.info
genhtml /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/geographic_module_coverage_filtered.info --output-directory /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/geographic_module_html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated for geographic module${NC}"
    echo "Geographic module coverage report available at: $COVERAGE_DIR/geographic_module_html/index.html"
else
    echo -e "${YELLOW}WARNING: Coverage report generation failed for geographic module${NC}"
fi

# 7. Performance Tests
print_section "Running Performance Tests for Geographic Module"

echo "Running performance benchmarks for geographic module..."
time ./geographic_module_tests --gtest_filter="*Performance*" > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed for geographic module${NC}"
else
    echo -e "${YELLOW}WARNING: Performance tests had issues for geographic module${NC}"
fi

# 8. Stress Tests
print_section "Running Stress Tests for Geographic Module"

echo "Running stress tests with high load for geographic module..."
for i in {1..5}; do
    echo "Geographic module stress test iteration $i/5"
    ./geographic_module_tests --gtest_filter="*Stress*" --gtest_repeat=10 > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_stress_$i.txt 2>&1
done

echo -e "${GREEN}✓ Stress tests completed for geographic module${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Geographic Module Test Report"

cat > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Geographic Module Test Report</title>
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
        <h1>Geographic Module Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: Geographic Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>Coordinate System Tests:</strong> Lat/lon to Cartesian conversion, distance calculation, bearing calculation</li>
            <li><strong>Terrain Data Tests:</strong> ASTER GDEM data loading, elevation lookup, interpolation, missing data handling</li>
            <li><strong>Vehicle Dynamics Tests:</strong> Position tracking, velocity calculation, heading/bearing, antenna orientation</li>
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
            <li><a href="geographic_module_basic_tests.xml">Basic Geographic Module Tests (XML)</a></li>
            <li><a href="geographic_module_valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="geographic_module_asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="geographic_module_tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="geographic_module_cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="geographic_module_clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="geographic_module_performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="/home/haaken/github-projects/fgcom-mumble/test/coverage/geographic_module_html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>Coordinate System Tests:</strong> Lat/lon to Cartesian conversion, distance calculation, bearing calculation, coordinate validation, WGS84 datum conversion</li>
            <li><strong>Terrain Data Tests:</strong> ASTER GDEM data loading, elevation lookup, interpolation, missing data handling, terrain profile generation, multi-polygon support</li>
            <li><strong>Vehicle Dynamics Tests:</strong> Position tracking, velocity calculation, heading/bearing, altitude changes, antenna orientation, mobile vs stationary detection</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/geographic_module_performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive geographic module test report generated${NC}"

# 10. Summary
print_section "Geographic Module Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/geographic_module_html/index.html"
echo "Test report: $TEST_RESULTS_DIR/geographic_module_test_report.html"

echo -e "\n${GREEN}=== All Geographic Module Tests Completed ===${NC}"
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/geographic_module_test_report.html in a web browser for a comprehensive overview."

cd ..

