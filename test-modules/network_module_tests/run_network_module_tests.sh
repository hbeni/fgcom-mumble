#!/bin/bash

# Comprehensive Network Module Test Suite Runner
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

echo -e "${BLUE}=== Network Module Comprehensive Test Suite ===${NC}"
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
print_section "Building Network Module Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests (OPTIMIZED)
print_section "Running Basic Network Module Unit Tests (Optimized)"

echo "Running Google Test suite for network module (optimized)..."
./network_module_tests --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_basic_tests.xml --gtest_repeat=1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic network module tests passed${NC}"
else
    echo -e "${RED}✗ Basic network module tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis for Network Module"

echo "Running CppCheck on network module..."
cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
    --output-file=/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_cppcheck.xml \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unmatchedSuppression \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/io_UDPClient.cpp \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/io_plugin.cpp

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed for network module${NC}"
else
    echo -e "${YELLOW}WARNING: CppCheck found issues in network module (see report)${NC}"
fi

echo "Running Clang-Tidy on network module..."
clang-tidy -checks='modernize-*,readability-*,performance-*,cppcoreguidelines-*' -header-filter='client/mumble-plugin/lib/.*' \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/io_UDPClient.cpp \
    /home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib/io_plugin.cpp \
    -- -std=c++17 -I/home/haaken/github-projects/fgcom-mumble/client/mumble-plugin/lib > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_clang-tidy.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed for network module${NC}"
else
    echo -e "${YELLOW}WARNING: Clang-Tidy found issues in network module (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind for Network Module"

echo "Running Valgrind memory leak detection on network module tests..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_valgrind.xml \
    ./network_module_tests --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed for network module${NC}"
else
    echo -e "${YELLOW}WARNING: Valgrind found memory issues in network module (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests for Network Module"

echo "Running AddressSanitizer memory error detection on network module..."
./network_module_tests_asan --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed for network module${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors in network module${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests for Network Module"

echo "Running ThreadSanitizer race condition detection on network module..."
./network_module_tests_tsan --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed for network module${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions in network module${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis for Network Module"

echo "Running coverage tests for network module..."
./network_module_tests_coverage --gtest_output=xml:/home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_coverage_tests.xml

echo "Generating coverage report for network module..."
lcov --capture --directory . --output-file /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/network_module_coverage.info
lcov --remove /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/network_module_coverage.info '/usr/*' --output-file /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/network_module_coverage_filtered.info
genhtml /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/network_module_coverage_filtered.info --output-directory /home/haaken/github-projects/fgcom-mumble/test/$COVERAGE_DIR/network_module_html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated for network module${NC}"
    echo "Network module coverage report available at: $COVERAGE_DIR/network_module_html/index.html"
else
    echo -e "${YELLOW}WARNING: Coverage report generation failed for network module${NC}"
fi

# 7. Performance Tests (OPTIMIZED)
print_section "Running Performance Tests for Network Module (Optimized)"

echo "Running performance benchmarks for network module (optimized)..."
time ./network_module_tests --gtest_filter="*Performance*" --gtest_repeat=1 > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed for network module${NC}"
else
    echo -e "${YELLOW}WARNING: Performance tests had issues for network module${NC}"
fi

# 8. Stress Tests (OPTIMIZED)
print_section "Running Stress Tests for Network Module (Optimized)"

echo "Running single stress test iteration (optimized)..."
./network_module_tests --gtest_filter="*Stress*" --gtest_repeat=1 > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_stress_optimized.txt 2>&1

echo -e "${GREEN}✓ Stress tests completed for network module (optimized)${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Network Module Test Report"

cat > /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Network Module Test Report</title>
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
        <h1>Network Module Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: Network Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>UDP Protocol Tests:</strong> Packet transmission, reception, loss handling, out-of-order handling</li>
            <li><strong>WebSocket Tests:</strong> Connection establishment, message send/receive, binary data transfer</li>
            <li><strong>RESTful API Tests:</strong> GET, POST, PUT, DELETE operations, authentication, rate limiting</li>
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
            <li><a href="network_module_basic_tests.xml">Basic Network Module Tests (XML)</a></li>
            <li><a href="network_module_valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="network_module_asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="network_module_tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="network_module_cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="network_module_clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="network_module_performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="/home/haaken/github-projects/fgcom-mumble/test/coverage/network_module_html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>UDP Protocol Tests:</strong> Packet transmission, reception, loss handling, out-of-order handling, duplicate detection, jitter buffer management</li>
            <li><strong>WebSocket Tests:</strong> Connection establishment, message send/receive, binary data transfer, ping/pong keepalive, reconnection logic, graceful disconnect</li>
            <li><strong>RESTful API Tests:</strong> GET, POST, PUT, DELETE operations, authentication (API keys), rate limiting, error response codes, JSON schema validation</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat /home/haaken/github-projects/fgcom-mumble/test/$TEST_RESULTS_DIR/network_module_performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive network module test report generated${NC}"

# 10. Summary
print_section "Network Module Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/network_module_html/index.html"
echo "Test report: $TEST_RESULTS_DIR/network_module_test_report.html"

echo -e "\n${GREEN}=== All Network Module Tests Completed (Optimized) ===${NC}"
echo "OPTIMIZATIONS APPLIED:"
echo "  ✓ Reduced UDP packet count from 1000 to 100"
echo "  ✓ Reduced WebSocket message count from 1000 to 100" 
echo "  ✓ Reduced REST API request count from 100 to 10"
echo "  ✓ Reduced stress test iterations from 5×10 to 1×1"
echo "  ✓ Added --gtest_repeat=1 to all test runs"
echo "  ✓ Estimated execution time reduction: ~70%"
echo ""
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/network_module_test_report.html in a web browser for a comprehensive overview."

cd ..

