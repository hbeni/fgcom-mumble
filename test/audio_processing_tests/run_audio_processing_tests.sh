#!/bin/bash

# Comprehensive Audio Processing Test Suite Runner
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

echo -e "${BLUE}=== Audio Processing Comprehensive Test Suite ===${NC}"
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
print_section "Building Audio Processing Test Suite"

cd $BUILD_DIR
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# 1. Basic Unit Tests
print_section "Running Basic Audio Processing Unit Tests"

echo "Running Google Test suite for audio processing..."
./audio_processing_tests --gtest_output=xml:../$TEST_RESULTS_DIR/audio_processing_basic_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Basic audio processing tests passed${NC}"
else
    echo -e "${RED}✗ Basic audio processing tests failed${NC}"
fi

# 2. Static Analysis
print_section "Running Static Analysis for Audio Processing"

echo "Running CppCheck on audio processing modules..."
cppcheck --enable=all --std=c++17 --xml --xml-version=2 \
    --output-file=../$TEST_RESULTS_DIR/audio_processing_cppcheck.xml \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    --suppress=unmatchedSuppression \
    ../../client/mumble-plugin/lib/audio.cpp \
    ../../client/mumble-plugin/lib/agc_squelch.cpp

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CppCheck completed for audio processing${NC}"
else
    echo -e "${YELLOW}⚠ CppCheck found issues in audio processing (see report)${NC}"
fi

echo "Running Clang-Tidy on audio processing modules..."
clang-tidy -checks='*' -header-filter='.*' \
    ../../client/mumble-plugin/lib/audio.cpp \
    ../../client/mumble-plugin/lib/agc_squelch.cpp \
    -- -std=c++17 -I../../client/mumble-plugin/lib > ../$TEST_RESULTS_DIR/audio_processing_clang-tidy.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Clang-Tidy completed for audio processing${NC}"
else
    echo -e "${YELLOW}⚠ Clang-Tidy found issues in audio processing (see report)${NC}"
fi

# 3. Memory Analysis with Valgrind
print_section "Running Memory Analysis with Valgrind for Audio Processing"

echo "Running Valgrind memory leak detection on audio processing tests..."
valgrind --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --xml=yes \
    --xml-file=../$TEST_RESULTS_DIR/audio_processing_valgrind.xml \
    ./audio_processing_tests --gtest_output=xml:../$TEST_RESULTS_DIR/audio_processing_valgrind_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Valgrind analysis completed for audio processing${NC}"
else
    echo -e "${YELLOW}⚠ Valgrind found memory issues in audio processing (see report)${NC}"
fi

# 4. AddressSanitizer Tests
print_section "Running AddressSanitizer Tests for Audio Processing"

echo "Running AddressSanitizer memory error detection on audio processing..."
./audio_processing_tests_asan --gtest_output=xml:../$TEST_RESULTS_DIR/audio_processing_asan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ AddressSanitizer tests passed for audio processing${NC}"
else
    echo -e "${RED}✗ AddressSanitizer found memory errors in audio processing${NC}"
fi

# 5. ThreadSanitizer Tests
print_section "Running ThreadSanitizer Tests for Audio Processing"

echo "Running ThreadSanitizer race condition detection on audio processing..."
./audio_processing_tests_tsan --gtest_output=xml:../$TEST_RESULTS_DIR/audio_processing_tsan_tests.xml

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ThreadSanitizer tests passed for audio processing${NC}"
else
    echo -e "${RED}✗ ThreadSanitizer found race conditions in audio processing${NC}"
fi

# 6. Code Coverage Analysis
print_section "Running Code Coverage Analysis for Audio Processing"

echo "Running coverage tests for audio processing..."
./audio_processing_tests_coverage --gtest_output=xml:../$TEST_RESULTS_DIR/audio_processing_coverage_tests.xml

echo "Generating coverage report for audio processing..."
lcov --capture --directory . --output-file ../$COVERAGE_DIR/audio_processing_coverage.info
lcov --remove ../$COVERAGE_DIR/audio_processing_coverage.info '/usr/*' --output-file ../$COVERAGE_DIR/audio_processing_coverage_filtered.info
genhtml ../$COVERAGE_DIR/audio_processing_coverage_filtered.info --output-directory ../$COVERAGE_DIR/audio_processing_html

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage report generated for audio processing${NC}"
    echo "Audio processing coverage report available at: $COVERAGE_DIR/audio_processing_html/index.html"
else
    echo -e "${YELLOW}⚠ Coverage report generation failed for audio processing${NC}"
fi

# 7. Performance Tests
print_section "Running Performance Tests for Audio Processing"

echo "Running performance benchmarks for audio processing..."
time ./audio_processing_tests --gtest_filter="*Performance*" > ../$TEST_RESULTS_DIR/audio_processing_performance.txt 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance tests completed for audio processing${NC}"
else
    echo -e "${YELLOW}⚠ Performance tests had issues for audio processing${NC}"
fi

# 8. Stress Tests
print_section "Running Stress Tests for Audio Processing"

echo "Running stress tests with high load for audio processing..."
for i in {1..5}; do
    echo "Audio processing stress test iteration $i/5"
    ./audio_processing_tests --gtest_filter="*Stress*" --gtest_repeat=10 > ../$TEST_RESULTS_DIR/audio_processing_stress_$i.txt 2>&1
done

echo -e "${GREEN}✓ Stress tests completed for audio processing${NC}"

# 9. Generate Comprehensive Report
print_section "Generating Comprehensive Audio Processing Test Report"

cat > ../$TEST_RESULTS_DIR/audio_processing_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Audio Processing Test Report</title>
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
        <h1>Audio Processing Comprehensive Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: Audio Processing Module</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>Codec Tests:</strong> Opus encoding/decoding, bitrate adaptation, packet loss concealment</li>
            <li><strong>Audio Effects:</strong> Background noise injection, squelch tail elimination, click removal</li>
            <li><strong>Sample Rate Conversion:</strong> Upsampling, downsampling, anti-aliasing, interpolation</li>
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
            <li><a href="audio_processing_basic_tests.xml">Basic Audio Processing Tests (XML)</a></li>
            <li><a href="audio_processing_valgrind.xml">Valgrind Memory Analysis</a></li>
            <li><a href="audio_processing_asan_tests.xml">AddressSanitizer Results</a></li>
            <li><a href="audio_processing_tsan_tests.xml">ThreadSanitizer Results</a></li>
            <li><a href="audio_processing_cppcheck.xml">CppCheck Static Analysis</a></li>
            <li><a href="audio_processing_clang-tidy.txt">Clang-Tidy Analysis</a></li>
            <li><a href="audio_processing_performance.txt">Performance Benchmarks</a></li>
        </ul>
    </div>

    <div class="section">
        <h2>Code Coverage</h2>
        <p>Coverage report: <a href="../coverage/audio_processing_html/index.html">HTML Coverage Report</a></p>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>Codec Tests:</strong> Opus encoding/decoding, bitrate adaptation, packet loss concealment, FEC, latency</li>
            <li><strong>Audio Effects Tests:</strong> Background noise injection, squelch tail elimination, click removal, limiting, compression</li>
            <li><strong>Sample Rate Conversion Tests:</strong> Upsampling (8k to 48k), downsampling (48k to 8k), arbitrary rate conversion, anti-aliasing, interpolation</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Execution Log</h2>
        <pre>$(cat ../$TEST_RESULTS_DIR/audio_processing_performance.txt 2>/dev/null || echo "Performance test log not available")</pre>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Comprehensive audio processing test report generated${NC}"

# 10. Summary
print_section "Audio Processing Test Suite Summary"

echo "Test results available in: $TEST_RESULTS_DIR/"
echo "Coverage report: $COVERAGE_DIR/audio_processing_html/index.html"
echo "Test report: $TEST_RESULTS_DIR/audio_processing_test_report.html"

echo -e "\n${GREEN}=== All Audio Processing Tests Completed ===${NC}"
echo "Check the test results directory for detailed reports."
echo "Open $TEST_RESULTS_DIR/audio_processing_test_report.html in a web browser for a comprehensive overview."

cd ..

