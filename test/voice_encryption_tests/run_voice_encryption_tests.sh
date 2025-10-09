#!/bin/bash

# Voice Encryption Tests Runner
# This script runs comprehensive voice encryption tests
#
# @author FGcom-mumble Development Team
# @date 2025
# @see test/voice_encryption_tests/

echo "=== VOICE ENCRYPTION TESTS ==="
echo "Date: $(date)"
echo "Project: fgcom-mumble"
echo "Module: Voice Encryption"
echo

# Initialize test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
TEST_RESULTS=""

# Function to run a test with specific options
run_test() {
    local test_name="$1"
    local test_options="$2"
    local test_description="$3"
    
    echo "=========================================="
    echo "Testing: $test_name"
    echo "Description: $test_description"
    echo "=========================================="
    
    if [ -f "voice_encryption_tests" ]; then
        echo "Running $test_name tests..."
        if ./voice_encryption_tests $test_options 2>&1 | tee ../test-logs/voice_${test_name}_test_output.log; then
            local test_count=$(grep -c "\[  PASSED  \]" ../test-logs/voice_${test_name}_test_output.log 2>/dev/null || echo "0")
            local total_count=$(grep -c "\[  PASSED  \]\|\[  FAILED  \]" ../test-logs/voice_${test_name}_test_output.log 2>/dev/null || echo "0")
            
            TEST_RESULTS+="PASS $test_name: $test_count/$total_count tests passed\n"
            PASSED_TESTS=$((PASSED_TESTS + test_count))
            TOTAL_TESTS=$((TOTAL_TESTS + total_count))
        else
            TEST_RESULTS+="FAIL $test_name: Tests failed\n"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        echo "Executable not found, building first..."
        if make clean && make -j$(nproc) 2>/dev/null; then
            if [ -f "voice_encryption_tests" ]; then
                echo "Running $test_name tests..."
                if ./voice_encryption_tests $test_options 2>&1 | tee ../test-logs/voice_${test_name}_test_output.log; then
                    local test_count=$(grep -c "\[  PASSED  \]" ../test-logs/voice_${test_name}_test_output.log 2>/dev/null || echo "0")
                    local total_count=$(grep -c "\[  PASSED  \]\|\[  FAILED  \]" ../test-logs/voice_${test_name}_test_output.log 2>/dev/null || echo "0")
                    
                    TEST_RESULTS+="PASS $test_name: $test_count/$total_count tests passed\n"
                    PASSED_TESTS=$((PASSED_TESTS + test_count))
                    TOTAL_TESTS=$((TOTAL_TESTS + total_count))
                else
                    TEST_RESULTS+="FAIL $test_name: Tests failed\n"
                    FAILED_TESTS=$((FAILED_TESTS + 1))
                fi
            else
                TEST_RESULTS+="FAIL $test_name: Build failed\n"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            fi
        else
            TEST_RESULTS+="FAIL $test_name: Build failed\n"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi
    echo
}

# Create test logs directory
mkdir -p ../test-logs

# Change to test directory
cd /home/haaken/github-projects/fgcom-mumble-dev/test/voice_encryption_tests

echo "Running Voice Encryption Tests..."
echo

# Run basic tests
run_test "basic" "" "Basic voice encryption functionality"

# Run Cold War era encryption tests
run_test "yachta" "--gtest_filter=*Yachta*" "Yachta T-219 Soviet voice encryption system"

run_test "vinson" "--gtest_filter=*Vinson*" "VINSON KY-57 NATO digital voice encryption"

run_test "granit" "--gtest_filter=*Granit*" "Granit Soviet time-domain scrambling"

run_test "stanag" "--gtest_filter=*STANAG*" "STANAG 4197 NATO QPSK OFDM digital voice"

# Run modern encryption tests
run_test "freedv" "--gtest_filter=*FreeDV*" "FreeDV modern digital voice system"

run_test "melpe" "--gtest_filter=*MELPe*" "MELPe NATO standard vocoder (STANAG 4591)"

# Run performance tests
run_test "performance" "--gtest_filter=*Performance*" "Performance and benchmarking tests"

# Run thread safety tests
run_test "thread_safety" "--gtest_filter=*Thread*" "Thread safety and concurrency tests"

# Run error handling tests
run_test "error_handling" "--gtest_filter=*Error*" "Error handling and edge cases"

# Run interception analysis tests
run_test "interception" "--gtest_filter=*Interception*" "Interception characteristics analysis"

# Run degradation analysis tests
run_test "degradation" "--gtest_filter=*Degradation*" "Degradation under poor conditions analysis"

# Run all tests with verbose output
run_test "verbose" "--gtest_verbose" "All tests with verbose output"

# Generate comprehensive test results
echo "=========================================="
echo "VOICE ENCRYPTION TEST RESULTS"
echo "=========================================="
echo "Date: $(date)"
echo "Project: fgcom-mumble"
echo "Module: Voice Encryption"
echo "Total Tests: $TOTAL_TESTS"
echo "Passed Tests: $PASSED_TESTS"
echo "Failed Tests: $FAILED_TESTS"
echo "Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
echo

echo "DETAILED RESULTS:"
echo "=================="
echo -e "$TEST_RESULTS"

# Save results to file
cat > ../test-logs/voice_encryption_tests_$(date +%Y%m%d_%H%M%S).md << EOF
# Voice Encryption Test Results

**Test Execution Date:** $(date)  
**Project:** fgcom-mumble  
**Module:** Voice Encryption  
**Total Tests:** $TOTAL_TESTS  
**Passed Tests:** $PASSED_TESTS  
**Failed Tests:** $FAILED_TESTS  
**Success Rate:** $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%

## Test Categories

### Cold War Era Encryption Systems
- **Yachta T-219**: Soviet frequency-domain scrambling
- **VINSON KY-57**: NATO digital CVSD secure voice
- **Granit**: Soviet time-domain scrambling
- **STANAG 4197**: NATO QPSK OFDM digital voice

### Modern Encryption Systems
- **FreeDV**: Modern digital voice, OFDM, multiple bitrate modes
- **MELPe**: NATO standard vocoder (STANAG 4591), 2400 bps

### Analysis Categories
- **Degradation Analysis**: Performance under poor conditions
- **Interception Analysis**: SIGINT characteristics and identifiability
- **Performance Testing**: Benchmarking and optimization
- **Thread Safety**: Concurrent operation testing
- **Error Handling**: Edge cases and failure scenarios

## Detailed Test Results

$(echo -e "$TEST_RESULTS")

## Summary
- **Total Test Execution Time:** $(date)
- **Test Environment:** Linux $(uname -r)
- **Compiler:** $(g++ --version | head -n1)
- **Build System:** Make + CMake

## Next Steps
- Review failed tests and fix issues
- Update documentation if needed
- Run performance benchmarks
- Validate voice encryption functionality
EOF

echo "Test results saved to ../test-logs/voice_encryption_tests_$(date +%Y%m%d_%H%M%S).md"
echo "Voice Encryption Tests completed!"
