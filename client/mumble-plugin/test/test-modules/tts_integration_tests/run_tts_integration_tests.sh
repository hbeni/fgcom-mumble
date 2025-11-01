#!/bin/bash

# TTS Integration Tests Runner
# This script runs comprehensive TTS integration tests
#
# @author FGcom-mumble Development Team
# @date 2025
# @see test/tts_integration_tests/

echo "=== TTS INTEGRATION TESTS ==="
echo "Date: $(date)"
echo "Project: fgcom-mumble"
echo "Module: TTS Integration"
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
    
    if [ -f "tts_integration_tests" ]; then
        echo "Running $test_name tests..."
        if ./tts_integration_tests $test_options 2>&1 | tee ../test-logs/tts_${test_name}_test_output.log; then
            local test_count=$(grep -c "\[  PASSED  \]" ../test-logs/tts_${test_name}_test_output.log 2>/dev/null || echo "0")
            local total_count=$(grep -c "\[  PASSED  \]\|\[  FAILED  \]" ../test-logs/tts_${test_name}_test_output.log 2>/dev/null || echo "0")
            
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
            if [ -f "tts_integration_tests" ]; then
                echo "Running $test_name tests..."
                if ./tts_integration_tests $test_options 2>&1 | tee ../test-logs/tts_${test_name}_test_output.log; then
                    local test_count=$(grep -c "\[  PASSED  \]" ../test-logs/tts_${test_name}_test_output.log 2>/dev/null || echo "0")
                    local total_count=$(grep -c "\[  PASSED  \]\|\[  FAILED  \]" ../test-logs/tts_${test_name}_test_output.log 2>/dev/null || echo "0")
                    
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
cd /home/haaken/github-projects/fgcom-mumble-dev/test/tts_integration_tests

echo "Running TTS Integration Tests..."
echo

# Run basic tests
run_test "basic" "" "Basic TTS integration functionality"

# Run Piper TTS tests
run_test "piper" "--gtest_filter=*Piper*" "Piper TTS integration and functionality"

# Run ATIS generation tests
run_test "atis" "--gtest_filter=*ATIS*" "ATIS text generation and processing"

# Run configuration tests
run_test "config" "--gtest_filter=*Config*" "TTS configuration management"

# Run performance tests
run_test "performance" "--gtest_filter=*Performance*" "Performance and benchmarking tests"

# Run thread safety tests
run_test "thread_safety" "--gtest_filter=*Thread*" "Thread safety and concurrency tests"

# Run error handling tests
run_test "error_handling" "--gtest_filter=*Error*" "Error handling and edge cases"

# Run integration tests
run_test "integration" "--gtest_filter=*Integration*" "Integration with FGcom-mumble server"

# Run all tests with verbose output
run_test "verbose" "--gtest_verbose" "All tests with verbose output"

# Generate comprehensive test results
echo "=========================================="
echo "TTS INTEGRATION TEST RESULTS"
echo "=========================================="
echo "Date: $(date)"
echo "Project: fgcom-mumble"
echo "Module: TTS Integration"
echo "Total Tests: $TOTAL_TESTS"
echo "Passed Tests: $PASSED_TESTS"
echo "Failed Tests: $FAILED_TESTS"
echo "Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
echo

echo "DETAILED RESULTS:"
echo "=================="
echo -e "$TEST_RESULTS"

# Save results to file
cat > ../test-logs/tts_integration_tests_$(date +%Y%m%d_%H%M%S).md << EOF
# TTS Integration Test Results

**Test Execution Date:** $(date)  
**Project:** fgcom-mumble  
**Module:** TTS Integration  
**Total Tests:** $TOTAL_TESTS  
**Passed Tests:** $PASSED_TESTS  
**Failed Tests:** $FAILED_TESTS  
**Success Rate:** $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%

## Test Categories

### TTS System Tests
- System initialization and configuration
- TTS model management
- Text processing and preprocessing
- Audio generation and validation

### Piper TTS Integration
- Piper TTS installation and setup
- Model loading and management
- Audio quality assessment
- Multiple language support
- Performance optimization

### ATIS Generation
- ATIS text generation
- Weather information processing
- Runway information formatting
- Airport code validation
- Phonetic alphabet conversion
- ATIS audio generation

### Configuration Management
- Configuration file loading
- Configuration validation
- Parameter management
- Default settings
- Custom configuration

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
- Validate TTS integration functionality
EOF

echo "Test results saved to ../test-logs/tts_integration_tests_$(date +%Y%m%d_%H%M%S).md"
echo "TTS Integration Tests completed!"
