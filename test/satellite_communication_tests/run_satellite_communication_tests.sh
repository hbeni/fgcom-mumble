#!/bin/bash

# Satellite Communication Tests Runner
# This script runs comprehensive satellite communication tests
#
# @author FGcom-mumble Development Team
# @date 2025
# @see test/satellite_communication_tests/

echo "=== SATELLITE COMMUNICATION TESTS ==="
echo "Date: $(date)"
echo "Project: fgcom-mumble"
echo "Module: Satellite Communication"
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
    
    if [ -f "satellite_communication_tests" ]; then
        echo "Running $test_name tests..."
        if ./satellite_communication_tests $test_options 2>&1 | tee ../test-logs/satellite_${test_name}_test_output.log; then
            local test_count=$(grep -c "\[  PASSED  \]" ../test-logs/satellite_${test_name}_test_output.log 2>/dev/null || echo "0")
            local total_count=$(grep -c "\[  PASSED  \]\|\[  FAILED  \]" ../test-logs/satellite_${test_name}_test_output.log 2>/dev/null || echo "0")
            
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
            if [ -f "satellite_communication_tests" ]; then
                echo "Running $test_name tests..."
                if ./satellite_communication_tests $test_options 2>&1 | tee ../test-logs/satellite_${test_name}_test_output.log; then
                    local test_count=$(grep -c "\[  PASSED  \]" ../test-logs/satellite_${test_name}_test_output.log 2>/dev/null || echo "0")
                    local total_count=$(grep -c "\[  PASSED  \]\|\[  FAILED  \]" ../test-logs/satellite_${test_name}_test_output.log 2>/dev/null || echo "0")
                    
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
cd /home/haaken/github-projects/fgcom-mumble-dev/test/satellite_communication_tests

echo "Running Satellite Communication Tests..."
echo

# Run basic tests
run_test "basic" "" "Basic satellite communication functionality"

# Run military satellite tests
run_test "military" "--gtest_filter=*Military*" "Military satellite systems (Strela-3, FLTSATCOM, Tsiklon)"

# Run amateur satellite tests
run_test "amateur" "--gtest_filter=*Amateur*" "Amateur radio satellites (AO-7, FO-29, AO-73, XW-2, SO-50, AO-91, AO-85, ISS)"

# Run IoT satellite tests
run_test "iot" "--gtest_filter=*IoT*" "IoT satellites (Orbcomm, Gonets)"

# Run orbital mechanics tests
run_test "orbital" "--gtest_filter=*Orbital*" "Orbital mechanics and TLE support"

# Run performance tests
run_test "performance" "--gtest_filter=*Performance*" "Performance and benchmarking tests"

# Run thread safety tests
run_test "thread_safety" "--gtest_filter=*Thread*" "Thread safety and concurrency tests"

# Run error handling tests
run_test "error_handling" "--gtest_filter=*Error*" "Error handling and edge cases"

# Run integration tests
run_test "integration" "--gtest_filter=*Integration*" "Integration with voice encryption systems"

# Run all tests with verbose output
run_test "verbose" "--gtest_verbose" "All tests with verbose output"

# Generate comprehensive test results
echo "=========================================="
echo "SATELLITE COMMUNICATION TEST RESULTS"
echo "=========================================="
echo "Date: $(date)"
echo "Project: fgcom-mumble"
echo "Module: Satellite Communication"
echo "Total Tests: $TOTAL_TESTS"
echo "Passed Tests: $PASSED_TESTS"
echo "Failed Tests: $FAILED_TESTS"
echo "Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
echo

echo "DETAILED RESULTS:"
echo "=================="
echo -e "$TEST_RESULTS"

# Save results to file
cat > ../test-logs/satellite_communication_tests_$(date +%Y%m%d_%H%M%S).md << EOF
# Satellite Communication Test Results

**Test Execution Date:** $(date)  
**Project:** fgcom-mumble  
**Module:** Satellite Communication  
**Total Tests:** $TOTAL_TESTS  
**Passed Tests:** $PASSED_TESTS  
**Failed Tests:** $FAILED_TESTS  
**Success Rate:** $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%

## Test Categories

### Military Satellites
- Strela-3 series (LEO Store-and-Forward)
- FLTSATCOM series (GEO UHF)
- Tsiklon/Tsikada Navigation

### Amateur Radio Satellites
- Linear Transponder Satellites (AO-7, FO-29, AO-73, XW-2 series)
- FM Voice Repeater Satellites (SO-50, AO-91, AO-85, ISS)
- Digital/Data Mode Satellites (NO-84, LilacSat-2, AO-95)

### IoT Satellites
- Orbcomm (LEO Data/IoT)
- Gonets (Russian IoT equivalent)

### Orbital Mechanics
- TLE (Two-Line Element) support
- SGP4/SDP4 algorithms
- Satellite tracking and visibility
- Doppler shift compensation

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
- Validate satellite communication functionality
EOF

echo "Test results saved to ../test-logs/satellite_communication_tests_$(date +%Y%m%d_%H%M%S).md"
echo "Satellite Communication Tests completed!"
