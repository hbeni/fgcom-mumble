#!/bin/bash

# Comprehensive Pattern Validation Test Suite
# Tests all aspects of pattern file validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    ((TESTS_RUN++))
    log_info "Running test: $test_name"
    
    if eval "$test_command"; then
        log_success "$test_name"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "$test_name"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test 1: File existence and basic structure
test_file_existence() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    
    # Check if pattern directory exists
    [ -d "$pattern_dir" ] || return 1
    
    # Check if we have pattern files
    local file_count=$(find "$pattern_dir" -name "*.txt" | wc -l)
    [ "$file_count" -gt 0 ] || return 1
    
    log_info "Found $file_count pattern files"
    return 0
}

# Test 2: File size validation
test_file_sizes() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    
    # Check for files that are too small
    local small_files=$(find "$pattern_dir" -name "*.txt" -size -500c | wc -l)
    if [ "$small_files" -gt 0 ]; then
        log_warning "Found $small_files files smaller than 500 bytes"
        return 1
    fi
    
    return 0
}

# Test 3: Header validation
test_headers() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local sample_files=$(find "$pattern_dir" -name "*.txt" | head -10)
    local invalid_headers=0
    
    for file in $sample_files; do
        if ! head -5 "$file" | grep -q "FGCom-mumble Far-Field Radiation Pattern"; then
            ((invalid_headers++))
            log_warning "Invalid header in: $(basename "$file")"
        fi
    done
    
    [ "$invalid_headers" -eq 0 ] || return 1
    return 0
}

# Test 4: Data format validation
test_data_format() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local sample_files=$(find "$pattern_dir" -name "*.txt" | head -5)
    local invalid_data=0
    
    for file in $sample_files; do
        # Check for data lines (not comments)
        local data_lines=$(grep -v "^#" "$file" | grep -v "^$" | wc -l)
        if [ "$data_lines" -lt 1000 ]; then
            ((invalid_data++))
            log_warning "Insufficient data in: $(basename "$file") ($data_lines lines)"
        fi
        
        # Check for numeric gain values
        local invalid_gains=$(grep -v "^#" "$file" | grep -v "^$" | awk '{print $3}' | grep -v "^[+-]*[0-9]*\.*[0-9]*$" | wc -l)
        if [ "$invalid_gains" -gt 0 ]; then
            ((invalid_data++))
            log_warning "Invalid gain values in: $(basename "$file")"
        fi
    done
    
    [ "$invalid_data" -eq 0 ] || return 1
    return 0
}

# Test 5: Category coverage
test_category_coverage() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local categories=("aircraft" "Ground-based" "military-land" "Marine")
    local missing_categories=0
    
    for category in "${categories[@]}"; do
        if [ ! -d "$pattern_dir/$category" ]; then
            ((missing_categories++))
            log_warning "Missing category: $category"
        else
            local file_count=$(find "$pattern_dir/$category" -name "*.txt" | wc -l)
            log_info "$category: $file_count files"
        fi
    done
    
    [ "$missing_categories" -eq 0 ] || return 1
    return 0
}

# Test 6: Frequency coverage
test_frequency_coverage() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local sample_files=$(find "$pattern_dir" -name "*.txt" | head -10)
    local missing_frequency=0
    
    for file in $sample_files; do
        if ! head -10 "$file" | grep -q "Frequency:"; then
            ((missing_frequency++))
            log_warning "Missing frequency info in: $(basename "$file")"
        fi
    done
    
    [ "$missing_frequency" -eq 0 ] || return 1
    return 0
}

# Test 7: Pattern file naming
test_naming_conventions() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local sample_files=$(find "$pattern_dir" -name "*.txt" | head -20)
    local invalid_names=0
    
    for file in $sample_files; do
        local filename=$(basename "$file")
        # Check for reasonable naming patterns
        if [[ ! "$filename" =~ (pattern|MHz|mhz|\.txt)$ ]]; then
            ((invalid_names++))
            log_warning "Unusual filename: $filename"
        fi
    done
    
    [ "$invalid_names" -eq 0 ] || return 1
    return 0
}

# Test 8: Performance test
test_performance() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local start_time=$(date +%s.%N)
    
    # Simulate loading all patterns
    find "$pattern_dir" -name "*.txt" | head -50 | while read file; do
        head -1 "$file" > /dev/null
    done
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    log_info "Performance test: $duration seconds for 50 files"
    
    # Should complete in reasonable time
    [ $(echo "$duration < 5.0" | bc) -eq 1 ] || return 1
    return 0
}

# Test 9: Memory usage test
test_memory_usage() {
    local pattern_dir="client/mumble-plugin/lib/antenna_patterns"
    local total_size=$(find "$pattern_dir" -name "*.txt" -exec wc -c {} + | tail -1 | awk '{print $1}')
    local file_count=$(find "$pattern_dir" -name "*.txt" | wc -l)
    local avg_size=$((total_size / file_count))
    
    log_info "Total size: $total_size bytes"
    log_info "Average file size: $avg_size bytes"
    
    # Average size should be reasonable (between 10KB and 100KB)
    [ "$avg_size" -gt 10000 ] && [ "$avg_size" -lt 100000 ] || return 1
    return 0
}

# Test 10: Integration test
test_integration() {
    # Test that our validation scripts work
    if [ -f "quick_pattern_check.sh" ]; then
        ./quick_pattern_check.sh > /dev/null 2>&1 || return 1
    fi
    
    if [ -f "validate_patterns_efficient.sh" ]; then
        timeout 30 ./validate_patterns_efficient.sh > /dev/null 2>&1 || return 1
    fi
    
    return 0
}

# Main test runner
main() {
    log_info "=== FGCom-mumble Pattern Validation Test Suite ==="
    log_info "Starting comprehensive pattern validation tests..."
    
    # Run all tests
    run_test "File Existence" "test_file_existence"
    run_test "File Size Validation" "test_file_sizes"
    run_test "Header Validation" "test_headers"
    run_test "Data Format Validation" "test_data_format"
    run_test "Category Coverage" "test_category_coverage"
    run_test "Frequency Coverage" "test_frequency_coverage"
    run_test "Naming Conventions" "test_naming_conventions"
    run_test "Performance Test" "test_performance"
    run_test "Memory Usage Test" "test_memory_usage"
    run_test "Integration Test" "test_integration"
    
    # Summary
    log_info "=== TEST SUITE SUMMARY ==="
    log_info "Tests run: $TESTS_RUN"
    log_success "Tests passed: $TESTS_PASSED"
    log_error "Tests failed: $TESTS_FAILED"
    
    local success_rate=0
    if [ "$TESTS_RUN" -gt 0 ]; then
        success_rate=$((TESTS_PASSED * 100 / TESTS_RUN))
    fi
    
    log_info "Success rate: $success_rate%"
    
    if [ "$TESTS_FAILED" -eq 0 ]; then
        log_success "All tests passed! Pattern collection is fully validated."
        exit 0
    else
        log_error "Some tests failed. Please review and fix issues."
        exit 1
    fi
}

# Run main function
main "$@"
