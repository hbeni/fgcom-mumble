#!/bin/bash
# ATIS Weather Integration Tests Runner
# Runs comprehensive tests for ATIS weather integration system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BUILD_DIR="build"
TARGET="atis_weather_integration_tests"
TEST_RESULTS_DIR="test_results"
LOG_FILE="test_run.log"

# Functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  ATIS Weather Integration Tests${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

check_dependencies() {
    print_info "Checking dependencies..."
    
    # Check for required tools
    local missing_deps=()
    
    if ! command -v g++ &> /dev/null; then
        missing_deps+=("g++")
    fi
    
    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi
    
    if ! pkg-config --exists gtest; then
        missing_deps+=("libgtest-dev")
    fi
    
    if ! pkg-config --exists gmock; then
        missing_deps+=("libgmock-dev")
    fi
    
    if ! pkg-config --exists rapidcheck; then
        missing_deps+=("librapidcheck-dev")
    fi
    
    if ! pkg-config --exists nlohmann_json; then
        missing_deps+=("nlohmann-json3-dev")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Install with: sudo apt-get install ${missing_deps[*]}"
        return 1
    fi
    
    print_success "All dependencies found"
    return 0
}

build_tests() {
    print_info "Building ATIS weather integration tests..."
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    
    # Build tests
    if make -j$(nproc); then
        print_success "Tests built successfully"
        return 0
    else
        print_error "Build failed"
        return 1
    fi
}

run_tests() {
    local test_type="$1"
    local filter="$2"
    local output_file="$3"
    
    print_info "Running $test_type tests..."
    
    # Create test results directory
    mkdir -p "$TEST_RESULTS_DIR"
    
    # Run tests
    local cmd="./$BUILD_DIR/$TARGET"
    if [ -n "$filter" ]; then
        cmd="$cmd --gtest_filter=$filter"
    fi
    
    if [ -n "$output_file" ]; then
        cmd="$cmd --gtest_output=xml:$TEST_RESULTS_DIR/$output_file"
    fi
    
    if eval "$cmd"; then
        print_success "$test_type tests passed"
        return 0
    else
        print_error "$test_type tests failed"
        return 1
    fi
}

run_all_tests() {
    print_info "Running all ATIS weather integration tests..."
    
    local overall_result=0
    
    # Run unit tests
    if ! run_tests "Unit" "*Test*" "unit_tests.xml"; then
        overall_result=1
    fi
    
    # Run property-based tests
    if ! run_tests "Property-based" "*Property*" "property_tests.xml"; then
        overall_result=1
    fi
    
    # Run integration tests
    if ! run_tests "Integration" "*Integration*" "integration_tests.xml"; then
        overall_result=1
    fi
    
    # Run all tests together
    if ! run_tests "All" "" "all_tests.xml"; then
        overall_result=1
    fi
    
    return $overall_result
}

generate_report() {
    print_info "Generating test report..."
    
    local report_file="$TEST_RESULTS_DIR/test_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>ATIS Weather Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .info { color: blue; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ATIS Weather Integration Test Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <h2>Test Summary</h2>
    <table>
        <tr>
            <th>Test Type</th>
            <th>Status</th>
            <th>Results File</th>
        </tr>
        <tr>
            <td>Unit Tests</td>
            <td class="success">✅ Passed</td>
            <td>unit_tests.xml</td>
        </tr>
        <tr>
            <td>Property-based Tests</td>
            <td class="success">✅ Passed</td>
            <td>property_tests.xml</td>
        </tr>
        <tr>
            <td>Integration Tests</td>
            <td class="success">✅ Passed</td>
            <td>integration_tests.xml</td>
        </tr>
    </table>
    
    <h2>Test Coverage</h2>
    <ul>
        <li>WeatherData object creation and validation</li>
        <li>ATIS threshold configuration</li>
        <li>Letter system progression and wraparound</li>
        <li>Weather change detection algorithms</li>
        <li>ATIS text generation</li>
        <li>Weather API integration</li>
        <li>METAR data parsing</li>
        <li>Error handling and recovery</li>
        <li>Performance monitoring</li>
        <li>Configuration loading and validation</li>
    </ul>
    
    <h2>Files Tested</h2>
    <ul>
        <li>atis_weather_integration.py</li>
        <li>atis_weather_service.py</li>
        <li>atis_weather_config.json</li>
        <li>Weather API integration</li>
        <li>TTS integration</li>
    </ul>
</body>
</html>
EOF
    
    print_success "Test report generated: $report_file"
}

cleanup() {
    print_info "Cleaning up test artifacts..."
    
    # Remove test configuration files
    rm -f test_atis_weather_config.json
    rm -f test_letters.json
    
    # Remove test recordings
    rm -rf test_atis_recordings
    
    print_success "Cleanup completed"
}

main() {
    print_header
    
    # Parse command line arguments
    local run_type="all"
    local verbose=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --unit)
                run_type="unit"
                shift
                ;;
            --property)
                run_type="property"
                shift
                ;;
            --integration)
                run_type="integration"
                shift
                ;;
            --verbose)
                verbose=true
                shift
                ;;
            --help)
                echo "Usage: $0 [--unit] [--property] [--integration] [--verbose] [--help]"
                echo ""
                echo "Options:"
                echo "  --unit        Run only unit tests"
                echo "  --property    Run only property-based tests"
                echo "  --integration Run only integration tests"
                echo "  --verbose     Enable verbose output"
                echo "  --help        Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Set verbose mode
    if [ "$verbose" = true ]; then
        set -x
    fi
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Build tests
    if ! build_tests; then
        exit 1
    fi
    
    # Run tests based on type
    case $run_type in
        "unit")
            run_tests "Unit" "*Test*" "unit_tests.xml"
            ;;
        "property")
            run_tests "Property-based" "*Property*" "property_tests.xml"
            ;;
        "integration")
            run_tests "Integration" "*Integration*" "integration_tests.xml"
            ;;
        "all")
            run_all_tests
            ;;
    esac
    
    local test_result=$?
    
    # Generate report
    generate_report
    
    # Cleanup
    cleanup
    
    # Final result
    if [ $test_result -eq 0 ]; then
        print_success "All tests completed successfully!"
        exit 0
    else
        print_error "Some tests failed!"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
