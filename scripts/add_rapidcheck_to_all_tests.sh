#!/bin/bash

# Script to add RapidCheck property-based testing to all test modules
# This script automatically updates CMakeLists.txt files and creates property-based test files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$PROJECT_ROOT/test"
RAPIDCHECK_DIR="$TEST_DIR/rapidcheck_tests/lib/rapidcheck"

print_status "Adding RapidCheck to all test modules in $PROJECT_ROOT"

# Check if RapidCheck directory exists
if [ ! -d "$RAPIDCHECK_DIR" ]; then
    print_error "RapidCheck directory not found at $RAPIDCHECK_DIR"
    print_status "Please run the RapidCheck setup first"
    exit 1
fi

# List of test modules to update
TEST_MODULES=(
    "agc_squelch_tests"
    "antenna_pattern_module_tests"
    "atis_module_tests"
    "audio_processing_tests"
    "client_plugin_module_tests"
    "database_configuration_module_tests"
    "error_handling_tests"
    "frequency_management_tests"
    "geographic_module_tests"
    "integration_tests"
    "network_module_tests"
    "openstreetmap_infrastructure_tests"
    "performance_tests"
    "professional_audio_tests"
    "radio_propagation_tests"
    "security_module_tests"
    "status_page_module_tests"
    "webrtc_api_tests"
    "work_unit_distribution_module_tests"
)

# Function to update CMakeLists.txt for a test module
update_cmake() {
    local module_dir="$TEST_DIR/$1"
    local cmake_file="$module_dir/CMakeLists.txt"
    
    if [ ! -f "$cmake_file" ]; then
        print_warning "CMakeLists.txt not found for $1, skipping"
        return
    fi
    
    print_status "Updating CMakeLists.txt for $1"
    
    # Create backup
    cp "$cmake_file" "$cmake_file.backup"
    
    # Check if RapidCheck is already added
    if grep -q "RAPIDCHECK_DIR" "$cmake_file"; then
        print_warning "RapidCheck already added to $1, skipping"
        return
    fi
    
    # Add RapidCheck setup after find_package calls
    sed -i '/find_package.*REQUIRED/a\
\
# RapidCheck setup\
set(RAPIDCHECK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rapidcheck_tests/lib/rapidcheck")\
set(RAPIDCHECK_INCLUDE_DIR "${RAPIDCHECK_DIR}/include")\
set(RAPIDCHECK_SRC_DIR "${RAPIDCHECK_DIR}/src")\
\
# Add RapidCheck as subdirectory if not already added\
if(NOT TARGET rapidcheck)\
    add_subdirectory(${RAPIDCHECK_DIR} rapidcheck)\
endif()\
' "$cmake_file"
    
    # Add RapidCheck include directory
    sed -i '/include_directories(/a\
    ${RAPIDCHECK_INCLUDE_DIR}\
' "$cmake_file"
    
    # Add RapidCheck to link libraries
    sed -i '/target_link_libraries.*{/a\
    rapidcheck\
' "$cmake_file"
    
    print_success "Updated CMakeLists.txt for $1"
}

# Function to create property-based test file for a module
create_property_test() {
    local module_dir="$TEST_DIR/$1"
    local test_file="$module_dir/test_${1}_tests_properties.cpp"
    
    if [ -f "$test_file" ]; then
        print_warning "Property test file already exists for $1, skipping"
        return
    fi
    
    print_status "Creating property-based test file for $1"
    
    # Create a basic property-based test file
    cat > "$test_file" << EOF
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <gtest/gtest.h>
#include <cmath>
#include <algorithm>
#include <vector>
#include <limits>

// Mock classes for $1 property-based testing
class ${1^}Processor {
public:
    // Add your mock classes and methods here
    // This is a template that should be customized for each module
    
    struct TestData {
        double value;
        std::string name;
        bool enabled;
    };
    
    // Example property-based method
    static bool isValidData(const TestData& data) {
        return data.value >= 0.0 && !data.name.empty() && data.enabled;
    }
    
    // Example calculation method
    static double calculateResult(const TestData& data) {
        return data.value * 2.0;
    }
};

// Property-based tests for $1
RC_GTEST_PROP(${1^}ProcessorTests,
              DataValidation,
              (${1^}Processor::TestData data)) {
    RC_PRE(data.value >= 0.0);
    RC_PRE(!data.name.empty());
    
    bool is_valid = ${1^}Processor::isValidData(data);
    RC_ASSERT(is_valid);
}

RC_GTEST_PROP(${1^}ProcessorTests,
              CalculationConsistency,
              (${1^}Processor::TestData data)) {
    RC_PRE(data.value >= 0.0);
    
    double result = ${1^}Processor::calculateResult(data);
    RC_ASSERT(result >= 0.0);
    RC_ASSERT(result == data.value * 2.0);
}

// Custom generators for $1 testing
namespace rc {
    template<>
    struct Arbitrary<${1^}Processor::TestData> {
        static Gen<${1^}Processor::TestData> arbitrary() {
            return gen::construct<${1^}Processor::TestData>(
                gen::inRange(0.0, 1000.0),      // value
                gen::arbitrary<std::string>(),   // name
                gen::arbitrary<bool>()          // enabled
            );
        }
    };
}
EOF
    
    print_success "Created property-based test file for $1"
}

# Function to add property test to CMakeLists.txt
add_property_test_to_cmake() {
    local module_dir="$TEST_DIR/$1"
    local cmake_file="$module_dir/CMakeLists.txt"
    
    if [ ! -f "$cmake_file" ]; then
        return
    fi
    
    # Check if property test is already added
    if grep -q "test_${1}_tests_properties.cpp" "$cmake_file"; then
        print_warning "Property test already added to CMakeLists.txt for $1"
        return
    fi
    
    # Add property test to source files
    sed -i "/set(TEST_SOURCES/a\\
    test_${1}_tests_properties.cpp\\
" "$cmake_file"
    
    print_success "Added property test to CMakeLists.txt for $1"
}

# Main execution
print_status "Starting RapidCheck integration for all test modules..."

for module in "${TEST_MODULES[@]}"; do
    print_status "Processing module: $module"
    
    # Update CMakeLists.txt
    update_cmake "$module"
    
    # Create property-based test file
    create_property_test "$module"
    
    # Add property test to CMakeLists.txt
    add_property_test_to_cmake "$module"
    
    print_success "Completed processing for $module"
    echo "---"
done

print_success "RapidCheck integration completed for all test modules!"
print_status "Summary:"
print_status "- Updated CMakeLists.txt files to include RapidCheck"
print_status "- Created property-based test files for each module"
print_status "- Added property tests to build configurations"

print_warning "Note: The generated property-based test files are templates."
print_warning "You should customize them with specific properties for each module."

print_status "To build and run the tests:"
print_status "cd test/[module_name] && mkdir build && cd build && cmake .. && make"
print_status "Then run: ./[module_name]_tests"
