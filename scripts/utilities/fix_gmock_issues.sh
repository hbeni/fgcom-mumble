#!/bin/bash

# Script to fix GMock CMake configuration issues in all test suites

echo "Fixing GMock CMake configuration issues..."

# List of test suites with GMock issues
test_suites=(
    "test/network_module_tests"
    "test/geographic_module_tests" 
    "test/database_configuration_module_tests"
    "test/work_unit_distribution_module_tests"
    "test/radio_propagation_tests"
    "test/antenna_pattern_module_tests"
    "test/audio_processing_tests"
    "test/atis_module_tests"
    "test/frequency_management_tests"
    "test/client_plugin_module_tests"
)

for test_suite in "${test_suites[@]}"; do
    echo "Fixing $test_suite..."
    
    cmake_file="$test_suite/CMakeLists.txt"
    
    if [ -f "$cmake_file" ]; then
        # Replace find_package(GMock REQUIRED) with PkgConfig approach
        sed -i 's/find_package(GMock REQUIRED)/# Find GMock\nfind_package(PkgConfig REQUIRED)\npkg_check_modules(GMOCK REQUIRED gmock)/' "$cmake_file"
        
        # Replace GMock::GMock with ${GMOCK_LIBRARIES} in target_link_libraries
        sed -i 's/GMock::GMock/${GMOCK_LIBRARIES}/g' "$cmake_file"
        
        echo "  ✓ Fixed $test_suite"
    else
        echo "  ✗ CMakeLists.txt not found in $test_suite"
    fi
done

echo "GMock fixes completed!"

