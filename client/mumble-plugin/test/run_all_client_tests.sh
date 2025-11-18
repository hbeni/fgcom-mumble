#!/bin/bash
#
# Run all client plugin tests
# Tests are organized in test-modules/ subdirectory

cd "$(dirname "$0")" || exit 1

echo "=== CLIENT PLUGIN TEST EXECUTION ==="
echo "Date: $(date)"
echo "Running all client plugin tests..."
echo

# List of all client test modules
declare -a TEST_MODULES=(
    "test-modules/agc_squelch_tests"
    "test-modules/antenna_pattern_module_tests"
    "test-modules/audio_processing_tests"
    "test-modules/client_plugin_module_tests"
    "test-modules/database_configuration_module_tests"
    "test-modules/diagnostic_examples"
    "test-modules/edge_case_coverage_tests"
    "test-modules/error_handling_tests"
    "test-modules/frequency_interference_tests"
    "test-modules/frequency_management_tests"
    "test-modules/geographic_module_tests"
    "test-modules/integration_tests"
    "test-modules/jsimconnect_build_tests"
    "test-modules/network_module_tests"
    "test-modules/openstreetmap_infrastructure_tests"
    "test-modules/performance_tests"
    "test-modules/professional_audio_tests"
    "test-modules/radio_propagation_tests"
    "test-modules/rapidcheck_tests"
    "test-modules/satellite_communication_tests"
    "test-modules/security_module_tests"
    "test-modules/tts_integration_tests"
    "test-modules/voice_encryption_tests"
    "test-modules/webrtc_api_tests"
    "test-modules/work_unit_distribution_module_tests"
)

# Function to run a test module
run_test_module() {
    local module_dir="$1"
    local module_name=$(basename "$module_dir")
    
    echo "=========================================="
    echo "Testing: $module_name"
    echo "=========================================="
    
    if [ ! -d "$module_dir" ]; then
        echo "Module $module_dir not found, skipping..."
        return
    fi
    
    cd "$module_dir" || return 1
    
    # Try to build and run tests
    if [ -f "Makefile" ]; then
        if make clean && make -j$(nproc) 2>/dev/null; then
            if [ -f "build/${module_name}" ]; then
                echo "Running $module_name tests..."
                ./build/${module_name} 2>&1
            fi
        fi
    fi
    
    cd - > /dev/null
    echo
}

# Run all test modules
for module in "${TEST_MODULES[@]}"; do
    run_test_module "$module"
done

echo "=== CLIENT PLUGIN TESTS COMPLETED ==="

