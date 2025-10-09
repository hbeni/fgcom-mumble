#!/bin/bash

# Script to update all test scripts to use centralized test-logs directory

echo "=== Updating Test Scripts to Use Centralized test-logs Directory ==="

# Find all test runner scripts
TEST_SCRIPTS=$(find test/ -name "run_*_tests.sh" -type f)

for script in $TEST_SCRIPTS; do
    echo "Updating: $script"
    
    # Create backup
    cp "$script" "$script.backup"
    
    # Update TEST_RESULTS_DIR to point to test-logs
    sed -i 's|TEST_RESULTS_DIR="test_results"|TEST_RESULTS_DIR="../test-logs/$(basename $(dirname $script))"|g' "$script"
    sed -i 's|TEST_RESULTS_DIR=".*test_results.*"|TEST_RESULTS_DIR="../test-logs/$(basename $(dirname $script))"|g' "$script"
    
    # Update any hardcoded test_results paths
    sed -i 's|test_results/|../test-logs/$(basename $(dirname $script))/|g' "$script"
    
    echo "  ✅ Updated $script"
done

echo ""
echo "=== Creating test-logs Directory Structure ==="

# Create test-logs directory
mkdir -p test/test-logs

# Create subdirectories for each test module
for module in agc_squelch_tests antenna_pattern_module_tests atis_module_tests audio_processing_tests client_plugin_module_tests database_configuration_module_tests error_handling_tests frequency_management_tests geographic_module_tests integration_tests network_module_tests openstreetmap_infrastructure_tests performance_tests professional_audio_tests radio_propagation_tests security_module_tests status_page_module_tests webrtc_api_tests work_unit_distribution_module_tests; do
    mkdir -p "test/test-logs/$module"
    echo "  ✅ Created test-logs/$module"
done

echo ""
echo "=== Test Logs Directory Structure Created ==="
echo "All test logs will now be saved to: test/test-logs/"
echo "Individual module logs will be in: test/test-logs/[module_name]/"
echo ""
echo "Directory structure:"
tree test/test-logs/ 2>/dev/null || ls -la test/test-logs/
