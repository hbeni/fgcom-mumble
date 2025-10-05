#!/bin/bash

# Script to check all test suites for unused variables and warnings

# List of test suites
TEST_SUITES=(
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
    "jsimconnect_build_tests"
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

echo "=== CHECKING ALL TEST SUITES FOR UNUSED VARIABLES ==="
echo ""

TOTAL_WARNINGS=0

for test_suite in "${TEST_SUITES[@]}"; do
    if [ -d "$test_suite" ]; then
        echo "--- Checking $test_suite ---"
        cd "$test_suite"
        
        # Clean and build
        make clean >/dev/null 2>&1
        BUILD_OUTPUT=$(make 2>&1)
        
        # Count warnings
        WARNING_COUNT=$(echo "$BUILD_OUTPUT" | grep -c -i "unused\|warning" || echo "0")
        
        if [ "$WARNING_COUNT" -gt 0 ]; then
            echo "WARNING: Found $WARNING_COUNT warnings:"
            echo "$BUILD_OUTPUT" | grep -i "unused\|warning" | head -5
            if [ "$WARNING_COUNT" -gt 5 ]; then
                echo "... and $((WARNING_COUNT - 5)) more warnings"
            fi
            TOTAL_WARNINGS=$((TOTAL_WARNINGS + WARNING_COUNT))
        else
            echo "SUCCESS: No unused variable warnings found"
        fi
        
        cd ..
        echo ""
    else
        echo "WARNING: Directory $test_suite not found, skipping..."
        echo ""
    fi
done

echo "=== SUMMARY ==="
if [ "$TOTAL_WARNINGS" -eq 0 ]; then
    echo "SUCCESS: All test suites are clean - no unused variable warnings found!"
else
    echo "WARNING: Total warnings found: $TOTAL_WARNINGS"
    echo "Some test suites have unused variables that should be fixed."
fi
