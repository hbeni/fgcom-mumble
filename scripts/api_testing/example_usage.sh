#!/bin/bash

# Example usage script for the Comprehensive API Testing Tool
# This script demonstrates various ways to use the API testing tool

echo "FGCom-mumble API Testing Tool - Example Usage"
echo "============================================="
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed"
    exit 1
fi

# Check if the testing script exists
if [ ! -f "comprehensive_api_tester.py" ]; then
    echo "Error: comprehensive_api_tester.py not found in current directory"
    echo "Please run this script from the scripts/api_testing/ directory"
    exit 1
fi

echo "1. Basic API Testing (All Tests)"
echo "-------------------------------"
echo "Running all API tests against localhost:8080..."
python3 comprehensive_api_tester.py

echo ""
echo "2. Verbose Testing with Detailed Output"
echo "---------------------------------------"
echo "Running tests with verbose output..."
python3 comprehensive_api_tester.py --verbose

echo ""
echo "3. Testing Specific API Category (Solar Data)"
echo "---------------------------------------------"
echo "Running only solar data API tests..."
python3 comprehensive_api_tester.py --category solar

echo ""
echo "4. Testing with Custom Server URL"
echo "---------------------------------"
echo "Running tests against custom server..."
python3 comprehensive_api_tester.py --base-url http://192.168.1.100:8080

echo ""
echo "5. Generating Detailed Report"
echo "-----------------------------"
echo "Running tests and generating JSON report..."
python3 comprehensive_api_tester.py --output-file api_test_report.json --verbose

if [ -f "api_test_report.json" ]; then
    echo "Report generated: api_test_report.json"
    echo "Report summary:"
    python3 -c "
import json
with open('api_test_report.json', 'r') as f:
    data = json.load(f)
    summary = data['test_summary']
    print(f'Total tests: {summary[\"total_tests\"]}')
    print(f'Passed: {summary[\"passed\"]}')
    print(f'Failed: {summary[\"failed\"]}')
    print(f'Errors: {summary[\"errors\"]}')
    print(f'Success rate: {summary[\"success_rate\"]:.1f}%')
"
else
    echo "No report generated"
fi

echo ""
echo "6. Testing Different API Categories"
echo "----------------------------------"
echo "Available categories: health, auth, solar, weather, bands, radio, presets, agc, antenna, vehicle"

for category in health auth solar weather bands radio presets agc antenna vehicle; do
    echo "Testing $category APIs..."
    python3 comprehensive_api_tester.py --category $category --base-url http://localhost:8080
    echo ""
done

echo ""
echo "7. Continuous Integration Example"
echo "--------------------------------"
echo "Example for CI/CD integration:"
echo ""
echo "#!/bin/bash"
echo "# Start FGCom-mumble server"
echo "./start_fgcom_server.sh &"
echo ""
echo "# Wait for server to be ready"
echo "sleep 30"
echo ""
echo "# Run API tests"
echo "python3 scripts/api_testing/comprehensive_api_tester.py --output-file ci_test_report.json"
echo ""
echo "# Check results"
echo "if [ \$? -eq 0 ]; then"
echo "    echo 'All API tests passed'"
echo "    exit 0"
echo "else"
echo "    echo 'Some API tests failed'"
echo "    exit 1"
echo "fi"

echo ""
echo "Example Usage Complete!"
echo "======================="
echo ""
echo "For more information, see:"
echo "- README.md in this directory"
echo "- Comprehensive API Tester documentation"
echo "- FGCom-mumble API documentation"
