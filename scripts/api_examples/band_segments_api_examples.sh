#!/bin/bash

# Band Segments API Usage Examples
# This script demonstrates how to use the Band Segments API endpoints

API_BASE="http://localhost:8080/api/v1/band-segments"

echo "=== Band Segments API Usage Examples ==="
echo

# Function to make API calls with error handling
api_call() {
    local endpoint="$1"
    local description="$2"
    
    echo "--- $description ---"
    echo "GET $endpoint"
    echo
    
    response=$(curl -s "$endpoint")
    if [ $? -eq 0 ]; then
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    else
        echo "Error: Failed to connect to API server"
    fi
    echo
    echo "----------------------------------------"
    echo
}

# Check if API server is running
echo "Checking API server status..."
if ! curl -s "http://localhost:8080/health" > /dev/null 2>&1; then
    echo "Error: API server is not running on localhost:8080"
    echo "Please start the FGCom-mumble plugin with API server enabled"
    exit 1
fi
echo "API server is running"
echo

# Example 1: List all band segments
api_call "$API_BASE" "List All Band Segments"

# Example 2: Filter by band
api_call "$API_BASE?band=20m" "Filter by Band (20m)"

# Example 3: Filter by mode
api_call "$API_BASE?mode=CW" "Filter by Mode (CW)"

# Example 4: Filter by region
api_call "$API_BASE?region=1" "Filter by ITU Region 1"

# Example 5: Get band segment by frequency
api_call "$API_BASE/frequency?frequency=14100&mode=SSB&region=1" "Get Band Segment by Frequency (20m SSB)"

# Example 6: Get power limit for 60m band
api_call "$API_BASE/power-limit?frequency=5310&mode=CW&region=1" "Get Power Limit for 60m Band"

# Example 7: Validate power level (valid)
api_call "$API_BASE/power-validation?frequency=5310&power=25&mode=CW&region=1" "Validate Power Level (25W on 60m - Valid)"

# Example 8: Validate power level (invalid)
api_call "$API_BASE/power-validation?frequency=5310&power=100&mode=CW&region=1" "Validate Power Level (100W on 60m - Invalid)"

# Example 9: Validate frequency (valid)
api_call "$API_BASE/frequency-validation?frequency=14100&mode=SSB&region=1" "Validate Frequency (20m SSB - Valid)"

# Example 10: Validate frequency (invalid)
api_call "$API_BASE/frequency-validation?frequency=15000&mode=SSB&region=1" "Validate Frequency (15 MHz - Invalid)"

# Example 11: Check 2m band power limit
api_call "$API_BASE/power-limit?frequency=145000&mode=SSB&region=1" "Get Power Limit for 2m Band"

# Example 12: Check 70cm band power limit
api_call "$API_BASE/power-limit?frequency=435000&mode=SSB&region=1" "Get Power Limit for 70cm Band"

# Example 13: Check 23cm band power limit
api_call "$API_BASE/power-limit?frequency=1250000&mode=SSB&region=1" "Get Power Limit for 23cm Band"

# Example 14: Get all CW segments
api_call "$API_BASE?mode=CW" "Get All CW Segments"

# Example 15: Get all SSB segments
api_call "$API_BASE?mode=SSB" "Get All SSB Segments"

echo "=== API Examples Complete ==="
echo
echo "For more information, see:"
echo "- Band Segments API Documentation: docs/BAND_SEGMENTS_API_DOCUMENTATION.md"
echo "- Main API Documentation: docs/API_DOCUMENTATION.md"
echo "- Configuration Guide: configs/README.md"
