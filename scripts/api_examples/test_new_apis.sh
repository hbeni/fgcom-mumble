#!/bin/bash

# Test script for new Radio Model and Preset Channel APIs
# This script tests the new API endpoints to ensure they work correctly

echo "Testing new Radio Model and Preset Channel APIs..."
echo "=================================================="

# Test Radio Model APIs
echo ""
echo "1. Testing Radio Model APIs:"
echo "----------------------------"

echo "GET /api/v1/radio-models"
curl -s "http://localhost:8080/api/v1/radio-models" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/radio-models/AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/AN%2FPRC-152/specifications"
curl -s "http://localhost:8080/api/v1/radio-models/AN%2FPRC-152/specifications" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/AN%2FPRC-152/capabilities"
curl -s "http://localhost:8080/api/v1/radio-models/AN%2FPRC-152/capabilities" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/search?q=NATO"
curl -s "http://localhost:8080/api/v1/radio-models/search?q=NATO" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/filter?country=USA&alliance=NATO"
curl -s "http://localhost:8080/api/v1/radio-models/filter?country=USA&alliance=NATO" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/compare?model1=AN%2FPRC-152&model2=R-105M"
curl -s "http://localhost:8080/api/v1/radio-models/compare?model1=AN%2FPRC-152&model2=R-105M" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/AN%2FPRC-152/channels"
curl -s "http://localhost:8080/api/v1/radio-models/AN%2FPRC-152/channels" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/AN%2FPRC-152/frequency?frequency=31.25"
curl -s "http://localhost:8080/api/v1/radio-models/AN%2FPRC-152/frequency?frequency=31.25" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/validate?model=AN%2FPRC-152&frequency=31.25&channel=100"
curl -s "http://localhost:8080/api/v1/radio-models/validate?model=AN%2FPRC-152&frequency=31.25&channel=100" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/radio-models/statistics"
curl -s "http://localhost:8080/api/v1/radio-models/statistics" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

# Test Preset Channel APIs
echo ""
echo "2. Testing Preset Channel APIs:"
echo "-------------------------------"

echo "GET /api/v1/preset-channels"
curl -s "http://localhost:8080/api/v1/preset-channels" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/preset-channels/AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/search?q=Tactical&radio=AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/preset-channels/search?q=Tactical&radio=AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/frequency?frequency=31.25&radio=AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/preset-channels/frequency?frequency=31.25&radio=AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/channel?channel=100&radio=AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/preset-channels/channel?channel=100&radio=AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/active?radio=AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/preset-channels/active?radio=AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/inactive?radio=AN%2FPRC-152"
curl -s "http://localhost:8080/api/v1/preset-channels/inactive?radio=AN%2FPRC-152" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "GET /api/v1/preset-channels/statistics"
curl -s "http://localhost:8080/api/v1/preset-channels/statistics" | jq '.' 2>/dev/null || echo "API not running or jq not installed"

# Test API Info endpoint
echo ""
echo "3. Testing Updated API Info Endpoint:"
echo "-------------------------------------"

echo "GET /api/info"
curl -s "http://localhost:8080/api/info" | jq '.endpoints' 2>/dev/null || echo "API not running or jq not installed"

echo ""
echo "API Testing Complete!"
echo "====================="
echo ""
echo "Note: If you see 'API not running or jq not installed', it means:"
echo "1. The API server is not running (start it first)"
echo "2. The jq command is not installed (install with: sudo apt install jq)"
echo "3. The server is not listening on localhost:8080"
echo ""
echo "To start the API server, run the plugin in Mumble with API enabled."
