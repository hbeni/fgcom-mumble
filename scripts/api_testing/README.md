# Comprehensive API Testing Tool

This directory contains a comprehensive API testing tool for FGCom-mumble that tests all available API endpoints.

## Overview

The `comprehensive_api_tester.py` script provides automated testing for all FGCom-mumble APIs including:

- **Authentication APIs** - Login, token refresh, user management
- **Solar Data APIs** - Current conditions, history, forecast, data submission
- **Weather & Lightning APIs** - Weather conditions, lightning strikes, atmospheric data
- **Band Segments APIs** - Amateur radio frequency allocations, power limits, validation
- **Radio Model APIs** - Radio specifications, capabilities, channel management
- **Preset Channel APIs** - Channel presets, frequency validation, radio-specific channels
- **AGC/Squelch APIs** - Audio processing, automatic gain control, squelch settings
- **Antenna Pattern APIs** - Antenna patterns, radiation patterns, pattern upload
- **Vehicle Dynamics APIs** - Vehicle tracking, position updates, dynamics simulation
- **System Health APIs** - Health checks, status monitoring, system information

## Requirements

### Prerequisites

1. **Running FGCom-mumble Server**: The API testing tool requires a compiled and running FGCom-mumble server with API server enabled
2. **Python 3.6+**: The tool is written in Python 3
3. **Required Python Packages**:
   ```bash
   pip install requests
   ```

### Server Setup

Before running the API tests, ensure:

1. **FGCom-mumble is compiled and running**
2. **API server is enabled** in the configuration
3. **Server is accessible** on the specified URL (default: http://localhost:8080)
4. **All required services are running** (radio communication, terrain analysis, etc.)

## Usage

### Basic Usage

```bash
# Run all API tests
python3 scripts/api_testing/comprehensive_api_tester.py

# Run with custom base URL
python3 scripts/api_testing/comprehensive_api_tester.py --base-url http://your-server:8080

# Run with verbose output
python3 scripts/api_testing/comprehensive_api_tester.py --verbose

# Generate detailed report
python3 scripts/api_testing/comprehensive_api_tester.py --output-file test_report.json
```

### Advanced Usage

```bash
# Test specific API category
python3 scripts/api_testing/comprehensive_api_tester.py --category solar

# Available categories:
# - health: Health check and system status
# - auth: Authentication APIs
# - solar: Solar data APIs
# - weather: Weather and lightning APIs
# - bands: Band segments APIs
# - radio: Radio model APIs
# - presets: Preset channel APIs
# - agc: AGC/Squelch APIs
# - antenna: Antenna pattern APIs
# - vehicle: Vehicle dynamics APIs

# Run with custom timeout and detailed logging
python3 scripts/api_testing/comprehensive_api_tester.py --verbose --output-file detailed_report.json
```

### Command Line Options

- `--base-url URL`: Base URL for the API server (default: http://localhost:8080)
- `--verbose`: Enable verbose logging and detailed output
- `--output-file FILE`: Save test report to JSON file
- `--category CATEGORY`: Run tests for specific API category only

## Test Categories

### 1. Health Check Tests
- Basic health check endpoint
- API status information
- System information and features

### 2. Authentication Tests
- User login with valid credentials
- Login with invalid credentials
- Token refresh functionality

### 3. Solar Data Tests
- Get current solar conditions
- Retrieve historical solar data
- Get solar data forecast
- Submit single solar data entry
- Submit batch solar data
- Update existing solar data

### 4. Weather & Lightning Tests
- Get current weather conditions
- Retrieve weather history
- Get weather forecast
- Submit weather data
- Get current lightning data
- Submit lightning strike data
- Submit batch lightning strikes

### 5. Band Segments Tests
- List all amateur radio band segments
- Filter segments by band, mode, or region
- Get band segment by frequency
- Get power limits for frequencies
- Validate power levels
- Validate frequencies for amateur radio

### 6. Radio Model Tests
- List all radio models
- Get specific radio model details
- Get radio model specifications and capabilities
- Search and filter radio models
- Compare radio models
- Get radio model channels and frequency information
- Validate radio model configurations

### 7. Preset Channel Tests
- List all preset channels
- Get radio-specific preset channels
- Search preset channels
- Get preset channels by frequency or channel number
- Get active/inactive preset channels
- Get preset channel statistics

### 8. AGC/Squelch Tests
- Get AGC and squelch status
- Configure AGC settings (mode, threshold, timing)
- Configure squelch settings (threshold, hysteresis, timing)
- Get combined AGC/Squelch status
- Get audio processing statistics
- Get available presets

### 9. Antenna Pattern Tests
- Get specific antenna patterns
- List all available antenna patterns
- Upload new antenna patterns

### 10. Vehicle Dynamics Tests
- Get vehicle dynamics information
- List all tracked vehicles
- Get and update vehicle positions
- Track vehicle movement and dynamics

## Output and Reporting

### Console Output

The tool provides real-time feedback during testing:

```
API server is running at http://localhost:8080
Starting comprehensive API testing...
============================================================
Running Health Check tests...
✓ Health Check
✓ API Status
✓ API Info
Running Authentication tests...
✓ Login (Valid Credentials)
✗ Login (Invalid Credentials): Expected status 401, got 200
...
Testing complete: 45/50 tests passed (90.0%)
```

### JSON Report

When using `--output-file`, the tool generates a detailed JSON report:

```json
{
  "test_summary": {
    "total_tests": 50,
    "passed": 45,
    "failed": 3,
    "errors": 2
  },
  "test_details": [
    {
      "name": "Health Check",
      "endpoint": "/health",
      "method": "GET",
      "result": "PASS",
      "status_code": 200,
      "response_time": 0.123,
      "error_message": "",
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```
   Error: Cannot connect to API server at http://localhost:8080
   ```
   **Solution**: Ensure FGCom-mumble server is running and API server is enabled

2. **Authentication Failures**
   ```
   ✗ Login (Valid Credentials): Expected status 200, got 401
   ```
   **Solution**: Check authentication configuration and credentials

3. **Timeout Errors**
   ```
   ✗ Get Current Solar Data: Request timeout
   ```
   **Solution**: Check server performance and network connectivity

4. **Missing Dependencies**
   ```
   ModuleNotFoundError: No module named 'requests'
   ```
   **Solution**: Install required Python packages: `pip install requests`

### Debug Mode

Use `--verbose` flag for detailed debugging information:

```bash
python3 scripts/api_testing/comprehensive_api_tester.py --verbose
```

This will show:
- Detailed request/response information
- Response data content
- Error stack traces
- Performance metrics

## Integration with CI/CD

The API testing tool can be integrated into continuous integration pipelines:

```bash
#!/bin/bash
# CI/CD Integration Example

# Start FGCom-mumble server
./start_fgcom_server.sh &

# Wait for server to be ready
sleep 30

# Run API tests
python3 scripts/api_testing/comprehensive_api_tester.py --output-file ci_test_report.json

# Check exit code
if [ $? -eq 0 ]; then
    echo "All API tests passed"
    exit 0
else
    echo "Some API tests failed"
    exit 1
fi
```

## Performance Considerations

- **Test Duration**: Full test suite typically takes 2-5 minutes
- **Server Load**: Tests generate moderate server load
- **Network Requirements**: Stable network connection recommended
- **Resource Usage**: Minimal memory and CPU usage

## Contributing

To add new API tests:

1. **Add test cases** to the appropriate test method in `comprehensive_api_tester.py`
2. **Follow naming conventions** for test cases
3. **Include proper error handling** and validation
4. **Update documentation** with new test categories
5. **Test thoroughly** before submitting changes

## Support

For issues with the API testing tool:

1. **Check server status** - Ensure FGCom-mumble is running
2. **Verify configuration** - Check API server settings
3. **Review logs** - Use `--verbose` for detailed information
4. **Test connectivity** - Verify network access to server
5. **Check dependencies** - Ensure all Python packages are installed

## Related Documentation

- [API Reference Complete](docs/API_REFERENCE_COMPLETE.md) - Complete API documentation
- [Technical Setup Guide](docs/TECHNICAL_SETUP_GUIDE.md) - Server setup instructions
- [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) - Common issues and solutions
