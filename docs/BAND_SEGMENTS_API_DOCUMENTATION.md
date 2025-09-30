# Band Segments API Documentation

## Overview

The Band Segments API provides read-only access to amateur radio frequency allocations, power limits, and regional restrictions. This API allows amateur radio clients to validate frequencies, check power limits, and ensure compliance with ITU regional regulations.

## Table of Contents

1. [API Endpoints](#api-endpoints)
2. [Request Parameters](#request-parameters)
3. [Response Formats](#response-formats)
4. [Usage Examples](#usage-examples)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Data Sources](#data-sources)

## API Endpoints

### Base URL
```
http://localhost:8080/api/v1/band-segments
```

### Available Endpoints

#### 1. List All Band Segments
**GET** `/api/v1/band-segments`

Returns all available band segments with optional filtering.

**Query Parameters:**
- `band` (optional): Filter by band name (e.g., "20m", "40m", "2m")
- `mode` (optional): Filter by mode (e.g., "CW", "SSB", "AM")
- `region` (optional): Filter by ITU region (1, 2, or 3)

**Example Request:**
```
GET /api/v1/band-segments?band=20m&mode=SSB&region=1
```

#### 2. Get Band Segment by Frequency
**GET** `/api/v1/band-segments/frequency`

Returns band segment information for a specific frequency.

**Required Parameters:**
- `frequency`: Frequency in kHz (e.g., "14100")

**Optional Parameters:**
- `mode`: Operating mode (default: "SSB")
- `region`: ITU region (default: 1)

**Example Request:**
```
GET /api/v1/band-segments/frequency?frequency=14100&mode=SSB&region=1
```

#### 3. Get Power Limit
**GET** `/api/v1/band-segments/power-limit`

Returns the maximum power limit for a specific frequency and mode.

**Required Parameters:**
- `frequency`: Frequency in kHz

**Optional Parameters:**
- `mode`: Operating mode (default: "SSB")
- `region`: ITU region (default: 1)

**Example Request:**
```
GET /api/v1/band-segments/power-limit?frequency=5310&mode=CW&region=1
```

#### 4. Validate Power Level
**GET** `/api/v1/band-segments/power-validation`

Validates if a power level is within limits for a specific frequency.

**Required Parameters:**
- `frequency`: Frequency in kHz
- `power`: Power level in watts

**Optional Parameters:**
- `mode`: Operating mode (default: "SSB")
- `region`: ITU region (default: 1)

**Example Request:**
```
GET /api/v1/band-segments/power-validation?frequency=5310&power=25&mode=CW&region=1
```

#### 5. Validate Frequency
**GET** `/api/v1/band-segments/frequency-validation`

Validates if a frequency is valid for amateur radio operation.

**Required Parameters:**
- `frequency`: Frequency in kHz

**Optional Parameters:**
- `mode`: Operating mode (default: "SSB")
- `region`: ITU region (default: 1)

**Example Request:**
```
GET /api/v1/band-segments/frequency-validation?frequency=14100&mode=SSB&region=1
```

## Request Parameters

### Frequency Format
- All frequencies are specified in kHz
- Use decimal notation (e.g., "14100.5" for 14100.5 kHz)
- No unit suffixes required

### ITU Regions
- **Region 1**: Europe, Africa, Middle East, former USSR
- **Region 2**: Americas
- **Region 3**: Asia-Pacific

### Operating Modes
- **CW**: Continuous Wave (Morse code)
- **SSB**: Single Sideband
- **AM**: Amplitude Modulation
- **DSB**: Double Sideband
- **ISB**: Independent Sideband
- **VSB**: Vestigial Sideband
- **NFM**: Narrow FM

## Response Formats

### Standard Response Structure
```json
{
  "status": "success",
  "data": {
    // Response data here
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Response Structure
```json
{
  "status": "error",
  "error": {
    "code": 400,
    "message": "Frequency parameter required"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Band Segment Response
```json
{
  "status": "success",
  "data": {
    "band": "20m",
    "mode": "SSB",
    "start_freq_khz": 14100.0,
    "end_freq_khz": 14350.0,
    "itu_region": 1,
    "power_limit_watts": 400.0,
    "countries": "Europe",
    "notes": "SSB and digital modes",
    "found": true
  }
}
```

### Power Limit Response
```json
{
  "status": "success",
  "data": {
    "frequency_khz": 5310.0,
    "mode": "CW",
    "itu_region": 1,
    "power_limit_watts": 50.0,
    "band": "60m",
    "countries": "Norway, Denmark, UK, Finland, Iceland, Germany, Sweden, Switzerland, Belgium, Bulgaria, Croatia, Czech Republic, Estonia, Greece, Hungary, Ireland, Italy, Latvia, Lithuania, Netherlands, Portugal, Romania, Slovakia, Slovenia, Spain",
    "is_valid": true
  }
}
```

### Power Validation Response
```json
{
  "status": "success",
  "data": {
    "frequency_khz": 5310.0,
    "mode": "CW",
    "itu_region": 1,
    "power_watts": 25.0,
    "max_power_watts": 50.0,
    "is_valid": true,
    "band": "60m",
    "countries": "Norway, Denmark, UK, Finland, Iceland, Germany, Sweden, Switzerland, Belgium, Bulgaria, Croatia, Czech Republic, Estonia, Greece, Hungary, Ireland, Italy, Latvia, Lithuania, Netherlands, Portugal, Romania, Slovakia, Slovenia, Spain"
  }
}
```

## Usage Examples

### Example 1: Check Power Limit for 60m Band
```bash
curl "http://localhost:8080/api/v1/band-segments/power-limit?frequency=5310&mode=CW&region=1"
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "frequency_khz": 5310.0,
    "mode": "CW",
    "itu_region": 1,
    "power_limit_watts": 50.0,
    "band": "60m",
    "countries": "Norway, Denmark, UK, Finland, Iceland, Germany, Sweden, Switzerland, Belgium, Bulgaria, Croatia, Czech Republic, Estonia, Greece, Hungary, Ireland, Italy, Latvia, Lithuania, Netherlands, Portugal, Romania, Slovakia, Slovenia, Spain",
    "is_valid": true
  }
}
```

### Example 2: Validate Power Level
```bash
curl "http://localhost:8080/api/v1/band-segments/power-validation?frequency=5310&power=100&mode=CW&region=1"
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "frequency_khz": 5310.0,
    "mode": "CW",
    "itu_region": 1,
    "power_watts": 100.0,
    "max_power_watts": 50.0,
    "is_valid": false,
    "band": "60m",
    "countries": "Norway, Denmark, UK, Finland, Iceland, Germany, Sweden, Switzerland, Belgium, Bulgaria, Croatia, Czech Republic, Estonia, Greece, Hungary, Ireland, Italy, Latvia, Lithuania, Netherlands, Portugal, Romania, Slovakia, Slovenia, Spain",
    "error_message": "Power level 100W exceeds maximum 50W for this frequency"
  }
}
```

### Example 3: Get All 20m Band Segments
```bash
curl "http://localhost:8080/api/v1/band-segments?band=20m&region=1"
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "total_count": 2,
    "segments": [
      {
        "band": "20m",
        "mode": "CW",
        "start_freq_khz": 14000.0,
        "end_freq_khz": 14070.0,
        "itu_region": 1,
        "power_limit_watts": 400.0,
        "countries": "Europe",
        "notes": "CW only below 14070 kHz"
      },
      {
        "band": "20m",
        "mode": "SSB",
        "start_freq_khz": 14101.0,
        "end_freq_khz": 14350.0,
        "itu_region": 1,
        "power_limit_watts": 400.0,
        "countries": "Europe",
        "notes": "SSB and digital modes"
      }
    ]
  }
}
```

### Example 4: Validate Frequency for Amateur Radio
```bash
curl "http://localhost:8080/api/v1/band-segments/frequency-validation?frequency=14100&mode=SSB&region=1"
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "frequency_khz": 14100.0,
    "mode": "SSB",
    "itu_region": 1,
    "is_valid": true,
    "band": "20m",
    "countries": "Europe",
    "power_limit_watts": 400.0,
    "notes": "SSB and digital modes"
  }
}
```

### Example 5: Check Invalid Frequency
```bash
curl "http://localhost:8080/api/v1/band-segments/frequency-validation?frequency=15000&mode=SSB&region=1"
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "frequency_khz": 15000.0,
    "mode": "SSB",
    "itu_region": 1,
    "is_valid": false,
    "band": "",
    "countries": "",
    "power_limit_watts": 0.0,
    "notes": "",
    "error_message": "Frequency 15000 kHz is not valid for amateur radio in ITU region 1"
  }
}
```

## Error Handling

### HTTP Status Codes
- **200 OK**: Request successful
- **400 Bad Request**: Missing or invalid parameters
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error
- **501 Not Implemented**: Endpoint not yet implemented

### Common Error Messages
- `"Frequency parameter required"`: Missing frequency parameter
- `"Power parameter required"`: Missing power parameter for validation
- `"Rate limit exceeded"`: Too many requests
- `"Failed to initialize amateur radio system"`: System initialization error
- `"No band segment found for frequency X kHz"`: Frequency not in amateur bands

## Rate Limiting

- **Default Limit**: 100 requests per minute per IP address
- **Headers**: Rate limit information included in response headers
- **Exceeded**: Returns HTTP 429 with error message

## Data Sources

### Band Segments CSV File Location
**File Path**: `/home/haaken/github-projects/fgcom-mumble/configs/band_segments.csv`

The API reads from the `configs/band_segments.csv` file which contains:

- **Band**: Amateur radio band (160m, 80m, 60m, 40m, 30m, 20m, 17m, 15m, 12m, 10m, 6m, 4m, 2m, 70cm, 23cm)
- **Mode**: Operating mode (CW, SSB, AM, DSB, ISB, VSB, NFM, EME, MS, Omni)
- **StartFreq/EndFreq**: Frequency range in kHz
- **Region**: ITU region (1, 2, 3)
- **PowerLimit**: Maximum power in watts (including special allocations like 1000W for EME/MS, 300W for omnidirectional on 2m/70cm, 100W for omnidirectional on 4m in Norway)
- **Countries**: Country-specific restrictions
- **Notes**: Additional operating notes

### File Format
```csv
Band,Mode,StartFreq,EndFreq,Region,PowerLimit,Countries,Notes
160m,CW,1810,1838,1,400,Europe,"CW only below 1838 kHz"
160m,SSB,1838,2000,1,400,Europe,"SSB and digital modes"
```

### Modifying the CSV File
To update band segments data:

1. **Edit the CSV file**: Modify `/home/haaken/github-projects/fgcom-mumble/configs/band_segments.csv`
2. **Restart the plugin**: Changes take effect after plugin restart
3. **No recompilation needed**: CSV changes are loaded dynamically

**Important Notes:**
- Maintain CSV format with proper headers
- Use quoted strings for fields containing commas
- Ensure frequency values are in kHz
- Power limits should be in watts
- ITU regions: 1 (Europe/Africa), 2 (Americas), 3 (Asia-Pacific)

**Example of adding a new band segment:**
```csv
Band,Mode,StartFreq,EndFreq,Region,PowerLimit,Countries,Notes
1.25m,CW,240000,241000,1,100,Europe,"1.25m band CW segment"
```

## Integration Examples

### Python Client Example
```python
import requests
import json

def get_power_limit(frequency, mode="SSB", region=1):
    url = "http://localhost:8080/api/v1/band-segments/power-limit"
    params = {
        "frequency": frequency,
        "mode": mode,
        "region": region
    }
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["power_limit_watts"]
    else:
        return None

# Usage
power_limit = get_power_limit(14100)  # Returns 400.0 for 20m SSB
print(f"Power limit: {power_limit}W")
```

### Norwegian Special Allocations

The CSV file includes special Norwegian allocations for EME (Earth-Moon-Earth) and MS (Meteor Scatter) operations:

- **2m Band**: 1000W for EME/MS operations (144-146 MHz)
- **70cm Band**: 1000W for EME/MS operations (430-440 MHz)  
- **23cm Band**: 1000W for EME/MS operations (1240-1300 MHz)

These allocations require:
- Directional antenna
- Logging of time, azimuth, and elevation
- Specialized EME/MS operations only

### JavaScript Client Example
```javascript
async function validateFrequency(frequency, mode = "SSB", region = 1) {
    const url = "http://localhost:8080/api/v1/band-segments/frequency-validation";
    const params = new URLSearchParams({
        frequency: frequency,
        mode: mode,
        region: region
    });
    
    try {
        const response = await fetch(`${url}?${params}`);
        const data = await response.json();
        return data.data.is_valid;
    } catch (error) {
        console.error("Error validating frequency:", error);
        return false;
    }
}

// Usage
validateFrequency(14100).then(isValid => {
    console.log(`Frequency 14100 kHz is ${isValid ? 'valid' : 'invalid'}`);
});
```

### cURL Examples
```bash
# Get power limit for 60m band
curl "http://localhost:8080/api/v1/band-segments/power-limit?frequency=5310&mode=CW&region=1"

# Validate power level
curl "http://localhost:8080/api/v1/band-segments/power-validation?frequency=5310&power=25&mode=CW&region=1"

# Check frequency validity
curl "http://localhost:8080/api/v1/band-segments/frequency-validation?frequency=14100&mode=SSB&region=1"

# List all band segments
curl "http://localhost:8080/api/v1/band-segments"

# Filter by band
curl "http://localhost:8080/api/v1/band-segments?band=20m"

# Filter by mode
curl "http://localhost:8080/api/v1/band-segments?mode=CW"

# Filter by region
curl "http://localhost:8080/api/v1/band-segments?region=2"
```

## Security Considerations

- **Read-Only API**: All endpoints are read-only, no data modification
- **Rate Limiting**: Prevents abuse with configurable limits
- **Input Validation**: All parameters are validated before processing
- **Error Handling**: Comprehensive error handling prevents information leakage

## Performance Notes

- **Caching**: Band segments data is cached in memory for fast access
- **Initialization**: One-time initialization on first API call
- **Response Time**: Typical response time < 10ms for cached data
- **Memory Usage**: Minimal memory footprint for band segments data

## Troubleshooting

### Common Issues

1. **"Failed to initialize amateur radio system"**
   - Check if `configs/band_segments.csv` exists
   - Verify file permissions and format

2. **"No band segment found"**
   - Frequency may be outside amateur bands
   - Check ITU region parameter
   - Verify mode parameter

3. **"Rate limit exceeded"**
   - Reduce request frequency
   - Implement client-side caching
   - Contact administrator for limit increase

### Debug Information
Enable debug logging by setting the appropriate log level in the configuration file.

## Version History

- **v1.0**: Initial implementation with basic band segments support
- **v1.1**: Added power limit validation
- **v1.2**: Added frequency validation
- **v1.3**: Added regional restrictions support
- **v1.4**: Enhanced error handling and rate limiting

## Support

For technical support or feature requests, please refer to the main project documentation or contact the development team.
