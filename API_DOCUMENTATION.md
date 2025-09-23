# FGCom-mumble API Documentation

## Overview

The FGCom-mumble API provides RESTful endpoints and WebSocket real-time updates for radio propagation calculations, solar data, band status, antenna patterns, and ground system modeling. The API is designed for external clients, web applications, and integration with other radio software.

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

Currently, the API supports optional API key authentication. Set `enable_api_key_auth = true` in the configuration and provide the API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/propagation
```

## Rate Limiting

The API implements rate limiting to prevent abuse. By default, 100 requests per minute per IP address are allowed. This can be configured in the `[api_server]` section:

```ini
rate_limit_requests_per_minute = 100
```

## CORS Support

Cross-Origin Resource Sharing (CORS) is enabled by default, allowing web applications to access the API from different domains.

## Response Format

All API responses follow a consistent format:

### Success Response
```json
{
  "success": true,
  "data": { ... },
  "timestamp": 1640995200
}
```

### Error Response
```json
{
  "error": true,
  "message": "Error description",
  "code": 400,
  "timestamp": 1640995200
}
```

## Endpoints

### 1. Health Check

**GET** `/health`

Check if the API server is running and healthy.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1640995200,
  "version": "1.0.0",
  "features": {
    "propagation": true,
    "solar_data": true,
    "band_status": true
  }
}
```

### 2. API Information

**GET** `/api/info`

Get information about the API, available features, and endpoints.

**Response:**
```json
{
  "title": "FGCom-mumble API",
  "version": "1.0.0",
  "description": "Radio propagation and amateur radio API",
  "contact": "https://github.com/hbeni/fgcom-mumble",
  "features": { ... },
  "endpoints": { ... }
}
```

### 3. Propagation Calculation

**POST** `/api/v1/propagation`

Calculate radio propagation between two points.

**Request Body:**
```json
{
  "lat1": 40.7128,
  "lon1": -74.0060,
  "lat2": 51.5074,
  "lon2": -0.1278,
  "alt1": 10.0,
  "alt2": 50.0,
  "frequency_mhz": 14.0,
  "power_watts": 100.0,
  "antenna_type": "vertical",
  "ground_type": "average",
  "mode": "SSB",
  "band": "20m",
  "include_solar_effects": true,
  "include_antenna_patterns": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "signal_quality": 0.75,
    "signal_strength_db": -2.5,
    "path_loss_db": 120.0,
    "antenna_gain_db": 2.15,
    "ground_loss_db": 3.0,
    "solar_effect_db": 1.2,
    "distance_km": 5570.0,
    "bearing_deg": 45.2,
    "elevation_angle_deg": 12.5,
    "propagation_mode": "skywave",
    "success": true,
    "error_message": ""
  }
}
```

### 4. Batch Propagation Calculation

**POST** `/api/v1/propagation/batch`

Calculate propagation for multiple paths in a single request.

**Request Body:**
```json
{
  "requests": [
    {
      "lat1": 40.7128,
      "lon1": -74.0060,
      "lat2": 51.5074,
      "lon2": -0.1278,
      "frequency_mhz": 14.0,
      "power_watts": 100.0
    },
    {
      "lat1": 40.7128,
      "lon1": -74.0060,
      "lat2": 35.6762,
      "lon2": 139.6503,
      "frequency_mhz": 7.0,
      "power_watts": 50.0
    }
  ]
}
```

### 5. Solar Data

**GET** `/api/v1/solar`

Get current solar conditions from NOAA/SWPC.

**Response:**
```json
{
  "success": true,
  "data": {
    "sfi": 85.2,
    "k_index": 2.0,
    "a_index": 8.0,
    "solar_zenith": 45.5,
    "is_day": true,
    "day_of_year": 45,
    "solar_declination": -12.3,
    "timestamp": 1640995200
  }
}
```

### 6. Solar Data History

**GET** `/api/v1/solar/history?hours=24`

Get historical solar data.

**Query Parameters:**
- `hours`: Number of hours of history to retrieve (default: 24)

### 7. Band Status

**GET** `/api/v1/bands`

Get status of all amateur radio bands.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "band": "20m",
      "mode": "SSB",
      "frequency_mhz": 14.0,
      "is_open": true,
      "muf_mhz": 25.0,
      "luf_mhz": 3.5,
      "signal_quality": 0.8,
      "propagation_conditions": "Good",
      "solar_conditions": "Quiet",
      "active_stations": ["W1ABC", "G0XYZ"],
      "timestamp": 1640995200
    }
  ]
}
```

### 8. Specific Band Status

**GET** `/api/v1/bands/{band}?mode=SSB`

Get status of a specific band.

**Path Parameters:**
- `band`: Band name (e.g., "20m", "40m", "80m")

**Query Parameters:**
- `mode`: Operating mode (e.g., "SSB", "CW", "AM")

### 9. Antenna Patterns

**GET** `/api/v1/antennas`

Get list of available antenna patterns.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "name": "vertical_1_4",
      "type": "4NEC2",
      "frequency_range": "1.8-30.0",
      "available": true
    },
    {
      "name": "dipole_1_2",
      "type": "4NEC2",
      "frequency_range": "3.5-30.0",
      "available": true
    }
  ]
}
```

### 10. Specific Antenna Pattern

**GET** `/api/v1/antennas/{antenna_name}?frequency=14.0`

Get antenna pattern data for a specific antenna and frequency.

**Path Parameters:**
- `antenna_name`: Name of the antenna pattern

**Query Parameters:**
- `frequency`: Frequency in MHz

### 11. Ground Systems

**GET** `/api/v1/ground`

Get list of available ground systems.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "name": "excellent_star",
      "available": true
    },
    {
      "name": "good_star",
      "available": true
    }
  ]
}
```

### 12. Specific Ground System

**GET** `/api/v1/ground/{system_name}`

Get details of a specific ground system.

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "excellent_star",
    "type": "star_network",
    "conductivity": 15.0,
    "area_coverage": 3000.0,
    "ground_resistance": 0.05,
    "is_saltwater": true,
    "material": "copper",
    "notes": "Excellent star network for coastal HF station"
  }
}
```

### 13. GPU Status

**GET** `/api/v1/gpu`

Get GPU status and capabilities.

**Response:**
```json
{
  "success": true,
  "data": {
    "gpu_available": false,
    "gpu_name": "None",
    "gpu_memory_mb": 0,
    "gpu_utilization": 0.0,
    "cuda_available": false,
    "opencl_available": false,
    "error_message": ""
  }
}
```

### 14. Configuration

**GET** `/api/v1/config`

Get current configuration.

**Response:**
```json
{
  "success": true,
  "data": {
    "amateur_radio": { ... },
    "solar_data": { ... },
    "propagation": { ... },
    "antenna_system": { ... },
    "api_server": { ... }
  }
}
```

### 15. Update Configuration

**PUT** `/api/v1/config`

Update configuration (requires appropriate permissions).

**Request Body:**
```json
{
  "amateur_radio": {
    "enabled": true,
    "default_power": 100
  },
  "solar_data": {
    "update_interval": 900
  }
}
```

### 16. Feature Flags

**GET** `/api/v1/config/features`

Get current feature flags.

**Response:**
```json
{
  "success": true,
  "data": {
    "propagation": true,
    "solar_data": true,
    "band_status": true,
    "antenna_patterns": true,
    "ground_systems": true,
    "gpu_status": true,
    "websocket": true,
    "rate_limiting": true,
    "cors": true
  }
}
```

### 17. Server Statistics

**GET** `/api/v1/stats`

Get server statistics and performance metrics.

**Response:**
```json
{
  "success": true,
  "data": {
    "server": {
      "uptime_seconds": 3600,
      "total_requests": 1250,
      "total_websocket_connections": 15,
      "active_websocket_connections": 8,
      "rate_limit_requests_per_minute": 100
    },
    "features": { ... },
    "version": "1.0.0"
  }
}
```

## WebSocket Real-time Updates

Connect to `/ws` for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'solar_update':
      console.log('Solar conditions updated:', data.data);
      break;
    case 'band_status_update':
      console.log('Band status updated:', data.band, data.data);
      break;
    case 'antenna_pattern_update':
      console.log('Antenna pattern updated:', data.antenna_name, data.data);
      break;
  }
};
```

### WebSocket Message Types

1. **Solar Update**: `{"type": "solar_update", "data": {...}}`
2. **Band Status Update**: `{"type": "band_status_update", "band": "20m", "data": {...}}`
3. **Antenna Pattern Update**: `{"type": "antenna_pattern_update", "antenna_name": "vertical_1_4", "data": {...}}`

## Error Codes

- `400`: Bad Request - Invalid request parameters
- `401`: Unauthorized - Missing or invalid API key
- `403`: Forbidden - Access denied
- `404`: Not Found - Endpoint or resource not found
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error - Server error
- `503`: Service Unavailable - Feature disabled or unavailable

## Examples

### Python Client Example

```python
import requests
import json

# Base URL
base_url = "http://localhost:8080/api/v1"

# Calculate propagation
propagation_data = {
    "lat1": 40.7128,
    "lon1": -74.0060,
    "lat2": 51.5074,
    "lon2": -0.1278,
    "frequency_mhz": 14.0,
    "power_watts": 100.0,
    "antenna_type": "vertical",
    "ground_type": "average"
}

response = requests.post(f"{base_url}/propagation", json=propagation_data)
result = response.json()

if result["success"]:
    signal_quality = result["data"]["signal_quality"]
    print(f"Signal quality: {signal_quality}")
else:
    print(f"Error: {result['message']}")

# Get solar data
response = requests.get(f"{base_url}/solar")
solar_data = response.json()

if solar_data["success"]:
    sfi = solar_data["data"]["sfi"]
    k_index = solar_data["data"]["k_index"]
    print(f"SFI: {sfi}, K-index: {k_index}")
```

### JavaScript Client Example

```javascript
// Calculate propagation
async function calculatePropagation() {
  const response = await fetch('/api/v1/propagation', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      lat1: 40.7128,
      lon1: -74.0060,
      lat2: 51.5074,
      lon2: -0.1278,
      frequency_mhz: 14.0,
      power_watts: 100.0,
      antenna_type: 'vertical',
      ground_type: 'average'
    })
  });
  
  const result = await response.json();
  
  if (result.success) {
    console.log('Signal quality:', result.data.signal_quality);
  } else {
    console.error('Error:', result.message);
  }
}

// Get band status
async function getBandStatus() {
  const response = await fetch('/api/v1/bands');
  const result = await response.json();
  
  if (result.success) {
    result.data.forEach(band => {
      console.log(`${band.band}: ${band.is_open ? 'Open' : 'Closed'}`);
    });
  }
}
```

### cURL Examples

```bash
# Health check
curl http://localhost:8080/health

# Get solar data
curl http://localhost:8080/api/v1/solar

# Calculate propagation
curl -X POST http://localhost:8080/api/v1/propagation \
  -H "Content-Type: application/json" \
  -d '{
    "lat1": 40.7128,
    "lon1": -74.0060,
    "lat2": 51.5074,
    "lon2": -0.1278,
    "frequency_mhz": 14.0,
    "power_watts": 100.0
  }'

# Get band status
curl http://localhost:8080/api/v1/bands

# Get antenna patterns
curl http://localhost:8080/api/v1/antennas

# Get ground systems
curl http://localhost:8080/api/v1/ground

# Get server statistics
curl http://localhost:8080/api/v1/stats
```

## Configuration

The API server can be configured through the configuration file. Key settings in the `[api_server]` section:

```ini
[api_server]
enabled = true
port = 8080
host = 0.0.0.0
enable_websocket = true
enable_cors = true
enable_rate_limiting = true
rate_limit_requests_per_minute = 100
enable_api_key_auth = false
api_key = your-secure-api-key
enable_ssl = false
ssl_cert_file = /path/to/cert.pem
ssl_key_file = /path/to/key.pem
```

## Security Considerations

1. **API Key Authentication**: Enable for production use
2. **Rate Limiting**: Configure appropriate limits for your use case
3. **IP Whitelisting**: Restrict access to specific IP addresses if needed
4. **SSL/TLS**: Enable HTTPS for production deployments
5. **CORS**: Configure appropriate origins for web applications

## Performance

- The API is designed for high-performance with caching and parallel processing
- GPU acceleration can be enabled for computationally intensive operations
- Rate limiting prevents abuse and ensures fair usage
- WebSocket connections are optimized for real-time updates

## Troubleshooting

### Common Issues

1. **Connection Refused**: Check if the API server is running and the port is correct
2. **Rate Limit Exceeded**: Reduce request frequency or increase rate limits
3. **Invalid Request**: Check request format and required parameters
4. **Feature Disabled**: Ensure the requested feature is enabled in configuration

### Debug Mode

Enable debug logging in the configuration:

```ini
[logging]
log_level = debug
enable_debug_logging = true
```

### Health Check

Use the health check endpoint to verify API status:

```bash
curl http://localhost:8080/health
```

## Support

For issues, feature requests, or questions:

- GitHub Issues: https://github.com/hbeni/fgcom-mumble/issues
- Documentation: https://github.com/hbeni/fgcom-mumble/wiki
- Community: https://github.com/hbeni/fgcom-mumble/discussions
