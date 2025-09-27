# Complete API Reference

## Overview

This document provides a comprehensive reference for all API endpoints in the FGCom-mumble system, including work unit distribution, security, and core functionality.

## Table of Contents

1. [Core API Endpoints](#core-api-endpoints)
2. [Work Unit Distribution API](#work-unit-distribution-api)
3. [Security API](#security-api)
4. [GPU Status API](#gpu-status-api)
5. [Propagation API](#propagation-api)
6. [Antenna Patterns API](#antenna-patterns-api)
7. [Ground Systems API](#ground-systems-api)
8. [Configuration API](#configuration-api)
9. [Band Segments Reference](#band-segments-reference)
10. [Error Codes](#error-codes)
11. [Rate Limiting](#rate-limiting)

## Core API Endpoints

### Health Check

**GET /health**

Returns server health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1703123456789,
  "uptime_seconds": 3600,
  "version": "1.4.1"
}
```

### API Information

**GET /api/info**

Returns API information and available endpoints.

**Response:**
```json
{
  "title": "FGCom-mumble API",
  "version": "1.4.1",
  "description": "API for distributed radio propagation calculations",
  "contact": "https://github.com/Supermagnum/fgcom-mumble",
  "features": {
    "propagation": true,
    "solar_data": true,
    "band_status": true,
    "antenna_patterns": true,
    "ground_systems": true,
    "gpu_status": true,
    "work_unit_distribution": true,
    "security": true
  },
  "endpoints": {
    "propagation": "/api/v1/propagation",
    "solar_data": "/api/v1/solar",
    "band_status": "/api/v1/bands",
    "antenna_patterns": "/api/v1/antennas",
    "ground_systems": "/api/v1/ground",
    "gpu_status": "/api/v1/gpu",
    "gpu_status_enhanced": "/api/v1/gpu-status",
    "work_unit_status": "/api/v1/work-units/status",
    "work_unit_queue": "/api/v1/work-units/queue",
    "work_unit_clients": "/api/v1/work-units/clients",
    "work_unit_statistics": "/api/v1/work-units/statistics",
    "work_unit_config": "/api/v1/work-units/config",
    "security_status": "/api/v1/security/status",
    "security_events": "/api/v1/security/events",
    "security_authenticate": "/api/v1/security/authenticate",
    "security_register": "/api/v1/security/register",
    "config": "/api/v1/config",
    "stats": "/api/v1/stats"
  }
}
```

## Work Unit Distribution API

### Work Unit Status

**GET /api/v1/work-units/status**

Returns overall work unit distributor status.

**Response:**
```json
{
  "success": true,
  "data": {
    "distributor_enabled": true,
    "pending_units": 5,
    "processing_units": 2,
    "completed_units": 1250,
    "failed_units": 12,
    "available_clients": 3,
    "status_report": "Work Unit Distributor Status:\n  Enabled: Yes\n  Workers Running: Yes\n  Pending Units: 5\n  Processing Units: 2\n  Completed Units: 1250\n  Failed Units: 12\n  Total Created: 1267\n  Total Completed: 1250\n  Total Failed: 12\n  Distribution Efficiency: 98.7%"
  }
}
```

### Work Unit Queue

**GET /api/v1/work-units/queue**

Returns current queue state.

**Response:**
```json
{
  "success": true,
  "data": {
    "pending_units": ["unit_001", "unit_002"],
    "processing_units": ["unit_003"],
    "completed_units": ["unit_004", "unit_005"],
    "failed_units": ["unit_006"],
    "queue_sizes": {
      "pending": 2,
      "processing": 1,
      "completed": 2,
      "failed": 1
    }
  }
}
```

### Work Unit Clients

**GET /api/v1/work-units/clients**

Returns available clients and their capabilities.

**Response:**
```json
{
  "success": true,
  "data": {
    "available_clients": ["client_001", "client_002", "client_003"],
    "client_count": 3,
    "performance_metrics": {
      "client_001_efficiency": 95.5,
      "client_001_avg_processing_time": 1250.0,
      "client_001_active_units": 1,
      "client_001_memory_usage": 512,
      "client_001_cpu_utilization": 45.0,
      "client_001_gpu_utilization": 78.0
    }
  }
}
```

### Work Unit Statistics

**GET /api/v1/work-units/statistics**

Returns detailed statistics about work unit processing.

**Response:**
```json
{
  "success": true,
  "total_units_created": 1267,
  "total_units_completed": 1250,
  "total_units_failed": 12,
  "total_units_timeout": 5,
  "average_processing_time_ms": 1250.0,
  "average_queue_wait_time_ms": 150.0,
  "distribution_efficiency_percent": 98.7,
  "current_queue_sizes": {
    "pending": 2,
    "processing": 1,
    "completed": 1250,
    "failed": 12
  },
  "work_unit_types": {
    "PROPAGATION_GRID": 800,
    "ANTENNA_PATTERN": 300,
    "FREQUENCY_OFFSET": 100,
    "AUDIO_PROCESSING": 67
  },
  "client_performance": {
    "client_001_efficiency": 95.5,
    "client_002_efficiency": 92.3,
    "client_003_efficiency": 88.7
  }
}
```

### Work Unit Configuration

**GET /api/v1/work-units/config**

Returns server configuration and requirements.

**Response:**
```json
{
  "success": true,
  "data": {
    "distribution_enabled": true,
    "acceleration_mode": "hybrid",
    "max_concurrent_units": 10,
    "max_queue_size": 1000,
    "unit_timeout_ms": 30000,
    "enable_retry": true,
    "max_retries": 3,
    "retry_delay_ms": 1000,
    "supported_work_unit_types": [
      "PROPAGATION_GRID",
      "ANTENNA_PATTERN",
      "FREQUENCY_OFFSET",
      "AUDIO_PROCESSING",
      "BATCH_QSO",
      "SOLAR_EFFECTS",
      "LIGHTNING_EFFECTS"
    ],
    "client_requirements": {
      "min_memory_mb": 512,
      "min_network_bandwidth_mbps": 10.0,
      "max_processing_latency_ms": 5000.0,
      "supported_frameworks": ["CUDA", "OpenCL", "Metal"]
    }
  }
}
```

## Security API

### Security Status

**GET /api/v1/security/status**

Returns overall security system status.

**Response:**
```json
{
  "success": true,
  "data": {
    "security_enabled": true,
    "security_report": "Work Unit Security Manager Status:\n  Enabled: Yes\n  Encryption: Yes\n  Signatures: Yes\n  Rate Limiting: Yes\n  Monitoring: Yes\n  Registered Clients: 5\n  Trusted Clients: 4\n  Blocked Clients: 1\n  Security Events: 23",
    "trusted_clients": 4,
    "blocked_clients": 1,
    "security_statistics": {
      "total_events": 23,
      "low_severity_events": 15,
      "medium_severity_events": 6,
      "high_severity_events": 2,
      "critical_severity_events": 0
    }
  }
}
```

### Security Events

**GET /api/v1/security/events?severity=medium**

Returns security events filtered by severity level.

**Query Parameters:**
- `severity` - Filter by severity level (low, medium, high, critical)

**Response:**
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "event_id": "evt_1234567890",
        "event_type": "AUTH_FAILED",
        "client_id": "client_001",
        "description": "Authentication failed",
        "severity": 1,
        "timestamp": 1703123456789,
        "requires_action": false,
        "recommended_action": "Check credentials"
      }
    ],
    "total_events": 1,
    "min_severity": 1
  }
}
```

### Client Authentication

**POST /api/v1/security/authenticate**

Authenticates a client using the specified authentication method.

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_data": "ak_1234567890abcdef",
  "auth_method": "api_key"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "client_id": "client_001",
    "auth_method": "api_key",
    "expires_at": "2023-12-22T10:30:00Z"
  }
}
```

### Client Registration

**POST /api/v1/security/register**

Registers a new client with the security system.

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_method": "api_key",
  "security_level": "medium",
  "capabilities": {
    "max_memory_mb": 2048,
    "supports_gpu": true,
    "network_bandwidth_mbps": 100.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "registered": true,
    "client_id": "client_001",
    "api_key": "ak_1234567890abcdef",
    "security_level": "medium",
    "auth_method": "api_key"
  }
}
```

## GPU Status API

### GPU Status

**GET /api/v1/gpu**

Returns basic GPU status information.

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
    "opencl_available": false
  }
}
```

### Enhanced GPU Status

**GET /api/v1/gpu-status**

Returns enhanced GPU status with work unit distribution information.

**Response:**
```json
{
  "success": true,
  "data": {
    "available": true,
    "acceleration_mode": "hybrid",
    "devices": [
      {
        "name": "NVIDIA GeForce RTX 3080",
        "vendor": "NVIDIA",
        "memory_total_mb": 10240,
        "memory_free_mb": 8192,
        "utilization_percent": 25.5,
        "temperature_celsius": 45.0,
        "power_usage_watts": 150.0
      }
    ],
    "queue_status": {
      "pending_tasks": 5,
      "active_tasks": 2,
      "completed_tasks": 1250,
      "failed_tasks": 12
    }
  }
}
```

## Propagation API

### Single Propagation Calculation

**POST /api/v1/propagation**

Calculates propagation between two points.

**Request Body:**
```json
{
  "lat1": 40.7128,
  "lon1": -74.0060,
  "alt1": 100.0,
  "lat2": 40.7589,
  "lon2": -73.9851,
  "alt2": 200.0,
  "frequency_mhz": 14.175,
  "tx_power_watts": 100.0,
  "include_solar_effects": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "signal_quality": 0.85,
    "signal_strength_db": -12.5,
    "distance_km": 8.2,
    "bearing_deg": 45.3,
    "elevation_angle_deg": 2.1,
    "propagation_mode": "skywave"
  }
}
```

### Batch Propagation Calculation

**POST /api/v1/propagation/batch**

Calculates propagation for multiple point pairs.

**Request Body:**
```json
{
  "calculations": [
    {
      "lat1": 40.7128,
      "lon1": -74.0060,
      "alt1": 100.0,
      "lat2": 40.7589,
      "lon2": -73.9851,
      "alt2": 200.0,
      "frequency_mhz": 14.175,
      "tx_power_watts": 100.0
    },
    {
      "lat1": 40.7128,
      "lon1": -74.0060,
      "alt1": 100.0,
      "lat2": 40.7831,
      "lon2": -73.9712,
      "alt2": 150.0,
      "frequency_mhz": 14.175,
      "tx_power_watts": 100.0
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "signal_quality": 0.85,
        "signal_strength_db": -12.5,
        "distance_km": 8.2,
        "bearing_deg": 45.3,
        "elevation_angle_deg": 2.1,
        "propagation_mode": "skywave"
      },
      {
        "signal_quality": 0.92,
        "signal_strength_db": -8.7,
        "distance_km": 6.1,
        "bearing_deg": 38.7,
        "elevation_angle_deg": 3.2,
        "propagation_mode": "skywave"
      }
    ],
    "total_calculations": 2,
    "processing_time_ms": 1250.0
  }
}
```

## Antenna Patterns API

### List Available Antennas

**GET /api/v1/antennas**

Returns list of available antenna patterns.

**Response:**
```json
{
  "success": true,
  "data": {
    "antennas": [
      {
        "name": "Yagi 6m",
        "type": "Yagi",
        "frequency_mhz": 50.0,
        "gain_db": 12.5,
        "pattern_file": "yagi_6m.ez"
      },
      {
        "name": "Yagi 2m",
        "type": "Yagi",
        "frequency_mhz": 144.0,
        "gain_db": 15.2,
        "pattern_file": "yagi_2m.ez"
      }
    ],
    "total_antennas": 2
  }
}
```

### Get Antenna Pattern

**GET /api/v1/antennas/{antenna_name}**

Returns antenna pattern data.

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "Yagi 6m",
    "type": "Yagi",
    "frequency_mhz": 50.0,
    "gain_db": 12.5,
    "pattern_data": {
      "elevation_angles": [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90],
      "azimuth_angles": [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 260, 270, 280, 290, 300, 310, 320, 330, 340, 350],
      "gain_pattern": [
        [12.5, 12.3, 12.1, 11.8, 11.5, 11.2, 10.8, 10.4, 10.0, 9.5, 9.0, 8.5, 8.0, 7.5, 7.0, 6.5, 6.0, 5.5, 5.0],
        [12.3, 12.1, 11.9, 11.6, 11.3, 11.0, 10.6, 10.2, 9.8, 9.3, 8.8, 8.3, 7.8, 7.3, 6.8, 6.3, 5.8, 5.3, 4.8]
      ]
    }
  }
}
```

## Ground Systems API

### List Ground Systems

**GET /api/v1/ground**

Returns list of available ground systems.

**Response:**
```json
{
  "success": true,
  "data": {
    "systems": [
      {
        "name": "80m-loop",
        "type": "Loop",
        "frequency_mhz": 3.5,
        "gain_db": 2.1,
        "available": true
      },
      {
        "name": "dipole",
        "type": "Dipole",
        "frequency_mhz": 14.175,
        "gain_db": 2.15,
        "available": true
      }
    ],
    "total_systems": 2
  }
}
```

### Get Ground System

**GET /api/v1/ground/{system_name}**

Returns ground system details.

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "80m-loop",
    "type": "Loop",
    "frequency_mhz": 3.5,
    "gain_db": 2.1,
    "pattern_file": "80m-loop.ez",
    "description": "80-meter loop antenna for HF communications"
  }
}
```

## Configuration API

### Get Configuration

**GET /api/v1/config**

Returns current server configuration.

**Response:**
```json
{
  "success": true,
  "data": {
    "server": {
      "host": "0.0.0.0",
      "port": 8080,
      "ssl_enabled": true,
      "certificate_path": "/etc/ssl/certs/server.crt",
      "private_key_path": "/etc/ssl/private/server.key"
    },
    "features": {
      "propagation": true,
      "solar_data": true,
      "band_status": true,
      "antenna_patterns": true,
      "ground_systems": true,
      "gpu_status": true,
      "work_unit_distribution": true,
      "security": true
    },
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 100,
      "burst_size": 20
    },
    "security": {
      "level": "medium",
      "encryption_enabled": true,
      "signature_validation_enabled": true,
      "rate_limiting_enabled": true,
      "monitoring_enabled": true
    }
  }
}
```

### Update Configuration

**PUT /api/v1/config**

Updates server configuration.

**Request Body:**
```json
{
  "rate_limiting": {
    "requests_per_minute": 200
  },
  "security": {
    "level": "high"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "updated": true,
    "message": "Configuration updated successfully"
  }
}
```

## Error Codes

### HTTP Status Codes

- **200 OK** - Request successful
- **400 Bad Request** - Invalid request parameters
- **401 Unauthorized** - Authentication required
- **403 Forbidden** - Access denied
- **404 Not Found** - Resource not found
- **429 Too Many Requests** - Rate limit exceeded
- **500 Internal Server Error** - Server error

### Error Response Format

```json
{
  "success": false,
  "error": "Error description",
  "error_code": 400,
  "timestamp": 1703123456789
}
```

### Common Error Messages

- **"Rate limit exceeded"** - Client has exceeded rate limits
- **"Authentication failed"** - Invalid credentials
- **"Missing required fields"** - Required parameters missing
- **"Invalid request"** - Request format is invalid
- **"Internal server error"** - Server encountered an error

## Rate Limiting

### Rate Limit Headers

All API responses include rate limiting headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1703124000
```

### Rate Limit Configuration

- **Default Limit**: 100 requests per minute
- **Burst Size**: 20 requests
- **Window**: 60 seconds
- **Penalty**: Temporary blocking for violations

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "error_code": 429,
  "retry_after": 60,
  "timestamp": 1703123456789
}
```

## Usage Examples

### Python Client Example

```python
import requests
import json

class FGComAPIClient:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}'
            })
    
    def get_health(self):
        """Get server health status"""
        response = self.session.get(f"{self.base_url}/health")
        return response.json()
    
    def get_api_info(self):
        """Get API information"""
        response = self.session.get(f"{self.base_url}/api/info")
        return response.json()
    
    def calculate_propagation(self, lat1, lon1, alt1, lat2, lon2, alt2, 
                            frequency_mhz, tx_power_watts):
        """Calculate propagation between two points"""
        data = {
            "lat1": lat1,
            "lon1": lon1,
            "alt1": alt1,
            "lat2": lat2,
            "lon2": lon2,
            "alt2": alt2,
            "frequency_mhz": frequency_mhz,
            "tx_power_watts": tx_power_watts,
            "include_solar_effects": True
        }
        
        response = self.session.post(f"{self.base_url}/api/v1/propagation", 
                                   json=data)
        return response.json()
    
    def get_work_unit_status(self):
        """Get work unit distribution status"""
        response = self.session.get(f"{self.base_url}/api/v1/work-units/status")
        return response.json()
    
    def get_security_status(self):
        """Get security system status"""
        response = self.session.get(f"{self.base_url}/api/v1/security/status")
        return response.json()

# Usage example
client = FGComAPIClient("http://localhost:8080")

# Check server health
health = client.get_health()
print(f"Server status: {health['status']}")

# Calculate propagation
result = client.calculate_propagation(
    lat1=40.7128, lon1=-74.0060, alt1=100.0,
    lat2=40.7589, lon2=-73.9851, alt2=200.0,
    frequency_mhz=14.175, tx_power_watts=100.0
)
print(f"Signal quality: {result['data']['signal_quality']}")

# Get work unit status
work_status = client.get_work_unit_status()
print(f"Pending units: {work_status['data']['pending_units']}")

# Get security status
security_status = client.get_security_status()
print(f"Security enabled: {security_status['data']['security_enabled']}")
```

### cURL Examples

```bash
# Check server health
curl -X GET "http://localhost:8080/health"

# Get API information
curl -X GET "http://localhost:8080/api/info"

# Calculate propagation
curl -X POST "http://localhost:8080/api/v1/propagation" \
     -H "Content-Type: application/json" \
     -d '{
       "lat1": 40.7128,
       "lon1": -74.0060,
       "alt1": 100.0,
       "lat2": 40.7589,
       "lon2": -73.9851,
       "alt2": 200.0,
       "frequency_mhz": 14.175,
       "tx_power_watts": 100.0,
       "include_solar_effects": true
     }'

# Get work unit status
curl -X GET "http://localhost:8080/api/v1/work-units/status"

# Get security status
curl -X GET "http://localhost:8080/api/v1/security/status"

# Authenticate client
curl -X POST "http://localhost:8080/api/v1/security/authenticate" \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "client_001",
       "auth_data": "ak_1234567890abcdef",
       "auth_method": "api_key"
     }'
```

## Band Segments Reference

For detailed band segment information and frequency allocations, refer to the comprehensive band segments database:

- **Band Segments CSV**: [https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv](https://github.com/Supermagnum/Supermorse-server/blob/main/Bandplans_and_antennas/band_segments.csv)

This CSV file contains detailed information about:
- Frequency allocations for different regions
- Band segments for various modulation modes
- ITU region specifications
- Channel spacing requirements
- Power limits and restrictions

## Conclusion

This API reference provides comprehensive documentation for all endpoints in the FGCom-mumble system. The API supports distributed radio propagation calculations with robust security, work unit distribution, and real-time monitoring capabilities.
