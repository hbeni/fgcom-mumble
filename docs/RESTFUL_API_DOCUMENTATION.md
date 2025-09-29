# RESTful API Documentation

## Overview

The FGCom-mumble RESTful API provides comprehensive HTTP endpoints for external integration, real-time monitoring, and system control. The API supports both RESTful HTTP requests and WebSocket real-time updates.

## Base URLs

- **Development**: `http://localhost:8080/api/v1`
- **Production**: `https://fgcom-mumble.example.com/api/v1`
- **WebSocket**: `ws://localhost:8080/ws` or `wss://fgcom-mumble.example.com/ws`

## Authentication

All API endpoints require authentication using Bearer tokens:

```http
Authorization: Bearer your_jwt_token_here
```

### Authentication Endpoints

#### POST /auth/login
Authenticate user and receive JWT token.

**Request:**
```json
{
  "username": "pilot123",
  "password": "secure_password",
  "client_type": "flight_simulator"
}
```

**Response:**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "user": {
    "id": "user_123",
    "username": "pilot123",
    "role": "pilot",
    "permissions": ["radio_communication", "terrain_access"]
  }
}
```

#### POST /auth/refresh
Refresh JWT token.

**Request:**
```json
{
  "refresh_token": "your_refresh_token_here"
}
```

**Response:**
```json
{
  "success": true,
  "token": "new_jwt_token_here",
  "expires_in": 3600
}
```

## Core System Endpoints

### Health Check

#### GET /health
Get server health status.

**Response:**
```json
{
  "status": "healthy",
  "uptime": "2d 14h 32m",
  "version": "1.4.1",
  "timestamp": "2024-01-15T10:30:00Z",
  "services": {
    "radio_communication": "operational",
    "terrain_analysis": "operational",
    "antenna_patterns": "operational",
    "propagation_modeling": "operational"
  }
}
```

### API Information

#### GET /api/info
Get API information and available features.

**Response:**
```json
{
  "title": "FGCom-mumble API",
  "version": "1.4.1",
  "description": "Radio communication simulation API",
  "contact": "support@fgcom-mumble.com",
  "features": {
    "propagation": true,
    "solar_data": true,
    "band_status": true,
    "antenna_patterns": true,
    "ground_systems": true,
    "gpu_status": true
  },
  "endpoints": {
    "propagation": "/api/v1/propagation",
    "solar_data": "/api/v1/solar",
    "band_status": "/api/v1/bands",
    "antenna_patterns": "/api/v1/antennas",
    "ground_systems": "/api/v1/ground",
    "gpu_status": "/api/v1/gpu-status"
  }
}
```

## Radio Communication API

### Radio Status

#### GET /api/v1/radio/status
Get current radio system status.

**Response:**
```json
{
  "system_status": "operational",
  "active_channels": 15,
  "connected_users": 42,
  "server_load": 0.23,
  "uptime": "2d 14h 32m",
  "version": "1.4.1"
}
```

#### GET /api/v1/radio/channels
List all available radio channels.

**Query Parameters:**
- `frequency_min` (optional): Minimum frequency in MHz
- `frequency_max` (optional): Maximum frequency in MHz
- `type` (optional): Channel type (atc, pilot, emergency, etc.)
- `active_only` (optional): Show only active channels (default: true)

**Response:**
```json
{
  "channels": [
    {
      "id": "channel_001",
      "frequency": 121.5,
      "type": "emergency",
      "name": "Emergency Frequency",
      "active": true,
      "users": 3,
      "signal_strength": -85.2
    },
    {
      "id": "channel_002",
      "frequency": 118.1,
      "type": "atc",
      "name": "Tower Frequency",
      "active": true,
      "users": 8,
      "signal_strength": -72.1
    }
  ],
  "total_channels": 2,
  "active_channels": 2
}
```

### Frequency Management

#### POST /api/v1/radio/tune
Tune to a specific frequency.

**Request:**
```json
{
  "frequency": 121.5,
  "mode": "AM",
  "squelch": true,
  "squelch_threshold": -80.0
}
```

**Response:**
```json
{
  "success": true,
  "frequency": 121.5,
  "mode": "AM",
  "signal_strength": -85.2,
  "squelch_open": true,
  "audio_quality": "good"
}
```

#### GET /api/v1/radio/signal-strength
Get current signal strength.

**Response:**
```json
{
  "frequency": 121.5,
  "signal_strength": -85.2,
  "noise_floor": -95.0,
  "snr": 9.8,
  "quality": "good",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Propagation API

### Single Propagation Calculation

#### POST /api/v1/propagation
Calculate propagation between two points.

**Request:**
```json
{
  "transmitter": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 1000,
    "frequency": 121.5,
    "power": 25.0,
    "antenna_gain": 3.0
  },
  "receiver": {
    "latitude": 40.7589,
    "longitude": -73.9851,
    "altitude": 500,
    "antenna_gain": 0.0
  },
  "conditions": {
    "solar_activity": "moderate",
    "weather": "clear",
    "terrain": "urban"
  }
}
```

**Response:**
```json
{
  "success": true,
  "distance_km": 12.5,
  "path_loss_db": 95.2,
  "received_power_dbw": -70.2,
  "signal_strength": -85.2,
  "propagation_mode": "line_of_sight",
  "reliability": 0.95,
  "calculations": {
    "free_space_loss": 92.1,
    "atmospheric_loss": 1.2,
    "terrain_loss": 2.0,
    "antenna_gain": 3.0
  }
}
```

### Batch Propagation Calculation

#### POST /api/v1/propagation/batch
Calculate propagation for multiple transmitter-receiver pairs.

**Request:**
```json
{
  "transmitters": [
    {
      "id": "tx_001",
      "latitude": 40.7128,
      "longitude": -74.0060,
      "altitude": 1000,
      "frequency": 121.5,
      "power": 25.0
    }
  ],
  "receivers": [
    {
      "id": "rx_001",
      "latitude": 40.7589,
      "longitude": -73.9851,
      "altitude": 500
    },
    {
      "id": "rx_002",
      "latitude": 40.6892,
      "longitude": -74.0445,
      "altitude": 200
    }
  ],
  "conditions": {
    "solar_activity": "moderate",
    "weather": "clear"
  }
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "transmitter_id": "tx_001",
      "receiver_id": "rx_001",
      "distance_km": 12.5,
      "path_loss_db": 95.2,
      "signal_strength": -85.2
    },
    {
      "transmitter_id": "tx_001",
      "receiver_id": "rx_002",
      "distance_km": 8.3,
      "path_loss_db": 89.1,
      "signal_strength": -79.1
    }
  ],
  "total_calculations": 2,
  "processing_time_ms": 45.2
}
```

## Solar Data API

### Current Solar Data

#### GET /api/v1/solar
Get current solar activity data.

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "solar_flux": 150.2,
  "sunspot_number": 45,
  "k_index": 2,
  "a_index": 8,
  "magnetic_field": "quiet",
  "propagation_conditions": "good",
  "forecast": {
    "next_24h": "good",
    "next_48h": "fair",
    "next_72h": "poor"
  }
}
```

### Solar Data History

#### GET /api/v1/solar/history
Get historical solar data.

**Query Parameters:**
- `start_date` (required): Start date (ISO 8601 format)
- `end_date` (required): End date (ISO 8601 format)
- `data_points` (optional): Number of data points (default: 100)

**Response:**
```json
{
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-01-15T23:59:59Z",
  "data_points": 100,
  "data": [
    {
      "timestamp": "2024-01-01T00:00:00Z",
      "solar_flux": 145.2,
      "sunspot_number": 42,
      "k_index": 1,
      "a_index": 5
    }
  ]
}
```

## Band Status API

### All Bands Status

#### GET /api/v1/bands
Get status of all frequency bands.

**Response:**
```json
{
  "bands": [
    {
      "name": "HF",
      "frequency_range": "3-30 MHz",
      "status": "open",
      "conditions": "good",
      "solar_impact": "moderate",
      "recommended_frequencies": [7.2, 14.2, 21.2, 28.2]
    },
    {
      "name": "VHF",
      "frequency_range": "30-300 MHz",
      "status": "open",
      "conditions": "excellent",
      "solar_impact": "low",
      "recommended_frequencies": [121.5, 146.52, 446.0]
    }
  ]
}
```

### Specific Band Status

#### GET /api/v1/bands/{band_name}
Get status of a specific frequency band.

**Response:**
```json
{
  "name": "VHF",
  "frequency_range": "30-300 MHz",
  "status": "open",
  "conditions": "excellent",
  "solar_impact": "low",
  "propagation_modes": ["line_of_sight", "tropospheric_ducting"],
  "recommended_frequencies": [121.5, 146.52, 446.0],
  "current_activity": {
    "active_stations": 15,
    "signal_quality": "good",
    "noise_level": "low"
  }
}
```

## Antenna Patterns API

### List Antennas

#### GET /api/v1/antennas
List all available antenna patterns.

**Query Parameters:**
- `type` (optional): Antenna type (yagi, dipole, vertical, etc.)
- `frequency_min` (optional): Minimum frequency in MHz
- `frequency_max` (optional): Maximum frequency in MHz

**Response:**
```json
{
  "antennas": [
    {
      "name": "4m_yagi",
      "type": "yagi",
      "frequency_range": "70-70.5 MHz",
      "gain": 11.01,
      "beamwidth": 45.2,
      "front_to_back": 21.45,
      "patterns_available": 19
    },
    {
      "name": "2m_dipole",
      "type": "dipole",
      "frequency_range": "144-148 MHz",
      "gain": 2.15,
      "beamwidth": 360.0,
      "front_to_back": 0.0,
      "patterns_available": 1
    }
  ],
  "total_antennas": 2
}
```

### Get Antenna Pattern

#### GET /api/v1/antennas/{antenna_name}
Get antenna pattern data.

**Query Parameters:**
- `frequency` (optional): Specific frequency in MHz
- `pitch` (optional): Antenna pitch angle in degrees
- `roll` (optional): Antenna roll angle in degrees
- `height` (optional): Antenna height in meters

**Response:**
```json
{
  "name": "4m_yagi",
  "frequency": 70.15,
  "pitch": 0,
  "roll": 0,
  "height": 10,
  "pattern_data": {
    "azimuth": [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95, 100, 105, 110, 115, 120, 125, 130, 135, 140, 145, 150, 155, 160, 165, 170, 175, 180, 185, 190, 195, 200, 205, 210, 215, 220, 225, 230, 235, 240, 245, 250, 255, 260, 265, 270, 275, 280, 285, 290, 295, 300, 305, 310, 315, 320, 325, 330, 335, 340, 345, 350, 355, 360],
    "elevation": [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95, 100, 105, 110, 115, 120, 125, 130, 135, 140, 145, 150, 155, 160, 165, 170, 175, 180],
    "gain_pattern": [
      [11.01, 11.00, 10.98, 10.95, 10.91, 10.86, 10.80, 10.73, 10.65, 10.56, 10.46, 10.35, 10.23, 10.10, 9.96, 9.81, 9.65, 9.48, 9.30, 9.11, 8.91, 8.70, 8.48, 8.25, 8.01, 7.76, 7.50, 7.23, 6.95, 6.66, 6.36, 6.05, 5.73, 5.40, 5.06, 4.71, 4.35, 3.98, 3.60, 3.21, 2.81, 2.40, 1.98, 1.55, 1.11, 0.66, 0.20, -0.27, -0.75, -1.24, -1.74, -2.25, -2.77, -3.30, -3.84, -4.39, -4.95, -5.52, -6.10, -6.69, -7.29, -7.90, -8.52, -9.15, -9.79, -10.44, -11.10, -11.77, -12.45, -13.14, -13.84, -14.55, -15.27, -16.00, -16.74, -17.49, -18.25, -19.02, -19.80, -20.59, -21.39, -22.20, -23.02, -23.85, -24.69, -25.54, -26.40, -27.27, -28.15, -29.04, -29.94, -30.85, -31.77, -32.70, -33.64, -34.59, -35.55, -36.52, -37.50, -38.49, -39.49, -40.50, -41.52, -42.55, -43.59, -44.64, -45.70, -46.77, -47.85, -48.94, -50.04, -51.15, -52.27, -53.40, -54.54, -55.69, -56.85, -58.02, -59.20, -60.39, -61.59, -62.80, -64.02, -65.25, -66.49, -67.74, -69.00, -70.27, -71.55, -72.84, -74.14, -75.45, -76.77, -78.10, -79.44, -80.79, -82.15, -83.52, -84.90, -86.29, -87.69, -89.10, -90.52, -91.95, -93.39, -94.84, -96.30, -97.77, -99.25, -100.74, -102.24, -103.75, -105.27, -106.80, -108.34, -109.89, -111.45, -113.02, -114.60, -116.19, -117.79, -119.40, -121.02, -122.65, -124.29, -125.94, -127.60, -129.27, -130.95, -132.64, -134.34, -136.05, -137.77, -139.50, -141.24, -142.99, -144.75, -146.52, -148.30, -150.09, -151.89, -153.70, -155.52, -157.35, -159.19, -161.04, -162.90, -164.77, -166.65, -168.54, -170.44, -172.35, -174.27, -176.20, -178.14, -180.09, -182.05, -184.02, -186.00, -187.99, -189.99, -192.00, -194.02, -196.05, -198.09, -200.14, -202.20, -204.27, -206.35, -208.44, -210.54, -212.65, -214.77, -216.90, -219.04, -221.19, -223.35, -225.52, -227.70, -229.89, -232.09, -234.30, -236.52, -238.75, -240.99, -243.24, -245.50, -247.77, -250.05, -252.34, -254.64, -256.95, -259.27, -261.60, -263.94, -266.29, -268.65, -271.02, -273.40, -275.79, -278.19, -280.60, -283.02, -285.45, -287.89, -290.34, -292.80, -295.27, -297.75, -300.24, -302.74, -305.25, -307.77, -310.30, -312.84, -315.39, -317.95, -320.52, -323.10, -325.69, -328.29, -330.90, -333.52, -336.15, -338.79, -341.44, -344.10, -346.77, -349.45, -352.14, -354.84, -357.55, -360.27]
    ]
  },
  "metadata": {
    "frequency": 70.15,
    "pitch": 0,
    "roll": 0,
    "height": 10,
    "gain": 11.01,
    "beamwidth": 45.2,
    "front_to_back": 21.45
  }
}
```

## Ground Systems API

### List Ground Systems

#### GET /api/v1/ground
List all available ground systems.

**Response:**
```json
{
  "ground_systems": [
    {
      "name": "airport_tower",
      "type": "control_tower",
      "location": {
        "latitude": 40.6892,
        "longitude": -74.1745,
        "altitude": 100
      },
      "frequencies": [118.1, 121.5, 124.9],
      "antenna_height": 50,
      "power": 25.0
    },
    {
      "name": "emergency_services",
      "type": "emergency",
      "location": {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude": 50
      },
      "frequencies": [121.5, 155.5],
      "antenna_height": 30,
      "power": 50.0
    }
  ],
  "total_systems": 2
}
```

### Get Ground System Details

#### GET /api/v1/ground/{system_name}
Get detailed information about a specific ground system.

**Response:**
```json
{
  "name": "airport_tower",
  "type": "control_tower",
  "location": {
    "latitude": 40.6892,
    "longitude": -74.1745,
    "altitude": 100
  },
  "frequencies": [118.1, 121.5, 124.9],
  "antenna_height": 50,
  "power": 25.0,
  "coverage": {
    "radius_km": 25.0,
    "elevation_angle": 5.0,
    "propagation_mode": "line_of_sight"
  },
  "status": "active",
  "last_update": "2024-01-15T10:30:00Z"
}
```

## GPU Status API

### GPU Status

#### GET /api/v1/gpu-status
Get GPU acceleration status and performance metrics.

**Response:**
```json
{
  "gpu_available": true,
  "gpu_name": "NVIDIA GeForce RTX 4080",
  "driver_version": "535.86.10",
  "cuda_version": "12.2",
  "memory": {
    "total_mb": 16384,
    "used_mb": 2048,
    "free_mb": 14336
  },
  "utilization": {
    "gpu_percent": 15.2,
    "memory_percent": 12.5,
    "temperature_c": 45.0
  },
  "acceleration_enabled": {
    "antenna_patterns": true,
    "propagation_modeling": true,
    "audio_processing": false
  },
  "performance": {
    "operations_per_second": 1250,
    "average_latency_ms": 2.1,
    "peak_latency_ms": 8.5
  }
}
```

## Work Unit Distribution API

### Work Unit Status

#### GET /api/v1/work-units/status
Get work unit distributor status.

**Response:**
```json
{
  "distributor_status": "active",
  "total_work_units": 1250,
  "completed_work_units": 1100,
  "pending_work_units": 150,
  "processing_rate": 45.2,
  "average_processing_time_ms": 125.5,
  "clients_connected": 8,
  "load_balancing": "optimal"
}
```

### Work Unit Queue

#### GET /api/v1/work-units/queue
Get current work unit queue state.

**Response:**
```json
{
  "queue_length": 150,
  "queue_status": "healthy",
  "oldest_work_unit_age_seconds": 45.2,
  "queue_categories": {
    "propagation_calculations": 75,
    "antenna_patterns": 45,
    "audio_processing": 30
  },
  "priority_levels": {
    "high": 25,
    "medium": 100,
    "low": 25
  }
}
```

### Work Unit Clients

#### GET /api/v1/work-units/clients
Get information about connected clients.

**Response:**
```json
{
  "clients": [
    {
      "client_id": "client_001",
      "status": "active",
      "work_units_assigned": 15,
      "work_units_completed": 12,
      "performance_score": 0.95,
      "last_activity": "2024-01-15T10:29:45Z"
    },
    {
      "client_id": "client_002",
      "status": "idle",
      "work_units_assigned": 0,
      "work_units_completed": 8,
      "performance_score": 0.88,
      "last_activity": "2024-01-15T10:25:30Z"
    }
  ],
  "total_clients": 2,
  "active_clients": 1
}
```

## AGC & Squelch API

### AGC Status

#### GET /api/agc/status
Get Automatic Gain Control status.

**Response:**
```json
{
  "enabled": true,
  "mode": "automatic",
  "current_gain_db": 15.2,
  "threshold_db": -80.0,
  "attack_time_ms": 10.0,
  "release_time_ms": 100.0,
  "max_gain_db": 30.0,
  "min_gain_db": 0.0,
  "performance": {
    "average_gain_db": 12.5,
    "gain_variation_db": 2.1,
    "response_time_ms": 8.5
  }
}
```

### Squelch Status

#### GET /api/squelch/status
Get squelch system status.

**Response:**
```json
{
  "enabled": true,
  "threshold_db": -85.0,
  "hysteresis_db": 3.0,
  "attack_time_ms": 5.0,
  "release_time_ms": 50.0,
  "tone_squelch": false,
  "noise_squelch": true,
  "current_state": "open",
  "signal_strength_db": -82.0
}
```

### Combined AGC/Squelch Configuration

#### POST /api/agc-squelch/config
Configure combined AGC and squelch settings.

**Request:**
```json
{
  "agc": {
    "enabled": true,
    "mode": "automatic",
    "threshold_db": -80.0,
    "attack_time_ms": 10.0,
    "release_time_ms": 100.0,
    "max_gain_db": 30.0,
    "min_gain_db": 0.0
  },
  "squelch": {
    "enabled": true,
    "threshold_db": -85.0,
    "hysteresis_db": 3.0,
    "attack_time_ms": 5.0,
    "release_time_ms": 50.0,
    "tone_squelch": false,
    "noise_squelch": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## WebSocket Real-time Updates

### Connection

#### WebSocket Endpoint: /ws
Connect to WebSocket for real-time updates.

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('WebSocket connected');
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

### Message Types

#### Propagation Updates
```json
{
  "type": "propagation_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "transmitter_id": "tx_001",
    "receiver_id": "rx_001",
    "signal_strength": -85.2,
    "path_loss": 95.2,
    "propagation_mode": "line_of_sight"
  }
}
```

#### Solar Data Updates
```json
{
  "type": "solar_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "solar_flux": 150.2,
    "sunspot_number": 45,
    "k_index": 2,
    "propagation_conditions": "good"
  }
}
```

#### Vehicle Position Updates
```json
{
  "type": "vehicle_position",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "vehicle_id": "vehicle_001",
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 1000,
    "heading": 45.0,
    "speed": 250.0
  }
}
```

#### System Status Updates
```json
{
  "type": "system_status",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "status": "operational",
    "active_channels": 15,
    "connected_users": 42,
    "server_load": 0.23
  }
}
```

## Error Handling

### Error Response Format

All API endpoints return errors in the following format:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_FREQUENCY",
    "message": "Frequency must be between 3.0 and 3000.0 MHz",
    "details": {
      "provided_frequency": 5000.0,
      "valid_range": "3.0-3000.0 MHz"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Common Error Codes

- **INVALID_FREQUENCY**: Frequency out of valid range
- **INVALID_COORDINATES**: Latitude/longitude out of range
- **AUTHENTICATION_FAILED**: Invalid or expired token
- **PERMISSION_DENIED**: Insufficient permissions
- **RESOURCE_NOT_FOUND**: Requested resource not found
- **RATE_LIMIT_EXCEEDED**: Too many requests
- **SERVER_ERROR**: Internal server error

## Rate Limiting

### Rate Limits

- **General API**: 1000 requests per hour
- **Propagation API**: 100 requests per hour
- **Solar Data API**: 500 requests per hour
- **WebSocket**: 1000 messages per hour

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248600
```

## Authentication & Security

### JWT Token Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_123",
    "username": "pilot123",
    "role": "pilot",
    "permissions": ["radio_communication", "terrain_access"],
    "iat": 1642248600,
    "exp": 1642252200
  }
}
```

### Permission Levels

- **admin**: Full system access
- **operator**: System monitoring and control
- **pilot**: Radio communication and navigation
- **observer**: Read-only access

## Examples

### Python Client Example

```python
import requests
import json

# Authentication
auth_response = requests.post('http://localhost:8080/auth/login', json={
    'username': 'pilot123',
    'password': 'secure_password',
    'client_type': 'flight_simulator'
})

token = auth_response.json()['token']
headers = {'Authorization': f'Bearer {token}'}

# Get radio status
status_response = requests.get('http://localhost:8080/api/v1/radio/status', headers=headers)
print(json.dumps(status_response.json(), indent=2))

# Calculate propagation
propagation_response = requests.post('http://localhost:8080/api/v1/propagation', 
    headers=headers,
    json={
        'transmitter': {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'altitude': 1000,
            'frequency': 121.5,
            'power': 25.0
        },
        'receiver': {
            'latitude': 40.7589,
            'longitude': -73.9851,
            'altitude': 500
        }
    }
)
print(json.dumps(propagation_response.json(), indent=2))
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to FGCom-mumble WebSocket');
    
    // Subscribe to propagation updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'propagation_updates'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'propagation_update':
            console.log('Propagation update:', data.data);
            break;
        case 'solar_update':
            console.log('Solar data update:', data.data);
            break;
        case 'vehicle_position':
            console.log('Vehicle position:', data.data);
            break;
    }
};
```

This comprehensive RESTful API provides complete integration capabilities for external systems, real-time monitoring, and system control.
