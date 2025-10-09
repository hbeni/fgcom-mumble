# FGCom-mumble API Reference - Complete Documentation

## Overview

FGCom-mumble provides comprehensive RESTful API and WebSocket interfaces for real-time radio communication simulation, terrain data access, and EME (Earth-Moon-Earth) communication support.

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

## Radio Communication API

### Radio Status

#### GET /radio/status
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

#### GET /radio/channels
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
      "name": "Ground Control",
      "frequency": 121.9,
      "type": "atc",
      "location": {
        "latitude": 40.6892,
        "longitude": -74.0445,
        "altitude": 10.0
      },
      "active_users": 3,
      "signal_quality": 0.95,
      "range_km": 50.0
    },
    {
      "id": "channel_002", 
      "name": "Tower",
      "frequency": 118.1,
      "type": "atc",
      "location": {
        "latitude": 40.6892,
        "longitude": -74.0445,
        "altitude": 15.0
      },
      "active_users": 2,
      "signal_quality": 0.88,
      "range_km": 30.0
    }
  ],
  "total_channels": 2,
  "page": 1,
  "per_page": 50
}
```

### Radio Communication

#### POST /radio/transmit
Start radio transmission.

**Request:**
```json
{
  "channel_id": "channel_001",
  "frequency": 121.9,
  "power_watts": 25.0,
  "antenna_gain_dbi": 2.15,
  "message": "Ground, this is N123AB, ready for taxi",
  "transmission_type": "voice",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 100.0,
    "heading": 270.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "transmission_id": "tx_789",
  "signal_quality": 0.87,
  "range_km": 45.2,
  "estimated_receivers": 3,
  "transmission_delay_ms": 12
}
```

#### GET /radio/transmissions/{transmission_id}
Get transmission status and results.

**Response:**
```json
{
  "transmission_id": "tx_789",
  "status": "completed",
  "start_time": "2024-01-15T10:30:00Z",
  "end_time": "2024-01-15T10:30:05Z",
  "duration_seconds": 5.0,
  "receivers": [
    {
      "user_id": "user_456",
      "signal_quality": 0.92,
      "distance_km": 12.3,
      "response_received": true,
      "response_time_ms": 45
    },
    {
      "user_id": "user_789",
      "signal_quality": 0.78,
      "distance_km": 28.7,
      "response_received": false,
      "response_time_ms": null
    }
  ]
}
```

#### POST /radio/receive
Receive radio transmission.

**Request:**
```json
{
  "channel_id": "channel_001",
  "frequency": 121.9,
  "antenna_gain_dbi": 2.15,
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 100.0,
    "heading": 270.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "received_transmissions": [
    {
      "transmission_id": "tx_789",
      "sender": "N123AB",
      "message": "Ground, this is N123AB, ready for taxi",
      "signal_quality": 0.87,
      "distance_km": 45.2,
      "frequency_offset_hz": 0.0,
      "received_time": "2024-01-15T10:30:00Z"
    }
  ]
}
```

## Terrain and Environmental Data API

### Terrain Data

#### GET /terrain/altitude
Get terrain altitude at specific coordinates.

**Query Parameters:**
- `latitude`: Latitude in decimal degrees
- `longitude`: Longitude in decimal degrees
- `resolution` (optional): Data resolution (1m, 10m, 100m, 1km)

**Example Request:**
```http
GET /terrain/altitude?latitude=40.6892&longitude=-74.0445&resolution=10m
```

**Response:**
```json
{
  "latitude": 40.6892,
  "longitude": -74.0445,
  "altitude_meters": 12.5,
  "resolution_meters": 10,
  "data_source": "ASTER_GDEM",
  "accuracy_meters": 5.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /terrain/line-of-sight
Check line of sight between two points.

**Query Parameters:**
- `lat1`, `lon1`: First point coordinates
- `lat2`, `lon2`: Second point coordinates
- `alt1`, `alt2`: Altitudes at each point (meters)
- `frequency` (optional): Operating frequency for atmospheric effects

**Example Request:**
```http
GET /terrain/line-of-sight?lat1=40.6892&lon1=-74.0445&alt1=100&lat2=40.7000&lon2=-74.0500&alt2=200&frequency=144.5
```

**Response:**
```json
{
  "line_of_sight": true,
  "distance_km": 1.2,
  "elevation_angle_deg": 4.7,
  "azimuth_angle_deg": 45.0,
  "terrain_clearance_m": 15.3,
  "atmospheric_effects": {
    "refraction_correction": 0.1,
    "attenuation_db": 0.05
  },
  "obstacles": []
}
```

### Environmental Conditions

#### GET /environmental/conditions
Get environmental conditions at specific location.

**Query Parameters:**
- `latitude`: Latitude in decimal degrees
- `longitude`: Longitude in decimal degrees
- `altitude` (optional): Altitude in meters (default: ground level)

**Response:**
```json
{
  "location": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 10.0
  },
  "temperature_celsius": 22.5,
  "humidity_percent": 65.0,
  "pressure_hpa": 1013.25,
  "wind_speed_mps": 5.2,
  "wind_direction_deg": 270.0,
  "precipitation_mmh": 0.0,
  "visibility_km": 15.0,
  "noise_floor_db": -120.5,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /environmental/noise-floor
Calculate radio noise floor at location.

**Query Parameters:**
- `latitude`: Latitude in decimal degrees
- `longitude`: Longitude in decimal degrees
- `frequency`: Operating frequency in MHz
- `bandwidth`: Receiver bandwidth in Hz

**Response:**
```json
{
  "location": {
    "latitude": 40.6892,
    "longitude": -74.0445
  },
  "frequency_mhz": 144.5,
  "bandwidth_hz": 500.0,
  "noise_floor_dbw": -147.2,
  "noise_floor_dbm": -117.2,
  "components": {
    "thermal_noise_db": -147.0,
    "atmospheric_noise_db": -2.0,
    "man_made_noise_db": -1.8,
    "galactic_noise_db": -0.5
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## EME (Earth-Moon-Earth) Communication API

### Moon Position Tracking

#### GET /eme/moon-position
Get current moon position and EME parameters.

**Query Parameters:**
- `band` (optional): EME band (2m, 6m, 70cm, 23cm, etc.)
- `frequency` (optional): Specific frequency in MHz

**Response:**
```json
{
  "moon_position": {
    "distance_km": 384400.0,
    "right_ascension_deg": 45.2,
    "declination_deg": 12.8,
    "longitude_libration_deg": 2.1,
    "latitude_libration_deg": -1.5,
    "phase_angle_deg": 45.0,
    "illumination_percent": 75.0
  },
  "eme_parameters": {
    "round_trip_delay_seconds": 2.565,
    "doppler_shift_hz": 0.0,
    "path_loss_db": 187.3,
    "moon_reflection_loss_db": 6.0,
    "atmospheric_loss_db": 0.5,
    "total_path_loss_db": 381.1
  },
  "band_info": {
    "name": "2m",
    "frequency_mhz": 144.0,
    "wavelength_m": 2.083,
    "typical_gain_dbi": 14.8,
    "noise_temp_k": 300.0
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /eme/optimal-windows
Get optimal EME communication windows.

**Query Parameters:**
- `days_ahead` (optional): Days to look ahead (default: 30)
- `band` (optional): Specific band to optimize for

**Response:**
```json
{
  "optimal_windows": [
    {
      "start_time": "2024-01-20T14:30:00Z",
      "end_time": "2024-01-20T20:30:00Z",
      "duration_hours": 6.0,
      "moon_distance_km": 356400.0,
      "delay_seconds": 2.378,
      "quality_score": 0.95,
      "band": "2m"
    },
    {
      "start_time": "2024-01-27T02:15:00Z", 
      "end_time": "2024-01-27T08:15:00Z",
      "duration_hours": 6.0,
      "moon_distance_km": 356400.0,
      "delay_seconds": 2.378,
      "quality_score": 0.92,
      "band": "2m"
    }
  ],
  "next_perigee": "2024-01-20T14:30:00Z",
  "next_apogee": "2024-02-03T08:45:00Z"
}
```

#### POST /eme/calculate-parameters
Calculate EME communication parameters.

**Request:**
```json
{
  "frequency_mhz": 144.5,
  "transmit_power_watts": 1000.0,
  "antenna_gain_dbi": 14.8,
  "system_noise_temp_k": 300.0,
  "bandwidth_hz": 500.0
}
```

**Response:**
```json
{
  "frequency_mhz": 144.5,
  "transmit_power_watts": 1000.0,
  "antenna_gain_dbi": 14.8,
  "effective_radiated_power_dbw": 44.8,
  "received_power_dbw": -321.5,
  "signal_to_noise_ratio_db": -174.7,
  "communication_range_km": 384400.0,
  "wavelength_m": 2.075,
  "path_loss_db": 187.3,
  "moon_reflection_loss_db": 6.0,
  "atmospheric_loss_db": 0.5,
  "total_path_loss_db": 381.1,
  "round_trip_delay_seconds": 2.565,
  "doppler_shift_hz": 0.0
}
```

## Vehicle Dynamics API

### Vehicle Registration

#### POST /vehicles/register
Register a new vehicle in the system.

**Request:**
```json
{
  "vehicle_id": "N123AB",
  "vehicle_type": "aircraft",
  "callsign": "N123AB",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 1000.0,
    "heading": 270.0
  },
  "capabilities": {
    "radio_frequencies": [121.9, 118.1, 124.0],
    "antenna_gain_dbi": 2.15,
    "transmit_power_watts": 25.0,
    "receive_sensitivity_dbw": -120.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "vehicle_id": "N123AB",
  "registration_id": "reg_789",
  "status": "active",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### PUT /vehicles/{vehicle_id}/position
Update vehicle position and attitude.

**Request:**
```json
{
  "position": {
    "latitude": 40.7000,
    "longitude": -74.0500,
    "altitude": 1200.0,
    "heading": 275.0
  },
  "velocity": {
    "ground_speed_kts": 150.0,
    "vertical_speed_fpm": 500.0
  },
  "attitude": {
    "pitch_deg": 2.0,
    "roll_deg": 1.0,
    "yaw_deg": 275.0
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "vehicle_id": "N123AB",
  "position_updated": true,
  "nearby_vehicles": [
    {
      "vehicle_id": "N456CD",
      "distance_km": 5.2,
      "bearing_deg": 45.0,
      "relative_altitude_m": 200.0
    }
  ]
}
```

### Antenna Management

#### GET /vehicles/{vehicle_id}/antennas
Get vehicle antenna information.

**Response:**
```json
{
  "vehicle_id": "N123AB",
  "antennas": [
    {
      "antenna_id": "ant_001",
      "type": "omnidirectional",
      "frequency_range_mhz": [118.0, 137.0],
      "gain_dbi": 2.15,
      "position": {
        "x_meters": 0.0,
        "y_meters": 0.0,
        "z_meters": 2.0
      },
      "orientation": {
        "azimuth_deg": 0.0,
        "elevation_deg": 0.0
      },
      "status": "active"
    }
  ]
}
```

#### POST /vehicles/{vehicle_id}/antennas/{antenna_id}/track
Enable antenna auto-tracking.

**Request:**
```json
{
  "target_type": "station",
  "target_id": "station_001",
  "tracking_enabled": true,
  "update_rate_hz": 10.0
}
```

**Response:**
```json
{
  "success": true,
  "antenna_id": "ant_001",
  "tracking_enabled": true,
  "target": {
    "type": "station",
    "id": "station_001",
    "distance_km": 15.2,
    "bearing_deg": 45.0,
    "elevation_deg": 2.0
  }
}
```

## WebSocket Real-Time Communication

### Connection

Connect to WebSocket endpoint:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function(event) {
    console.log('Connected to FGCom-mumble WebSocket');
    
    // Authenticate
    ws.send(JSON.stringify({
        type: 'auth',
        token: 'your_jwt_token_here'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};
```

### Message Types

#### Radio Transmission
```json
{
  "type": "radio_transmission",
  "transmission_id": "tx_789",
  "channel_id": "channel_001",
  "frequency": 121.9,
  "sender": "N123AB",
  "message": "Ground, this is N123AB, ready for taxi",
  "signal_quality": 0.87,
  "distance_km": 45.2,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Position Update
```json
{
  "type": "position_update",
  "vehicle_id": "N123AB",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 1000.0,
    "heading": 270.0
  },
  "velocity": {
    "ground_speed_kts": 150.0,
    "vertical_speed_fpm": 500.0
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### EME Status Update
```json
{
  "type": "eme_status",
  "moon_position": {
    "distance_km": 384400.0,
    "delay_seconds": 2.565,
    "doppler_shift_hz": 0.0
  },
  "optimal_windows": [
    {
      "start_time": "2024-01-20T14:30:00Z",
      "end_time": "2024-01-20T20:30:00Z",
      "quality_score": 0.95
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Terrain Data Update
```json
{
  "type": "terrain_update",
  "location": {
    "latitude": 40.6892,
    "longitude": -74.0445
  },
  "altitude_meters": 12.5,
  "line_of_sight": true,
  "environmental_conditions": {
    "temperature_celsius": 22.5,
    "humidity_percent": 65.0,
    "noise_floor_db": -120.5
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Sending Messages

#### Start Transmission
```json
{
  "type": "start_transmission",
  "channel_id": "channel_001",
  "frequency": 121.9,
  "message": "Ground, this is N123AB, ready for taxi",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 1000.0
  }
}
```

#### Update Position
```json
{
  "type": "update_position",
  "vehicle_id": "N123AB",
  "position": {
    "latitude": 40.7000,
    "longitude": -74.0500,
    "altitude": 1200.0,
    "heading": 275.0
  }
}
```

#### Request Terrain Data
```json
{
  "type": "request_terrain",
  "latitude": 40.6892,
  "longitude": -74.0445,
  "resolution": "10m"
}
```

## Error Handling

### Standard Error Response
```json
{
  "success": false,
  "error": {
    "code": "INVALID_FREQUENCY",
    "message": "Frequency 999.9 MHz is not supported",
    "details": {
      "supported_range": "118.0 - 137.0 MHz",
      "provided_frequency": 999.9
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_FREQUENCY` | Frequency not supported | 400 |
| `INVALID_COORDINATES` | Invalid latitude/longitude | 400 |
| `AUTHENTICATION_FAILED` | Invalid or expired token | 401 |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions | 403 |
| `VEHICLE_NOT_FOUND` | Vehicle ID not found | 404 |
| `CHANNEL_NOT_FOUND` | Radio channel not found | 404 |
| `TRANSMISSION_FAILED` | Radio transmission failed | 500 |
| `TERRAIN_DATA_UNAVAILABLE` | Terrain data not available | 503 |

## Rate Limiting

API requests are rate limited to prevent abuse:

- **Authentication**: 5 requests per minute
- **Radio Communication**: 100 requests per minute
- **Terrain Data**: 1000 requests per hour
- **EME Calculations**: 500 requests per hour
- **WebSocket Messages**: 1000 messages per minute

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248600
```

## SDK Examples

### Python SDK Example
```python
import requests
import json

class FGComClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def get_radio_channels(self, frequency_min=None, frequency_max=None):
        params = {}
        if frequency_min:
            params['frequency_min'] = frequency_min
        if frequency_max:
            params['frequency_max'] = frequency_max
        
        response = requests.get(
            f'{self.base_url}/radio/channels',
            headers=self.headers,
            params=params
        )
        return response.json()
    
    def transmit_radio(self, channel_id, frequency, message, position):
        data = {
            'channel_id': channel_id,
            'frequency': frequency,
            'message': message,
            'position': position
        }
        
        response = requests.post(
            f'{self.base_url}/radio/transmit',
            headers=self.headers,
            json=data
        )
        return response.json()
    
    def get_terrain_altitude(self, latitude, longitude):
        params = {
            'latitude': latitude,
            'longitude': longitude
        }
        
        response = requests.get(
            f'{self.base_url}/terrain/altitude',
            headers=self.headers,
            params=params
        )
        return response.json()

# Usage
client = FGComClient('http://localhost:8080/api/v1', 'your_token_here')

# Get radio channels
channels = client.get_radio_channels(frequency_min=118.0, frequency_max=137.0)
print(f"Found {len(channels['channels'])} channels")

# Transmit radio message
result = client.transmit_radio(
    channel_id='channel_001',
    frequency=121.9,
    message='Ground, this is N123AB',
    position={
        'latitude': 40.6892,
        'longitude': -74.0445,
        'altitude': 1000.0,
        'heading': 270.0
    }
)
print(f"Transmission ID: {result['transmission_id']}")

# Get terrain altitude
terrain = client.get_terrain_altitude(40.6892, -74.0445)
print(f"Altitude: {terrain['altitude_meters']} meters")
```

### JavaScript SDK Example
```javascript
class FGComClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.token = token;
    }
    
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        const response = await fetch(url, config);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error?.message || 'Request failed');
        }
        
        return data;
    }
    
    async getRadioChannels(frequencyMin, frequencyMax) {
        const params = new URLSearchParams();
        if (frequencyMin) params.append('frequency_min', frequencyMin);
        if (frequencyMax) params.append('frequency_max', frequencyMax);
        
        return this.request(`/radio/channels?${params}`);
    }
    
    async transmitRadio(channelId, frequency, message, position) {
        return this.request('/radio/transmit', {
            method: 'POST',
            body: JSON.stringify({
                channel_id: channelId,
                frequency: frequency,
                message: message,
                position: position
            })
        });
    }
    
    async getTerrainAltitude(latitude, longitude) {
        const params = new URLSearchParams({
            latitude: latitude.toString(),
            longitude: longitude.toString()
        });
        
        return this.request(`/terrain/altitude?${params}`);
    }
}

// Usage
const client = new FGComClient('http://localhost:8080/api/v1', 'your_token_here');

// Get radio channels
client.getRadioChannels(118.0, 137.0)
    .then(channels => {
        console.log(`Found ${channels.channels.length} channels`);
    })
    .catch(error => {
        console.error('Error:', error.message);
    });

// Transmit radio message
client.transmitRadio(
    'channel_001',
    121.9,
    'Ground, this is N123AB',
    {
        latitude: 40.6892,
        longitude: -74.0445,
        altitude: 1000.0,
        heading: 270.0
    }
)
.then(result => {
    console.log(`Transmission ID: ${result.transmission_id}`);
})
.catch(error => {
    console.error('Error:', error.message);
});
```

## Testing

### API Testing with curl

#### Authentication
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "pilot123",
    "password": "secure_password",
    "client_type": "flight_simulator"
  }'
```

#### Get Radio Channels
```bash
curl -X GET "http://localhost:8080/api/v1/radio/channels?frequency_min=118.0&frequency_max=137.0" \
  -H "Authorization: Bearer your_jwt_token_here"
```

#### Transmit Radio Message
```bash
curl -X POST http://localhost:8080/api/v1/radio/transmit \
  -H "Authorization: Bearer your_jwt_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "channel_id": "channel_001",
    "frequency": 121.9,
    "message": "Ground, this is N123AB, ready for taxi",
    "position": {
      "latitude": 40.6892,
      "longitude": -74.0445,
      "altitude": 1000.0,
      "heading": 270.0
    }
  }'
```

#### Get Terrain Altitude
```bash
curl -X GET "http://localhost:8080/api/v1/terrain/altitude?latitude=40.6892&longitude=-74.0445" \
  -H "Authorization: Bearer your_jwt_token_here"
```

#### Get Moon Position
```bash
curl -X GET "http://localhost:8080/api/v1/eme/moon-position?band=2m" \
  -H "Authorization: Bearer your_jwt_token_here"
```

## Satellite Communication API

### Satellite Simulation

#### POST /satellite/add
Add a fake satellite to the simulation system.

**Request:**
```json
{
  "name": "FAKE-SAT-1",
  "type": "AMATEUR_LINEAR",
  "mode": "LINEAR_TRANSPONDER",
  "tle": {
    "line1": "1 12345U 12345A   12345.12345678  .00000000  00000-0  00000-0 0  1234",
    "line2": "2 12345  98.5000 000.0000 0000000   0.0000   0.0000 14.12345678901234"
  },
  "frequencies": {
    "uplink": 145.900,
    "downlink": 435.800
  }
}
```

**Response:**
```json
{
  "success": true,
  "satellite": {
    "name": "FAKE-SAT-1",
    "type": "AMATEUR_LINEAR",
    "mode": "LINEAR_TRANSPONDER",
    "frequencies": {
      "uplink": 145.900,
      "downlink": 435.800
    },
    "tle_valid": true,
    "simulation_active": true
  }
}
```

#### POST /satellite/simulate
Simulate satellite communication with realistic effects.

**Request:**
```json
{
  "satellite": "FAKE-SAT-1",
  "ground_station": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 0.0
  },
  "audio_data": "base64_encoded_audio_data",
  "simulation_effects": {
    "doppler_shift": true,
    "signal_degradation": true,
    "orbital_mechanics": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "satellite": "FAKE-SAT-1",
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 400.0,
    "elevation": 45.2,
    "azimuth": 180.5,
    "range": 1200.5
  },
  "doppler_shift": 2.3,
  "simulated_audio": "base64_encoded_simulated_audio",
  "communication_quality": 0.85,
  "signal_strength": -85.2
}
```

#### GET /satellite/position/{satellite}
Get current satellite position and tracking data.

**Response:**
```json
{
  "success": true,
  "satellite": "FAKE-SAT-1",
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 400.0,
    "elevation": 45.2,
    "azimuth": 180.5,
    "range": 1200.5,
    "velocity": 7.5,
    "doppler_shift": 2.3
  },
  "visibility": {
    "visible": true,
    "elevation_angle": 45.2,
    "azimuth_angle": 180.5,
    "range_km": 1200.5
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /satellite/passes/{satellite}
Get satellite pass predictions.

**Query Parameters:**
- `hours` (optional): Hours to predict ahead (default: 24)

**Response:**
```json
{
  "success": true,
  "satellite": "FAKE-SAT-1",
  "passes": [
    {
      "aos": "2024-01-15T10:30:00Z",
      "los": "2024-01-15T10:45:00Z",
      "max_elevation": 67.8,
      "max_elevation_time": "2024-01-15T10:37:30Z",
      "duration": 900,
      "visible": true
    }
  ],
  "total_passes": 1,
  "next_pass": "2024-01-15T10:30:00Z"
}
```

#### POST /satellite/configure
Configure satellite simulation parameters.

**Request:**
```json
{
  "satellite": "FAKE-SAT-1",
  "parameters": {
    "tracking_enabled": true,
    "tracking_interval": 1.0,
    "doppler_compensation": true,
    "simulation_effects": {
      "signal_degradation": true,
      "atmospheric_effects": true,
      "orbital_mechanics": true
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "satellite": "FAKE-SAT-1",
  "configuration": {
    "tracking_enabled": true,
    "tracking_interval": 1.0,
    "doppler_compensation": true,
    "simulation_effects": {
      "signal_degradation": true,
      "atmospheric_effects": true,
      "orbital_mechanics": true
    }
  }
}
```

#### GET /satellite/list
List all available satellites (real and simulated).

**Response:**
```json
{
  "success": true,
  "satellites": [
    {
      "name": "FAKE-SAT-1",
      "type": "AMATEUR_LINEAR",
      "mode": "LINEAR_TRANSPONDER",
      "simulated": true,
      "active": true
    },
    {
      "name": "AO-7",
      "type": "AMATEUR_LINEAR",
      "mode": "LINEAR_TRANSPONDER",
      "simulated": false,
      "active": true
    }
  ],
  "total_satellites": 2
}
```

### Satellite Simulation Features

#### Supported Satellite Types
- **Military Satellites**: Strela-3, FLTSATCOM, Tsiklon
- **Amateur Satellites**: AO-7, FO-29, AO-73, XW-2 series, SO-50, AO-91, AO-85, ISS
- **IoT Satellites**: Orbcomm, Gonets

#### Simulation Capabilities
- **Orbital Mechanics**: TLE-based position calculations using SGP4/SDP4 algorithms
- **Doppler Shift**: Frequency compensation for satellite motion
- **Visibility**: Satellite pass predictions and tracking
- **Frequency Management**: Uplink/downlink frequency pairs
- **Communication Modes**: Linear transponder, FM repeater, digital modes
- **Signal Processing**: Realistic audio effects and degradation

### Python SDK Example for Satellite Simulation
```python
import requests
import json

class SatelliteAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def add_satellite(self, name, satellite_type, mode, tle, frequencies):
        data = {
            'name': name,
            'type': satellite_type,
            'mode': mode,
            'tle': tle,
            'frequencies': frequencies
        }
        
        response = requests.post(
            f'{self.base_url}/satellite/add',
            headers=self.headers,
            json=data
        )
        return response.json()
    
    def simulate_communication(self, satellite, ground_station, audio_data, effects):
        data = {
            'satellite': satellite,
            'ground_station': ground_station,
            'audio_data': audio_data,
            'simulation_effects': effects
        }
        
        response = requests.post(
            f'{self.base_url}/satellite/simulate',
            headers=self.headers,
            json=data
        )
        return response.json()
    
    def get_satellite_position(self, satellite):
        response = requests.get(
            f'{self.base_url}/satellite/position/{satellite}',
            headers=self.headers
        )
        return response.json()
    
    def get_satellite_passes(self, satellite, hours=24):
        params = {'hours': hours}
        response = requests.get(
            f'{self.base_url}/satellite/passes/{satellite}',
            headers=self.headers,
            params=params
        )
        return response.json()

# Usage
api = SatelliteAPI('http://localhost:8080/api/v1', 'your_token_here')

# Add fake satellite
satellite = api.add_satellite(
    name="FAKE-SAT-1",
    satellite_type="AMATEUR_LINEAR",
    mode="LINEAR_TRANSPONDER",
    tle={
        "line1": "1 12345U 12345A   12345.12345678  .00000000  00000-0  00000-0 0  1234",
        "line2": "2 12345  98.5000 000.0000 0000000   0.0000   0.0000 14.12345678901234"
    },
    frequencies={"uplink": 145.900, "downlink": 435.800}
)

# Simulate communication
result = api.simulate_communication(
    satellite="FAKE-SAT-1",
    ground_station={"latitude": 40.7128, "longitude": -74.0060, "altitude": 0.0},
    audio_data="base64_encoded_audio",
    effects={"doppler_shift": True, "signal_degradation": True}
)

print(f"Communication quality: {result['communication_quality']}")
print(f"Doppler shift: {result['doppler_shift']} Hz")
```

### JavaScript SDK Example for Satellite Simulation
```javascript
class SatelliteAPI {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.token = token;
    }
    
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        const response = await fetch(url, config);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error?.message || 'Request failed');
        }
        
        return data;
    }
    
    async addSatellite(name, type, mode, tle, frequencies) {
        return this.request('/satellite/add', {
            method: 'POST',
            body: JSON.stringify({
                name: name,
                type: type,
                mode: mode,
                tle: tle,
                frequencies: frequencies
            })
        });
    }
    
    async simulateCommunication(satellite, groundStation, audioData, effects) {
        return this.request('/satellite/simulate', {
            method: 'POST',
            body: JSON.stringify({
                satellite: satellite,
                ground_station: groundStation,
                audio_data: audioData,
                simulation_effects: effects
            })
        });
    }
    
    async getSatellitePosition(satellite) {
        return this.request(`/satellite/position/${satellite}`);
    }
    
    async getSatellitePasses(satellite, hours = 24) {
        const params = new URLSearchParams({ hours: hours.toString() });
        return this.request(`/satellite/passes/${satellite}?${params}`);
    }
}

// Usage
const api = new SatelliteAPI('http://localhost:8080/api/v1', 'your_token_here');

// Add fake satellite
api.addSatellite(
    'FAKE-SAT-1',
    'AMATEUR_LINEAR',
    'LINEAR_TRANSPONDER',
    {
        line1: '1 12345U 12345A   12345.12345678  .00000000  00000-0  00000-0 0  1234',
        line2: '2 12345  98.5000 000.0000 0000000   0.0000   0.0000 14.12345678901234'
    },
    { uplink: 145.900, downlink: 435.800 }
)
.then(satellite => {
    console.log('Satellite added:', satellite.satellite.name);
})
.catch(error => {
    console.error('Error:', error.message);
});

// Simulate communication
api.simulateCommunication(
    'FAKE-SAT-1',
    { latitude: 40.7128, longitude: -74.0060, altitude: 0.0 },
    'base64_encoded_audio',
    { doppler_shift: true, signal_degradation: true }
)
.then(result => {
    console.log(`Communication quality: ${result.communication_quality}`);
    console.log(`Doppler shift: ${result.doppler_shift} Hz`);
})
.catch(error => {
    console.error('Error:', error.message);
});
```

This comprehensive API reference provides complete documentation for all FGCom-mumble RESTful API endpoints and WebSocket communication, with practical examples in multiple programming languages.