# Fake Moon Placement API Documentation

## Overview

The Fake Moon Placement API provides comprehensive functionality for placing and managing artificial moons in the FGcom-Mumble simulation system. This API enables realistic orbital mechanics simulation, visibility calculations, and communication effects for custom moons.

## Features

- **Moon Placement**: Create fake moons with custom orbital parameters
- **Orbital Mechanics**: Realistic orbital calculations with Keplerian elements
- **Visibility Tracking**: Calculate moon visibility from ground stations
- **Communication Simulation**: Doppler shift and signal quality calculations
- **Real-time Updates**: Live position and communication status
- **Multi-moon Support**: Manage up to 50 simultaneous fake moons

## API Endpoints

### Base URL
```
http://localhost:8081/api/v1
```

### Authentication
Currently no authentication required (development mode).

## Endpoints

### 1. Add Fake Moon

**POST** `/moon/add`

Creates a new fake moon with specified orbital and physical parameters.

**Request Body:**
```json
{
  "name": "FAKE-MOON-1",
  "type": "COMMUNICATION",
  "mode": "REFLECTOR",
  "orbital_parameters": {
    "semi_major_axis": 384400,
    "eccentricity": 0.0,
    "inclination": 0.0,
    "longitude_of_ascending_node": 0.0,
    "orbital_period": 27.3
  },
  "physical_parameters": {
    "radius": 1737.4,
    "mass": 7.342e22,
    "albedo": 0.136
  },
  "frequencies": {
    "uplink": 145.900,
    "downlink": 435.800
  },
  "power": 100,
  "antenna_gain": 10,
  "minimum_elevation": 5,
  "maximum_range": 500000,
  "doppler_compensation": true,
  "atmospheric_effects": true,
  "signal_degradation": true
}
```

**Response:**
```json
{
  "success": true,
  "moon": {
    "id": "FAKE-MOON-1",
    "name": "FAKE-MOON-1",
    "type": "COMMUNICATION",
    "mode": "REFLECTOR",
    "orbital_parameters": {
      "semi_major_axis": 384400,
      "eccentricity": 0.0,
      "inclination": 0.0,
      "longitude_of_ascending_node": 0.0,
      "orbital_period": 27.3
    },
    "physical_parameters": {
      "radius": 1737.4,
      "mass": 7.342e22,
      "albedo": 0.136
    },
    "frequencies": {
      "uplink": 145.900,
      "downlink": 435.800
    },
    "power": 100,
    "antenna_gain": 10,
    "minimum_elevation": 5,
    "maximum_range": 500000,
    "simulation_effects": {
      "doppler_compensation": true,
      "atmospheric_effects": true,
      "signal_degradation": true
    },
    "active": true,
    "created_at": 1704067200
  }
}
```

### 2. Get Moon Position

**GET** `/moon/position/{moon_id}`

Retrieves current position and visibility data for a specific moon.

**Response:**
```json
{
  "success": true,
  "moon_id": "FAKE-MOON-1",
  "position": {
    "x": 384400.0,
    "y": 0.0,
    "z": 0.0,
    "distance": 384400.0,
    "true_anomaly": 0.0
  },
  "visibility": {
    "visible": true,
    "elevation": 45.2,
    "azimuth": 180.5,
    "distance": 384400.0
  },
  "doppler_shift": 2.3,
  "timestamp": 1704067200
}
```

### 3. Simulate Communication

**POST** `/moon/simulate/{moon_id}`

Simulates communication with a fake moon, including Doppler shift and signal quality calculations.

**Request Body:**
```json
{
  "ground_station": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 0.0
  },
  "audio_data": "base64_encoded_audio_data",
  "effects": {
    "doppler_shift": true,
    "signal_degradation": true,
    "atmospheric_effects": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "moon_id": "FAKE-MOON-1",
  "position": {
    "x": 384400.0,
    "y": 0.0,
    "z": 0.0,
    "distance": 384400.0,
    "elevation": 45.2,
    "azimuth": 180.5
  },
  "communication": {
    "doppler_shift": 2.3,
    "signal_quality": 0.85,
    "signal_strength": -85.2,
    "communication_quality": 0.85,
    "uplink_frequency": 145.9023,
    "downlink_frequency": 435.8023
  },
  "simulated_audio": "base64_encoded_audio_data",
  "timestamp": 1704067200
}
```

### 4. List All Moons

**GET** `/moon/list`

Returns a list of all active fake moons.

**Response:**
```json
{
  "success": true,
  "moons": [
    {
      "id": "FAKE-MOON-1",
      "name": "FAKE-MOON-1",
      "type": "COMMUNICATION",
      "mode": "REFLECTOR",
      "active": true,
      "created_at": 1704067200
    }
  ],
  "total_moons": 1,
  "max_moons": 50
}
```

### 5. Remove Moon

**DELETE** `/moon/remove/{moon_id}`

Removes a fake moon from the simulation.

**Response:**
```json
{
  "success": true,
  "message": "Moon removed: FAKE-MOON-1"
}
```

## Orbital Parameters

### Keplerian Elements

- **semi_major_axis**: Semi-major axis of the orbit (km)
- **eccentricity**: Orbital eccentricity (0.0 = circular, 0.0-1.0 = elliptical)
- **inclination**: Orbital inclination relative to equatorial plane (degrees)
- **longitude_of_ascending_node**: Longitude of ascending node (degrees)
- **orbital_period**: Orbital period in days

### Physical Parameters

- **radius**: Moon radius (km)
- **mass**: Moon mass (kg)
- **albedo**: Surface albedo (reflectivity, 0.0-1.0)

### Communication Parameters

- **frequencies**: Uplink and downlink frequencies (MHz)
- **power**: Transmitter power (watts)
- **antenna_gain**: Antenna gain (dBi)
- **minimum_elevation**: Minimum elevation angle for visibility (degrees)
- **maximum_range**: Maximum communication range (km)

## Simulation Effects

### Doppler Shift
- Calculated based on relative velocity between moon and ground station
- Automatically applied to uplink and downlink frequencies
- Can be enabled/disabled per moon

### Signal Quality
- Distance-based signal degradation
- Atmospheric effects based on elevation angle
- Configurable signal quality parameters

### Atmospheric Effects
- Signal degradation at low elevation angles
- Realistic atmospheric absorption modeling
- Weather-dependent signal quality

## Usage Examples

### Python Example

```python
import requests
import json

class FakeMoonAPI:
    def __init__(self, base_url="http://localhost:8081/api/v1"):
        self.base_url = base_url
    
    def add_moon(self, name, orbital_params, physical_params, frequencies):
        data = {
            "name": name,
            "type": "COMMUNICATION",
            "mode": "REFLECTOR",
            "orbital_parameters": orbital_params,
            "physical_parameters": physical_params,
            "frequencies": frequencies,
            "power": 100,
            "antenna_gain": 10,
            "minimum_elevation": 5,
            "maximum_range": 500000,
            "doppler_compensation": True,
            "atmospheric_effects": True,
            "signal_degradation": True
        }
        
        response = requests.post(f"{self.base_url}/moon/add", json=data)
        return response.json()
    
    def get_moon_position(self, moon_id):
        response = requests.get(f"{self.base_url}/moon/position/{moon_id}")
        return response.json()
    
    def simulate_communication(self, moon_id, ground_station, audio_data, effects):
        data = {
            "ground_station": ground_station,
            "audio_data": audio_data,
            "effects": effects
        }
        
        response = requests.post(f"{self.base_url}/moon/simulate/{moon_id}", json=data)
        return response.json()
    
    def list_moons(self):
        response = requests.get(f"{self.base_url}/moon/list")
        return response.json()
    
    def remove_moon(self, moon_id):
        response = requests.delete(f"{self.base_url}/moon/remove/{moon_id}")
        return response.json()

# Usage
api = FakeMoonAPI()

# Add a fake moon
moon = api.add_moon(
    name="TEST-MOON-1",
    orbital_params={
        "semi_major_axis": 384400,
        "eccentricity": 0.0,
        "inclination": 0.0,
        "longitude_of_ascending_node": 0.0,
        "orbital_period": 27.3
    },
    physical_params={
        "radius": 1737.4,
        "mass": 7.342e22,
        "albedo": 0.136
    },
    frequencies={
        "uplink": 145.900,
        "downlink": 435.800
    }
)

print(f"Moon created: {moon['moon']['id']}")

# Get moon position
position = api.get_moon_position("TEST-MOON-1")
print(f"Moon position: {position['position']}")

# Simulate communication
communication = api.simulate_communication(
    "TEST-MOON-1",
    {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude": 0.0
    },
    "base64_audio_data",
    {
        "doppler_shift": True,
        "signal_degradation": True,
        "atmospheric_effects": True
    }
)

print(f"Communication quality: {communication['communication']['communication_quality']}")
```

### JavaScript Example

```javascript
class FakeMoonAPI {
    constructor(baseUrl = 'http://localhost:8081/api/v1') {
        this.baseUrl = baseUrl;
    }
    
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };
        
        const response = await fetch(url, config);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    }
    
    async addMoon(name, orbitalParams, physicalParams, frequencies) {
        const data = {
            name: name,
            type: 'COMMUNICATION',
            mode: 'REFLECTOR',
            orbital_parameters: orbitalParams,
            physical_parameters: physicalParams,
            frequencies: frequencies,
            power: 100,
            antenna_gain: 10,
            minimum_elevation: 5,
            maximum_range: 500000,
            doppler_compensation: true,
            atmospheric_effects: true,
            signal_degradation: true
        };
        
        return this.request('/moon/add', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    async getMoonPosition(moonId) {
        return this.request(`/moon/position/${moonId}`);
    }
    
    async simulateCommunication(moonId, groundStation, audioData, effects) {
        const data = {
            ground_station: groundStation,
            audio_data: audioData,
            effects: effects
        };
        
        return this.request(`/moon/simulate/${moonId}`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    async listMoons() {
        return this.request('/moon/list');
    }
    
    async removeMoon(moonId) {
        return this.request(`/moon/remove/${moonId}`, {
            method: 'DELETE'
        });
    }
}

// Usage
const api = new FakeMoonAPI();

// Add a fake moon
api.addMoon(
    'TEST-MOON-1',
    {
        semi_major_axis: 384400,
        eccentricity: 0.0,
        inclination: 0.0,
        longitude_of_ascending_node: 0.0,
        orbital_period: 27.3
    },
    {
        radius: 1737.4,
        mass: 7.342e22,
        albedo: 0.136
    },
    {
        uplink: 145.900,
        downlink: 435.800
    }
)
.then(moon => {
    console.log(`Moon created: ${moon.moon.id}`);
})
.catch(error => {
    console.error('Error:', error.message);
});

// Get moon position
api.getMoonPosition('TEST-MOON-1')
.then(position => {
    console.log('Moon position:', position.position);
})
.catch(error => {
    console.error('Error:', error.message);
});
```

## Error Handling

All API endpoints return JSON responses with a `success` field indicating the operation status. Error responses include an `error` field with descriptive messages.

### Common Error Codes

- **400 Bad Request**: Invalid JSON or missing required parameters
- **404 Not Found**: Moon ID not found
- **500 Internal Server Error**: Server-side processing error

### Error Response Format

```json
{
  "success": false,
  "error": "Moon not found: INVALID-MOON-ID"
}
```

## Configuration

The API server can be configured by modifying the `MOON_API_CONFIG` table in `server/api/fake_moon_api.lua`:

```lua
local MOON_API_CONFIG = {
    port = 8081,                    -- API server port
    host = "0.0.0.0",              -- Bind address
    max_moons = 50,                 -- Maximum number of moons
    default_altitude = 384400,      -- Default altitude (km)
    default_radius = 1737.4,        -- Default radius (km)
    orbital_period = 27.3,          -- Default orbital period (days)
    max_communication_range = 500000 -- Maximum communication range (km)
}
```

## Starting the API Server

To start the fake moon API server:

```bash
cd server/api
luajit fake_moon_api.lua
```

The server will start on `http://localhost:8081` and provide all the documented endpoints.

## Integration with FGcom-Mumble

The fake moon API integrates seamlessly with the existing FGcom-Mumble satellite communication system:

1. **Satellite System Integration**: Fake moons use the same orbital mechanics as real satellites
2. **Frequency Management**: Compatible with existing frequency allocation systems
3. **Communication Protocols**: Uses the same communication protocols as satellite systems
4. **Ground Station Support**: Compatible with existing ground station infrastructure

## Advanced Features

### Real-time Tracking
- Continuous position updates
- Live visibility calculations
- Real-time Doppler shift compensation

### Multi-moon Support
- Up to 50 simultaneous fake moons
- Independent orbital parameters for each moon
- Individual communication settings

### Realistic Physics
- Keplerian orbital mechanics
- Gravitational effects
- Atmospheric modeling
- Signal propagation calculations

This comprehensive API provides everything needed to create and manage fake moons in the FGcom-Mumble simulation system with realistic orbital mechanics and communication effects.
