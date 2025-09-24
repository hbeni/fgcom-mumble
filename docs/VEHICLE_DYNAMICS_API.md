# FGCom-mumble Vehicle Dynamics API Documentation

## Overview

The Vehicle Dynamics API provides comprehensive tracking and control of vehicle orientation, speed, attitude, altitude, and antenna rotation for accurate radio propagation calculations. This API is essential for directional antennas like Yagis, where vehicle orientation directly affects antenna pointing.

## Base URL

```
http://localhost:8080/api/v1/vehicles
```

## Key Features

- **Vehicle Registration**: Register and manage vehicles (aircraft, boats, ships, ground vehicles)
- **Real-time Dynamics**: Track heading, speed, attitude, and altitude
- **Antenna Rotation**: Control rotatable antennas (Yagis, directional arrays)
- **Antenna Control**: Manual antenna pointing and orientation control
- **WebSocket Updates**: Real-time vehicle dynamics updates

## Data Structures

### Vehicle Dynamics
```json
{
  "vehicle_id": "N12345",
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_ft_msl": 3500.0,
    "altitude_ft_agl": 3000.0,
    "ground_elevation_ft": 500.0,
    "callsign": "N12345",
    "vehicle_type": "aircraft"
  },
  "attitude": {
    "pitch_deg": 2.5,
    "roll_deg": -1.2,
    "yaw_deg": 045.0,
    "magnetic_heading_deg": 043.5,
    "magnetic_declination_deg": -1.5
  },
  "velocity": {
    "speed_knots": 180.0,
    "speed_kmh": 333.3,
    "speed_ms": 92.6,
    "course_deg": 045.0,
    "vertical_speed_fpm": 500.0,
    "vertical_speed_ms": 2.5
  },
  "antennas": [
    {
      "antenna_id": "vertical_hf",
      "antenna_type": "vertical",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "is_rotatable": false
    },
    {
      "antenna_id": "dipole_vhf",
      "antenna_type": "dipole",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "is_rotatable": false
    }
  ],
  "status": "active",
  "last_update": "2024-01-15T10:30:00Z"
}
```

## API Endpoints

### 1. Vehicle Registration

**POST** `/api/v1/vehicles/register`

Register a new vehicle in the system.

**Request Body:**
```json
{
  "vehicle_id": "N12345",
  "vehicle_type": "aircraft",
  "callsign": "N12345",
  "initial_position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_ft_msl": 3500.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Vehicle registered successfully",
  "vehicle_id": "N12345",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 2. Vehicle Unregistration

**DELETE** `/api/v1/vehicles/{vehicle_id}`

Remove a vehicle from the system.

**Response:**
```json
{
  "success": true,
  "message": "Vehicle unregistered successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 3. Get Vehicle Dynamics

**GET** `/api/v1/vehicles/{vehicle_id}/dynamics`

Get complete vehicle dynamics information.

**Query Parameters:**
- `include_attitude`: Include attitude data (default: true)
- `include_velocity`: Include velocity data (default: true)
- `include_antennas`: Include antenna data (default: true)
- `include_position`: Include position data (default: true)

**Response:**
```json
{
  "success": true,
  "data": {
    "vehicle_id": "N12345",
    "position": { ... },
    "attitude": { ... },
    "velocity": { ... },
    "antennas": [ ... ],
    "status": "active",
    "last_update": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 4. Update Vehicle Position

**PUT** `/api/v1/vehicles/{vehicle_id}/position`

Update vehicle position information.

**Request Body:**
```json
{
  "latitude": 40.7128,
  "longitude": -74.0060,
  "altitude_ft_msl": 3500.0,
  "altitude_ft_agl": 3000.0,
  "ground_elevation_ft": 500.0
}
```

### 5. Update Vehicle Attitude

**PUT** `/api/v1/vehicles/{vehicle_id}/attitude`

Update vehicle attitude (pitch, roll, yaw).

**Request Body:**
```json
{
  "pitch_deg": 2.5,
  "roll_deg": -1.2,
  "yaw_deg": 045.0,
  "magnetic_heading_deg": 043.5
}
```

### 6. Update Vehicle Velocity

**PUT** `/api/v1/vehicles/{vehicle_id}/velocity`

Update vehicle velocity information.

**Request Body:**
```json
{
  "speed_knots": 180.0,
  "course_deg": 045.0,
  "vertical_speed_fpm": 500.0
}
```

### 7. Get All Vehicles

**GET** `/api/v1/vehicles`

Get list of all registered vehicles.

**Query Parameters:**
- `vehicle_type`: Filter by vehicle type (aircraft, boat, ship, vehicle, ground_station)
- `status`: Filter by status (active, inactive, maintenance)
- `in_range`: Filter vehicles within range of a point
  - `center_lat`: Center latitude
  - `center_lon`: Center longitude
  - `radius_km`: Radius in kilometers

**Response:**
```json
{
  "success": true,
  "data": {
    "vehicles": [
      {
        "vehicle_id": "N12345",
        "vehicle_type": "aircraft",
        "status": "active",
        "last_update": "2024-01-15T10:30:00Z"
      }
    ],
    "total_count": 1
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Antenna Rotation API

### 8. Rotate Antenna

**POST** `/api/v1/vehicles/{vehicle_id}/antennas/{antenna_id}/rotate`

Rotate a specific antenna to a target position.

**Request Body:**
```json
{
  "target_azimuth_deg": 090.0,
  "target_elevation_deg": 20.0,
  "immediate": false,
  "rotation_mode": "absolute"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Antenna rotation initiated",
  "current_orientation": {
    "azimuth_deg": 045.0,
    "elevation_deg": 15.0
  },
  "estimated_arrival_time_sec": 4.5,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 9. Get Antenna Status

**GET** `/api/v1/vehicles/{vehicle_id}/antennas/{antenna_id}/status`

Get current antenna orientation and status.

**Response:**
```json
{
  "success": true,
  "data": {
    "antenna_id": "vertical_hf",
    "antenna_type": "vertical",
    "azimuth_deg": 0.0,
    "elevation_deg": 0.0,
    "is_rotatable": false,
    "last_update": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```


### 10. Get Vehicle Antennas

**GET** `/api/v1/vehicles/{vehicle_id}/antennas`

Get all antennas for a specific vehicle.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "antenna_id": "yagi_20m",
      "antenna_type": "yagi",
      "azimuth_deg": 045.0,
      "elevation_deg": 15.0,
      "is_rotatable": true,
      "is_auto_tracking": false
    },
    {
      "antenna_id": "vertical_40m",
      "antenna_type": "vertical",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "is_rotatable": false
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## WebSocket Real-time Updates

Connect to `/ws/vehicles` for real-time vehicle dynamics updates:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws/vehicles');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'vehicle_position_update':
      console.log('Vehicle position updated:', data.vehicle_id, data.position);
      break;
    case 'vehicle_attitude_update':
      console.log('Vehicle attitude updated:', data.vehicle_id, data.attitude);
      break;
    case 'vehicle_velocity_update':
      console.log('Vehicle velocity updated:', data.vehicle_id, data.velocity);
      break;
    case 'antenna_rotation_update':
      console.log('Antenna rotation updated:', data.vehicle_id, data.antenna_id, data.orientation);
      break;
    case 'vehicle_registered':
      console.log('New vehicle registered:', data.vehicle_id);
      break;
    case 'vehicle_unregistered':
      console.log('Vehicle unregistered:', data.vehicle_id);
      break;
  }
};
```

### WebSocket Message Types

1. **Vehicle Position Update**: `{"type": "vehicle_position_update", "vehicle_id": "N12345", "position": {...}}`
2. **Vehicle Attitude Update**: `{"type": "vehicle_attitude_update", "vehicle_id": "N12345", "attitude": {...}}`
3. **Vehicle Velocity Update**: `{"type": "vehicle_velocity_update", "vehicle_id": "N12345", "velocity": {...}}`
4. **Antenna Rotation Update**: `{"type": "antenna_rotation_update", "vehicle_id": "N12345", "antenna_id": "yagi_20m", "orientation": {...}}`
5. **Vehicle Registered**: `{"type": "vehicle_registered", "vehicle_id": "N12345", "vehicle_type": "aircraft"}`
6. **Vehicle Unregistered**: `{"type": "vehicle_unregistered", "vehicle_id": "N12345"}`

## Integration with Propagation Calculations

Vehicle dynamics are automatically integrated into propagation calculations:

### Antenna Orientation Effects
- **Yagi Antennas**: Vehicle attitude affects antenna pointing direction
- **Dipole Antennas**: Vehicle orientation affects polarization
- **Vertical Antennas**: Less affected by vehicle attitude
- **Loop Antennas**: Cannot be rotated, but vehicle attitude affects orientation

### Propagation Model Integration
```json
{
  "lat1": 40.7128,
  "lon1": -74.0060,
  "lat2": 51.5074,
  "lon2": -0.1278,
  "frequency_mhz": 14.0,
  "power_watts": 100.0,
  "antenna_type": "yagi",
  "include_vehicle_dynamics": true,
  "vehicle_id": "N12345",
  "antenna_id": "yagi_20m"
}
```

The propagation calculation will automatically:
1. Get current vehicle attitude and position
2. Calculate antenna orientation based on vehicle attitude
3. Apply antenna pattern based on current orientation
4. Include vehicle speed effects on Doppler shift
5. Account for altitude changes in propagation

## Examples

### Python Client Example

```python
import requests
import json

# Base URL
base_url = "http://localhost:8080/api/v1/vehicles"

# Register a new aircraft
aircraft_data = {
    "vehicle_id": "N12345",
    "vehicle_type": "aircraft",
    "callsign": "N12345",
    "initial_position": {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude_ft_msl": 3500.0
    }
}

response = requests.post(f"{base_url}/register", json=aircraft_data)
result = response.json()

if result["success"]:
    print(f"Aircraft {result['vehicle_id']} registered successfully")

# Update aircraft attitude
attitude_data = {
    "pitch_deg": 2.5,
    "roll_deg": -1.2,
    "yaw_deg": 045.0,
    "magnetic_heading_deg": 043.5
}

response = requests.put(f"{base_url}/N12345/attitude", json=attitude_data)
result = response.json()

if result["success"]:
    print("Aircraft attitude updated")

# Rotate Yagi antenna
rotation_data = {
    "target_azimuth_deg": 090.0,
    "target_elevation_deg": 20.0,
    "immediate": False
}

response = requests.post(f"{base_url}/N12345/antennas/yagi_20m/rotate", json=rotation_data)
result = response.json()

if result["success"]:
    print(f"Antenna rotation initiated, ETA: {result['estimated_arrival_time_sec']} seconds")
```

### JavaScript Client Example

```javascript
// Register vehicle
async function registerVehicle() {
  const response = await fetch('/api/v1/vehicles/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      vehicle_id: 'N12345',
      vehicle_type: 'aircraft',
      callsign: 'N12345',
      initial_position: {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude_ft_msl: 3500.0
      }
    })
  });
  
  const result = await response.json();
  
  if (result.success) {
    console.log('Vehicle registered:', result.vehicle_id);
  }
}

// Update vehicle dynamics
async function updateVehicleDynamics(vehicleId, dynamics) {
  const response = await fetch(`/api/v1/vehicles/${vehicleId}/dynamics`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(dynamics)
  });
  
  const result = await response.json();
  
  if (result.success) {
    console.log('Vehicle dynamics updated');
  }
}

// Rotate antenna
async function rotateAntenna(vehicleId, antennaId, azimuth, elevation) {
  const response = await fetch(`/api/v1/vehicles/${vehicleId}/antennas/${antennaId}/rotate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      target_azimuth_deg: azimuth,
      target_elevation_deg: elevation,
      immediate: false
    })
  });
  
  const result = await response.json();
  
  if (result.success) {
    console.log('Antenna rotation initiated');
  }
}
```

### cURL Examples

```bash
# Register vehicle
curl -X POST http://localhost:8080/api/v1/vehicles/register \
  -H "Content-Type: application/json" \
  -d '{
    "vehicle_id": "N12345",
    "vehicle_type": "aircraft",
    "callsign": "N12345",
    "initial_position": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "altitude_ft_msl": 3500.0
    }
  }'

# Update attitude
curl -X PUT http://localhost:8080/api/v1/vehicles/N12345/attitude \
  -H "Content-Type: application/json" \
  -d '{
    "pitch_deg": 2.5,
    "roll_deg": -1.2,
    "yaw_deg": 045.0
  }'

# Rotate antenna
curl -X POST http://localhost:8080/api/v1/vehicles/N12345/antennas/yagi_20m/rotate \
  -H "Content-Type: application/json" \
  -d '{
    "target_azimuth_deg": 090.0,
    "target_elevation_deg": 20.0,
    "immediate": false
  }'

# Get vehicle dynamics
curl http://localhost:8080/api/v1/vehicles/N12345/dynamics

# Get all vehicles
curl http://localhost:8080/api/v1/vehicles
```

## Configuration

Vehicle dynamics can be configured in the main configuration file:

```ini
[vehicle_dynamics]
enabled = true
auto_cleanup_enabled = true
cleanup_interval_seconds = 300
default_rotation_speed_deg_per_sec = 10.0
magnetic_declination_source = auto
antenna_rotation_enabled = true
```

## Error Codes

- `400`: Bad Request - Invalid request parameters
- `401`: Unauthorized - Missing or invalid API key
- `403`: Forbidden - Access denied
- `404`: Not Found - Vehicle or antenna not found
- `409`: Conflict - Vehicle already exists
- `422`: Unprocessable Entity - Invalid vehicle dynamics data
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error - Server error

## Performance Considerations

- Vehicle dynamics updates are optimized for real-time performance
- WebSocket connections are limited to prevent resource exhaustion
- Antenna rotation calculations are optimized for performance
- Vehicle cleanup runs automatically to remove inactive vehicles
- Antenna rotation calculations include collision detection for safety

## Security Considerations

- Vehicle registration requires appropriate permissions
- Antenna rotation commands are validated for safety limits
- Antenna rotation can be disabled for security-sensitive applications
- Rate limiting prevents abuse of vehicle dynamics APIs
- WebSocket connections are authenticated and rate-limited
