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
- **3D Attitude Support**: Full pitch, roll, and yaw rotation tracking
- **Antenna Rotation**: Control rotatable antennas (Yagis, directional arrays) with real-time yaw support
- **Antenna Control**: Manual antenna pointing and orientation control
- **Pattern Integration**: Seamless integration with pre-generated 3D attitude radiation patterns
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
    },
    {
      "antenna_id": "dipole_vhf",
      "antenna_type": "dipole",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
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
      "antenna_id": "vhf_whip",
      "antenna_type": "whip",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "is_auto_tracking": false
    },
    {
      "antenna_id": "vertical_40m",
      "antenna_type": "vertical",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
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
4. **Antenna Rotation Update**: `{"type": "antenna_rotation_update", "vehicle_id": "N12345", "antenna_id": "vhf_whip", "orientation": {...}}`
5. **Vehicle Registered**: `{"type": "vehicle_registered", "vehicle_id": "N12345", "vehicle_type": "aircraft"}`
6. **Vehicle Unregistered**: `{"type": "vehicle_unregistered", "vehicle_id": "N12345"}`

## Integration with Propagation Calculations

Vehicle dynamics are automatically integrated into propagation calculations:

### Antenna Orientation Effects
- **Yagi Antennas**: Vehicle attitude affects antenna pointing direction
- **Dipole Antennas**: Vehicle orientation affects polarization
- **Vertical Antennas**: Less affected by vehicle attitude
- **Loop Antennas**: Cannot be rotated, but vehicle attitude affects orientation

### 3D Attitude Pattern Integration

The system now supports full 3D attitude modeling:

- **Pre-generated Patterns**: 3D attitude patterns generated for pitch/roll combinations
- **Real-time Yaw**: Yaw rotation handled dynamically via API
- **Python Transformations**: Reliable coordinate transformations using Python
- **Aviation Coordinate System**: Standard X-forward, Y-right, Z-up system
- **Pattern Quality**: More accurate radiation patterns with proper ground effects

### Propagation Model Integration
```json
{
  "lat1": 40.7128,
  "lon1": -74.0060,
  "lat2": 51.5074,
  "lon2": -0.1278,
  "frequency_mhz": 14.0,
  "power_watts": 100.0,
  "antenna_type": "whip",
  "include_vehicle_dynamics": true,
  "vehicle_id": "N12345",
  "antenna_id": "vhf_whip"
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

response = requests.post(f"{base_url}/N12345/antennas/vhf_whip/rotate", json=rotation_data)
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
curl -X POST http://localhost:8080/api/v1/vehicles/N12345/antennas/vhf_whip/rotate \
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

## EZNEC Multi-Antenna Modeling Guidelines

### Critical Limitation: Single Active Antenna Per Model

**Important**: Due to EZNEC's computational nature, it is not possible to model multiple active antennas (VHF and HF) simultaneously in the same model. This will produce incorrect radiation data and other modeling issues.

### Proper Multi-Antenna Modeling Approach

To get correct radiation patterns for vehicles with multiple antennas:

1. **Active Antenna**: Only one antenna should have a source/feed point
2. **Passive Elements**: Other antennas must be modeled as wires without feed points
3. **Mutual Coupling**: Passive elements will still affect the active antenna through mutual coupling

### Example: Tu-95 "Bear" with VHF Antenna

```eznec
EZNEC ver. 7.0

DESCRIPTION
Tu-95 "Bear" Strategic Bomber with Primary VHF Communications Antenna
Aircraft Structure: 49.5m fuselage, 51.1m wingspan, realistic wire grid
VHF Antenna: 3m monopole on fuselage centerline for 118-174 MHz operation
Model includes fuselage, wings, stabilizers, and existing HF antennas
Grid spacing optimized for VHF frequency analysis

FREQUENCY
150.0  MHz

ENVIRONMENT
0  (Free Space)

GROUND
0  (No Ground)

WIRES
99

WIRE DATA
W001  99  -24.750  0.000  0.000  24.750  0.000  0.000  0.003
W002  10  -24.750  0.000  1.450  -19.750  0.000  1.450  0.003
W003  10  -19.750  0.000  1.450  -14.750  0.000  1.450  0.003
W004  10  -14.750  0.000  1.450  -9.750  0.000  1.450  0.003
W005  10  -9.750  0.000  1.450  -4.750  0.000  1.450  0.003
W006  10  -4.750  0.000  1.450  0.250  0.000  1.450  0.003
W007  10  0.250  0.000  1.450  5.250  0.000  1.450  0.003
W008  10  5.250  0.000  1.450  10.250  0.000  1.450  0.003
W009  10  10.250  0.000  1.450  15.250  0.000  1.450  0.003
W010  10  15.250  0.000  1.450  20.250  0.000  1.450  0.003
W011  10  20.250  0.000  1.450  24.750  0.000  1.450  0.003

REM Fuselage Cross-Sections (Circular approximation)
W012  8  -20.000  -1.450  0.000  -20.000  1.450  0.000  0.003
W013  8  -20.000  1.450  0.000  -20.000  -1.450  0.000  0.003
W014  8  -15.000  -1.450  0.000  -15.000  1.450  0.000  0.003
W015  8  -15.000  1.450  0.000  -15.000  -1.450  0.000  0.003
W016  8  -10.000  -1.450  0.000  -10.000  1.450  0.000  0.003
W017  8  -10.000  1.450  0.000  -10.000  -1.450  0.000  0.003
W018  8  -5.000  -1.450  0.000  -5.000  1.450  0.000  0.003
W019  8  -5.000  1.450  0.000  -5.000  -1.450  0.000  0.003
W020  8  0.000  -1.450  0.000  0.000  1.450  0.000  0.003
W021  8  0.000  1.450  0.000  0.000  -1.450  0.000  0.003
W022  8  5.000  -1.450  0.000  5.000  1.450  0.000  0.003
W023  8  5.000  1.450  0.000  5.000  -1.450  0.000  0.003
W024  8  10.000  -1.450  0.000  10.000  1.450  0.000  0.003
W025  8  10.000  1.450  0.000  10.000  -1.450  0.000  0.003
W026  8  15.000  -1.450  0.000  15.000  1.450  0.000  0.003
W027  8  15.000  1.450  0.000  15.000  -1.450  0.000  0.003
W028  8  20.000  -1.450  0.000  20.000  1.450  0.000  0.003
W029  8  20.000  1.450  0.000  20.000  -1.450  0.000  0.003

REM Main Wings (Swept back design)
W030  48  -8.000  -25.550  -0.500  -12.000  -1.550  0.500  0.003
W031  48  -8.000  25.550  -0.500  -12.000  1.550  0.500  0.003
W032  10  -8.000  -25.550  -0.500  -8.000  -1.550  -0.500  0.003
W033  10  -8.000  25.550  -0.500  -8.000  1.550  -0.500  0.003
W034  10  -12.000  -25.550  0.500  -12.000  -1.550  0.500  0.003
W035  10  -12.000  25.550  0.500  -12.000  1.550  0.500  0.003

REM Vertical Stabilizer
W036  22  15.000  0.000  1.450  15.000  0.000  12.550  0.003
W037  10  15.000  -2.000  1.450  15.000  2.000  1.450  0.003
W038  10  15.000  -2.000  12.550  15.000  2.000  12.550  0.003

REM Horizontal Stabilizers
W039  24  10.000  -6.000  2.000  10.000  6.000  2.000  0.003
W040  12  10.000  -6.000  2.000  20.000  -6.000  2.500  0.003
W041  12  10.000  6.000  2.000  20.000  6.000  2.500  0.003
W042  10  20.000  -6.000  2.500  20.000  6.000  2.500  0.003

REM Existing HF Antennas (PASSIVE - No Source)
W043  26  8.000  0.000  -0.500  34.000  0.000  -3.500  0.003
W044  12  5.000  0.000  2.000  5.000  0.000  5.000  0.005

REM Direction Finding Loops (PASSIVE - No Source)
W045  4  -10.000  -20.000  1.800  -10.000  -19.500  2.200  0.004
W046  4  -10.000  20.000  1.800  -10.000  19.500  2.200  0.004

REM VHF Communications Antenna (ACTIVE - With Source)
W047  12  0.000  0.000  1.450  0.000  0.000  4.450  0.008

SOURCES
1
SRC  W047  6  0  1.000  0.000

LOADS
0

TRANSMISSION LINES
0

NETWORKS
0

END
```

### Key Modeling Principles

1. **Single Source**: Only one antenna (W047) has a source point
2. **Passive Elements**: HF antennas (W043, W044) and DF loops (W045, W046) are present but unpowered
3. **Mutual Coupling**: Passive elements affect the active antenna's radiation pattern
4. **Realistic Effects**: Shows actual operational scenario with multiple antennas present

### Expected Mutual Coupling Effects

- **26m HF trailing wire**: Acts as parasitic element at VHF frequencies
- **Pattern distortion**: Especially in aft sectors due to long trailing wire
- **Near-field coupling**: HF dorsal whip affects VHF antenna performance
- **Minor ripples**: DF loops create small pattern variations
- **Electrically long elements**: All HF elements are long at VHF frequencies

### Analysis Benefits

- **Realistic operational scenario**: VHF active, HF antennas present but inactive
- **Actual mutual coupling**: Shows real-world multi-antenna installation effects
- **Pattern distortion**: Passive elements clearly visible in radiation pattern
- **Accurate predictions**: More realistic gain and impedance calculations

### Frequency Analysis Recommendations

- **Primary frequency**: 150 MHz (center of VHF aviation band)
- **Frequency sweep**: 118-174 MHz for full band analysis
- **Comparison studies**: Remove passive elements (W043-W046) for baseline comparison
- **Pattern analysis**: Focus on 150 MHz for realistic aircraft effects

### Expected Performance Characteristics

- **Omnidirectional horizontal pattern**: With aircraft structure effects
- **Pattern distortion**: From 26m trailing wire parasitic coupling
- **Vertical polarization**: With some cross-pol from passive elements
- **Ground plane effect**: From fuselage structure
- **Typical gain**: -2 to +3 dBi depending on frequency and direction
- **Pattern nulls/lobes**: From parasitic coupling effects

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
