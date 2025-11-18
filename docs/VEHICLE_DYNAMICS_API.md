# Vehicle Dynamics API Documentation

## Overview

The FGCom-mumble Vehicle Dynamics API provides comprehensive vehicle position, attitude, and antenna orientation tracking capabilities. This system enables real-time monitoring of vehicle movements, antenna positioning, and advanced features like auto-tracking and rotation control.

## System Architecture

### Core Components

- **VehicleDynamicsManager**: Central management system for all vehicle dynamics
- **Position Tracking**: GPS and coordinate-based position monitoring
- **Attitude Tracking**: Pitch, roll, yaw, and heading monitoring
- **Antenna Management**: Multi-antenna orientation and rotation control
- **Auto-Tracking**: Automatic antenna pointing and rotation
- **Caching System**: Performance-optimized data storage and retrieval

## Data Structures

### Vehicle Position

```cpp
struct fgcom_vehicle_position {
    double latitude;                    // Latitude in decimal degrees
    double longitude;                   // Longitude in decimal degrees
    float altitude_ft_msl;             // Altitude in feet MSL
    float altitude_ft_agl;             // Altitude in feet AGL
    float ground_elevation_ft;          // Ground elevation in feet MSL
    std::string callsign;               // Vehicle callsign
    std::string vehicle_type;           // "aircraft", "boat", "ship", "vehicle", "ground_station"
    std::chrono::system_clock::time_point timestamp;
};
```

### Vehicle Attitude

```cpp
struct fgcom_vehicle_attitude {
    float pitch_deg;                    // Pitch angle in degrees (-90 to +90)
    float roll_deg;                     // Roll angle in degrees (-180 to +180)
    float yaw_deg;                      // Yaw angle in degrees (0 to 360, true heading)
    float magnetic_heading_deg;         // Magnetic heading in degrees (0 to 360)
    float magnetic_declination_deg;     // Magnetic declination at current location
    std::chrono::system_clock::time_point timestamp;
};
```

### Vehicle Velocity

```cpp
struct fgcom_vehicle_velocity {
    float speed_knots;                  // Speed in knots
    float speed_kmh;                    // Speed in km/h
    float speed_ms;                     // Speed in m/s
    float course_deg;                   // Course over ground in degrees (0-360)
    float vertical_speed_fpm;           // Vertical speed in feet per minute
    float vertical_speed_ms;            // Vertical speed in m/s
    std::chrono::system_clock::time_point timestamp;
};
```

### Antenna Orientation

```cpp
struct fgcom_antenna_orientation {
    std::string antenna_id;             // Unique antenna identifier
    std::string antenna_type;            // "yagi", "dipole", "vertical", "loop", "whip"
    float azimuth_deg;                  // Azimuth pointing direction (0-360)
    float elevation_deg;                // Elevation angle (-90 to +90)
    bool is_auto_tracking;              // Is auto-tracking enabled?
    float rotation_speed_deg_per_sec;  // Rotation speed for motorized antennas
    std::chrono::system_clock::time_point timestamp;
};
```

### Complete Vehicle Dynamics

```cpp
struct fgcom_vehicle_dynamics {
    fgcom_vehicle_position position;
    fgcom_vehicle_attitude attitude;
    fgcom_vehicle_velocity velocity;
    std::vector<fgcom_antenna_orientation> antennas;
    std::string vehicle_id;             // Unique vehicle identifier
    std::string status;                 // "active", "inactive", "maintenance"
    std::chrono::system_clock::time_point last_update;
};
```

## API Endpoints

### Vehicle Management

#### Register Vehicle
```http
POST /api/v1/vehicle-dynamics/register
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "vehicle_id": "player_001",
  "vehicle_type": "aircraft",
  "callsign": "N123AB",
  "initial_position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_ft_msl": 3000,
    "altitude_ft_agl": 2500,
    "ground_elevation_ft": 500
  },
  "initial_attitude": {
    "pitch_deg": 0.0,
    "roll_deg": 0.0,
    "yaw_deg": 90.0,
    "magnetic_heading_deg": 88.5
  },
  "antennas": [
    {
      "antenna_id": "main_antenna",
      "antenna_type": "yagi",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "is_auto_tracking": false
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Vehicle registered successfully",
  "vehicle_id": "player_001",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Unregister Vehicle
```http
DELETE /api/v1/vehicle-dynamics/{vehicle_id}
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "message": "Vehicle unregistered successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### List All Vehicles
```http
GET /api/v1/vehicle-dynamics/vehicles
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "vehicles": [
    {
      "vehicle_id": "player_001",
      "vehicle_type": "aircraft",
      "callsign": "N123AB",
      "status": "active",
      "last_update": "2024-01-15T10:30:00Z",
      "position": {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude_ft_msl": 3000
      },
      "antennas": [
        {
          "antenna_id": "main_antenna",
          "antenna_type": "yagi",
          "azimuth_deg": 0.0,
          "elevation_deg": 0.0
        }
      ]
    }
  ],
  "total_vehicles": 1
}
```

#### Get Vehicle Dynamics
```http
GET /api/v1/vehicle-dynamics/{vehicle_id}
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "vehicle_id": "player_001",
  "dynamics": {
    "position": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "altitude_ft_msl": 3000,
      "altitude_ft_agl": 2500,
      "ground_elevation_ft": 500,
      "callsign": "N123AB",
      "vehicle_type": "aircraft",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    "attitude": {
      "pitch_deg": 2.5,
      "roll_deg": -1.2,
      "yaw_deg": 90.0,
      "magnetic_heading_deg": 88.5,
      "magnetic_declination_deg": -12.3,
      "timestamp": "2024-01-15T10:30:00Z"
    },
    "velocity": {
      "speed_knots": 250.0,
      "speed_kmh": 463.0,
      "speed_ms": 128.6,
      "course_deg": 90.0,
      "vertical_speed_fpm": 500.0,
      "vertical_speed_ms": 2.54,
      "timestamp": "2024-01-15T10:30:00Z"
    },
    "antennas": [
      {
        "antenna_id": "main_antenna",
        "antenna_type": "yagi",
        "azimuth_deg": 0.0,
        "elevation_deg": 0.0,
        "is_auto_tracking": false,
        "rotation_speed_deg_per_sec": 0.0,
        "timestamp": "2024-01-15T10:30:00Z"
      }
    ],
    "status": "active",
    "last_update": "2024-01-15T10:30:00Z"
  }
}
```

### Position and Attitude Updates

#### Update Vehicle Position
```http
PUT /api/v1/vehicle-dynamics/{vehicle_id}/position
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "latitude": 40.7589,
  "longitude": -73.9851,
  "altitude_ft_msl": 3500,
  "altitude_ft_agl": 3000,
  "ground_elevation_ft": 500
}
```

**Response:**
```json
{
  "success": true,
  "message": "Position updated successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Update Vehicle Attitude
```http
PUT /api/v1/vehicle-dynamics/{vehicle_id}/attitude
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "pitch_deg": 3.2,
  "roll_deg": -0.8,
  "yaw_deg": 95.0,
  "magnetic_heading_deg": 93.5
}
```

**Response:**
```json
{
  "success": true,
  "message": "Attitude updated successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Update Vehicle Velocity
```http
PUT /api/v1/vehicle-dynamics/{vehicle_id}/velocity
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "speed_knots": 275.0,
  "speed_kmh": 509.3,
  "speed_ms": 141.5,
  "course_deg": 95.0,
  "vertical_speed_fpm": 750.0,
  "vertical_speed_ms": 3.81
}
```

**Response:**
```json
{
  "success": true,
  "message": "Velocity updated successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Update Complete Dynamics
```http
PUT /api/v1/vehicle-dynamics/{vehicle_id}/dynamics
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "position": {
    "latitude": 40.7589,
    "longitude": -73.9851,
    "altitude_ft_msl": 3500,
    "altitude_ft_agl": 3000,
    "ground_elevation_ft": 500
  },
  "attitude": {
    "pitch_deg": 3.2,
    "roll_deg": -0.8,
    "yaw_deg": 95.0,
    "magnetic_heading_deg": 93.5
  },
  "velocity": {
    "speed_knots": 275.0,
    "speed_kmh": 509.3,
    "speed_ms": 141.5,
    "course_deg": 95.0,
    "vertical_speed_fpm": 750.0,
    "vertical_speed_ms": 3.81
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Dynamics updated successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Antenna Management

#### Add Antenna to Vehicle
```http
POST /api/v1/vehicle-dynamics/{vehicle_id}/antennas
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "antenna_id": "backup_antenna",
  "antenna_type": "dipole",
  "azimuth_deg": 180.0,
  "elevation_deg": 0.0,
  "is_auto_tracking": false,
  "rotation_speed_deg_per_sec": 0.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "Antenna added successfully",
  "antenna_id": "backup_antenna",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Remove Antenna from Vehicle
```http
DELETE /api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "message": "Antenna removed successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Update Antenna Orientation
```http
PUT /api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "azimuth_deg": 45.0,
  "elevation_deg": 15.0,
  "is_auto_tracking": false,
  "rotation_speed_deg_per_sec": 0.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "Antenna orientation updated successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### List Vehicle Antennas
```http
GET /api/v1/vehicle-dynamics/{vehicle_id}/antennas
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "vehicle_id": "player_001",
  "antennas": [
    {
      "antenna_id": "main_antenna",
      "antenna_type": "yagi",
      "azimuth_deg": 0.0,
      "elevation_deg": 0.0,
      "is_auto_tracking": false,
      "rotation_speed_deg_per_sec": 0.0,
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "antenna_id": "backup_antenna",
      "antenna_type": "dipole",
      "azimuth_deg": 180.0,
      "elevation_deg": 0.0,
      "is_auto_tracking": false,
      "rotation_speed_deg_per_sec": 0.0,
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "total_antennas": 2
}
```

### Antenna Rotation and Auto-Tracking

#### Rotate Antenna
```http
POST /api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/rotate
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "target_azimuth": 90.0,
  "target_elevation": 30.0,
  "immediate": false,
  "rotation_speed_deg_per_sec": 5.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "Antenna rotation started",
  "rotation_id": "rot_001",
  "estimated_completion_time": "2024-01-15T10:30:18Z",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Get Rotation Status
```http
GET /api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/rotation-status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "antenna_id": "main_antenna",
  "is_rotating": true,
  "current_azimuth": 45.0,
  "current_elevation": 15.0,
  "target_azimuth": 90.0,
  "target_elevation": 30.0,
  "rotation_progress_percent": 50.0,
  "estimated_completion_time": "2024-01-15T10:30:18Z",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Enable Auto-Tracking
```http
POST /api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/auto-tracking
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "target_vehicle_id": "player_002",
  "tracking_mode": "continuous",
  "update_interval_ms": 100,
  "rotation_speed_deg_per_sec": 10.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "Auto-tracking enabled",
  "tracking_id": "track_001",
  "target_vehicle_id": "player_002",
  "tracking_mode": "continuous",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Disable Auto-Tracking
```http
DELETE /api/v1/vehicle-dynamics/{vehicle_id}/antennas/{antenna_id}/auto-tracking
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "message": "Auto-tracking disabled",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## C++ API Usage

### Basic Vehicle Management

```cpp
#include "vehicle_dynamics.h"

// Get vehicle dynamics manager instance
auto& dynamics_manager = FGCom_VehicleDynamicsManager::getInstance();

// Register a new vehicle
fgcom_vehicle_dynamics vehicle;
vehicle.vehicle_id = "player_001";
vehicle.position.latitude = 40.7128;
vehicle.position.longitude = -74.0060;
vehicle.position.altitude_ft_msl = 3000;
vehicle.position.callsign = "N123AB";
vehicle.position.vehicle_type = "aircraft";

bool success = dynamics_manager.registerVehicle(vehicle);
if (success) {
    std::cout << "Vehicle registered successfully" << std::endl;
}
```

### Position Updates

```cpp
// Update vehicle position
fgcom_vehicle_position new_position;
new_position.latitude = 40.7589;
new_position.longitude = -73.9851;
new_position.altitude_ft_msl = 3500;
new_position.altitude_ft_agl = 3000;
new_position.ground_elevation_ft = 500;

success = dynamics_manager.updateVehiclePosition("player_001", new_position);
if (success) {
    std::cout << "Position updated successfully" << std::endl;
}
```

### Attitude Updates

```cpp
// Update vehicle attitude
fgcom_vehicle_attitude new_attitude;
new_attitude.pitch_deg = 3.2;
new_attitude.roll_deg = -0.8;
new_attitude.yaw_deg = 95.0;
new_attitude.magnetic_heading_deg = 93.5;

success = dynamics_manager.updateVehicleAttitude("player_001", new_attitude);
if (success) {
    std::cout << "Attitude updated successfully" << std::endl;
}
```

### Antenna Management

```cpp
// Add antenna to vehicle
fgcom_antenna_orientation antenna;
antenna.antenna_id = "main_antenna";
antenna.antenna_type = "yagi";
antenna.azimuth_deg = 0.0;
antenna.elevation_deg = 0.0;
antenna.is_auto_tracking = false;

success = dynamics_manager.addAntenna("player_001", antenna);
if (success) {
    std::cout << "Antenna added successfully" << std::endl;
}
```

### Antenna Rotation

```cpp
// Rotate antenna
float target_azimuth = 90.0;
float target_elevation = 30.0;
bool immediate = false;

success = dynamics_manager.rotateAntenna("player_001", "main_antenna", 
                                        target_azimuth, target_elevation, immediate);
if (success) {
    std::cout << "Antenna rotation started" << std::endl;
}
```

### Auto-Tracking

```cpp
// Enable auto-tracking
success = dynamics_manager.enableAutoTracking("player_001", "main_antenna", 
                                            "player_002", "continuous");
if (success) {
    std::cout << "Auto-tracking enabled" << std::endl;
}

// Disable auto-tracking
success = dynamics_manager.disableAutoTracking("player_001", "main_antenna");
if (success) {
    std::cout << "Auto-tracking disabled" << std::endl;
}
```

## Advanced Features

### Magnetic Declination Calculation

```cpp
float calculateMagneticDeclination(double latitude, double longitude) {
    // Simplified magnetic declination calculation
    // In practice, use a proper magnetic model like WMM or IGRF
    
    float declination = 0.0;
    
    // Basic approximation (not accurate for production use)
    declination = -12.3 + (latitude - 40.0) * 0.1 + (longitude + 74.0) * 0.05;
    
    return declination;
}
```

### Coordinate Transformations

```cpp
void transformAttitudeToAntennaOrientation(const fgcom_vehicle_attitude& attitude, 
                                          fgcom_antenna_orientation& antenna) {
    // Transform vehicle attitude to antenna orientation
    // This is a simplified transformation
    
    // Account for vehicle pitch and roll
    float adjusted_azimuth = antenna.azimuth_deg + attitude.yaw_deg;
    float adjusted_elevation = antenna.elevation_deg + attitude.pitch_deg;
    
    // Normalize angles
    antenna.azimuth_deg = normalizeAngle(adjusted_azimuth);
    antenna.elevation_deg = std::max(-90.0f, std::min(90.0f, adjusted_elevation));
}
```

### Auto-Tracking Implementation

```cpp
void FGCom_VehicleDynamicsManager::updateAutoTracking() {
    std::lock_guard<std::mutex> lock(vehicles_mutex);
    
    for (auto& vehicle_pair : vehicles) {
        auto& vehicle = vehicle_pair.second;
        
        for (auto& antenna : vehicle.antennas) {
            if (antenna.is_auto_tracking) {
                // Find target vehicle
                auto target_it = vehicles.find(antenna.auto_tracking_target);
                if (target_it != vehicles.end()) {
                    // Calculate bearing to target
                    float bearing = calculateBearing(vehicle.position, target_it->second.position);
                    
                    // Update antenna orientation
                    antenna.azimuth_deg = bearing;
                    antenna.elevation_deg = calculateElevation(vehicle.position, target_it->second.position);
                }
            }
        }
    }
}
```

## Performance Optimization

### Caching System

```cpp
class VehicleDynamicsCache {
private:
    std::map<std::string, fgcom_vehicle_dynamics> cache;
    std::mutex cache_mutex;
    std::time_t cache_ttl;
    
public:
    bool getCachedVehicle(const std::string& vehicle_id, fgcom_vehicle_dynamics& vehicle) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        
        auto it = cache.find(vehicle_id);
        if (it != cache.end()) {
            // Check if data is still valid
            auto now = std::chrono::system_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_update).count();
            
            if (age < cache_ttl) {
                vehicle = it->second;
                return true;
            } else {
                // Remove expired data
                cache.erase(it);
            }
        }
        
        return false;
    }
    
    void setCachedVehicle(const std::string& vehicle_id, const fgcom_vehicle_dynamics& vehicle) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache[vehicle_id] = vehicle;
    }
};
```

### Thread Safety

```cpp
class FGCom_VehicleDynamicsManager {
private:
    std::map<std::string, fgcom_vehicle_dynamics> vehicles;
    mutable std::mutex vehicles_mutex;
    
    // Thread-safe operations
    bool updateVehiclePosition(const std::string& vehicle_id, const fgcom_vehicle_position& position) {
        std::lock_guard<std::mutex> lock(vehicles_mutex);
        
        auto it = vehicles.find(vehicle_id);
        if (it == vehicles.end()) {
            return false;
        }
        
        it->second.position = position;
        it->second.last_update = std::chrono::system_clock::now();
        
        return true;
    }
};
```

## Error Handling

### Common Error Responses

```json
{
  "success": false,
  "error": {
    "code": "VEHICLE_NOT_FOUND",
    "message": "Vehicle with ID 'player_001' not found",
    "details": {
      "vehicle_id": "player_001",
      "available_vehicles": ["player_002", "player_003"]
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

- **VEHICLE_NOT_FOUND**: Vehicle ID does not exist
- **ANTENNA_NOT_FOUND**: Antenna ID does not exist on vehicle
- **INVALID_COORDINATES**: Latitude/longitude out of valid range
- **INVALID_ATTITUDE**: Attitude angles out of valid range
- **AUTO_TRACKING_FAILED**: Auto-tracking operation failed
- **ROTATION_FAILED**: Antenna rotation operation failed

## WebSocket Real-time Updates

### Vehicle Position Updates

```json
{
  "type": "vehicle_position_update",
  "vehicle_id": "player_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "latitude": 40.7589,
    "longitude": -73.9851,
    "altitude_ft_msl": 3500,
    "altitude_ft_agl": 3000
  }
}
```

### Vehicle Attitude Updates

```json
{
  "type": "vehicle_attitude_update",
  "vehicle_id": "player_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "pitch_deg": 3.2,
    "roll_deg": -0.8,
    "yaw_deg": 95.0,
    "magnetic_heading_deg": 93.5
  }
}
```

### Antenna Orientation Updates

```json
{
  "type": "antenna_orientation_update",
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "azimuth_deg": 90.0,
    "elevation_deg": 30.0,
    "is_rotating": false,
    "is_auto_tracking": true
  }
}
```

## Examples

### Python Client Example

```python
import requests
import json
import time

# Authentication
auth_response = requests.post('http://localhost:8080/auth/login', json={
    'username': 'pilot123',
    'password': 'secure_password',
    'client_type': 'flight_simulator'
})

token = auth_response.json()['token']
headers = {'Authorization': f'Bearer {token}'}

# Register vehicle
vehicle_data = {
    'vehicle_id': 'player_001',
    'vehicle_type': 'aircraft',
    'callsign': 'N123AB',
    'initial_position': {
        'latitude': 40.7128,
        'longitude': -74.0060,
        'altitude_ft_msl': 3000,
        'altitude_ft_agl': 2500,
        'ground_elevation_ft': 500
    },
    'initial_attitude': {
        'pitch_deg': 0.0,
        'roll_deg': 0.0,
        'yaw_deg': 90.0,
        'magnetic_heading_deg': 88.5
    }
}

response = requests.post('http://localhost:8080/api/v1/vehicle-dynamics/register',
                       headers=headers, json=vehicle_data)
print(json.dumps(response.json(), indent=2))

# Update position
position_update = {
    'latitude': 40.7589,
    'longitude': -73.9851,
    'altitude_ft_msl': 3500,
    'altitude_ft_agl': 3000,
    'ground_elevation_ft': 500
}

response = requests.put('http://localhost:8080/api/v1/vehicle-dynamics/player_001/position',
                       headers=headers, json=position_update)
print(json.dumps(response.json(), indent=2))
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to Vehicle Dynamics WebSocket');
    
    // Subscribe to vehicle updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'vehicle_dynamics',
        vehicle_id: 'player_001'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'vehicle_position_update':
            console.log('Position update:', data.data);
            break;
        case 'vehicle_attitude_update':
            console.log('Attitude update:', data.data);
            break;
        case 'antenna_orientation_update':
            console.log('Antenna update:', data.data);
            break;
    }
};
```

This comprehensive Vehicle Dynamics API provides complete vehicle tracking, antenna management, and real-time monitoring capabilities for FGCom-mumble.
