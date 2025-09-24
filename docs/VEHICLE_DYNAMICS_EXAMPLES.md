# Vehicle Dynamics Integration Examples

## Overview

This document provides comprehensive examples of how vehicle dynamics (heading, speed, attitude, altitude) affect radio propagation calculations and antenna performance in FGCom-mumble.

## Key Concepts

### Vehicle Dynamics Impact on Antennas

1. **Yagi Antennas**: Vehicle attitude directly affects pointing direction
2. **Dipole Antennas**: Vehicle orientation affects polarization
3. **Vertical Antennas**: Least affected by vehicle attitude
4. **Loop Antennas**: Cannot be rotated, but vehicle attitude affects orientation
5. **Whip Antennas**: Similar to vertical antennas

### Propagation Model Integration

Vehicle dynamics are automatically integrated into propagation calculations to provide accurate signal quality predictions.

## Example 1: Aircraft with Yagi Antenna

### Scenario
- **Aircraft**: Cessna 172 (General Aviation)
- **Antenna**: 20m Yagi antenna
- **Frequency**: 14.230 MHz (20m SSB)
- **Target**: Ground station 100km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "N12345",
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude_ft_msl": 3500.0,
    "altitude_ft_agl": 3000.0
  },
  "attitude": {
    "pitch_deg": 2.5,      // Nose up
    "roll_deg": -1.2,      // Left wing down
    "yaw_deg": 045.0,      // Heading 045°
    "magnetic_heading_deg": 043.5
  },
  "velocity": {
    "speed_knots": 120.0,
    "course_deg": 045.0,
    "vertical_speed_fpm": 500.0
  },
  "antennas": [
    {
      "antenna_id": "yagi_20m",
      "antenna_type": "yagi",
      "azimuth_deg": 090.0,    // Pointing east
      "elevation_deg": 15.0,   // 15° elevation
      "is_rotatable": true,
      "rotation_speed_deg_per_sec": 10.0
    }
  ]
}
```

### Antenna Orientation Calculation

**Without Vehicle Dynamics Compensation:**
- Antenna pointing: 090° (East)
- Effective pointing: 090° (East)
- Signal quality: Good

**With Vehicle Dynamics Compensation:**
- Vehicle yaw: 045° (Northeast)
- Antenna pointing: 090° (East)
- Effective pointing: 135° (Southeast) - 090° + 045°
- Signal quality: Reduced due to pointing error

**Optimal Antenna Orientation:**
- Target direction: 225° (Southwest) - towards ground station
- Compensated pointing: 180° (South) - 225° - 045°
- Signal quality: Excellent

### Propagation Calculation

```json
{
  "lat1": 40.7128,
  "lon1": -74.0060,
  "lat2": 39.7128,
  "lon2": -75.0060,
  "alt1": 3000.0,
  "alt2": 100.0,
  "frequency_mhz": 14.230,
  "power_watts": 100.0,
  "antenna_type": "yagi",
  "include_vehicle_dynamics": true,
  "vehicle_id": "N12345",
  "antenna_id": "yagi_20m"
}
```

**Result:**
```json
{
  "signal_quality": 0.85,
  "signal_strength_db": -1.2,
  "antenna_gain_db": 6.8,
  "vehicle_attitude_effect_db": -2.1,
  "effective_antenna_azimuth_deg": 135.0,
  "effective_antenna_elevation_deg": 17.5,
  "propagation_mode": "skywave"
}
```

## Example 2: Sailboat with Backstay Antenna

### Scenario
- **Vessel**: 40-foot sailboat
- **Antenna**: Backstay antenna (inverted-L)
- **Frequency**: 7.150 MHz (40m SSB)
- **Target**: Another vessel 50km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "SV_SEAHAWK",
  "position": {
    "latitude": 41.8781,
    "longitude": -87.6298,
    "altitude_ft_msl": 0.0,
    "altitude_ft_agl": 0.0
  },
  "attitude": {
    "pitch_deg": 5.0,      // Bow up (sailing upwind)
    "roll_deg": 15.0,      // Port side down (heeling)
    "yaw_deg": 030.0,      // Heading 030°
    "magnetic_heading_deg": 028.5
  },
  "velocity": {
    "speed_knots": 8.0,
    "course_deg": 030.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "backstay_40m",
      "antenna_type": "inverted_l",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0,
      "is_rotatable": false,
      "is_auto_tracking": false
    }
  ]
}
```

### Antenna Orientation Calculation

**Backstay Antenna Effects:**
- Vehicle roll: 15° (Port side down)
- Antenna polarization: Affected by roll
- Effective gain: Reduced by 1.5dB due to roll
- Signal quality: Good (omnidirectional antenna)

### Propagation Calculation

```json
{
  "lat1": 41.8781,
  "lon1": -87.6298,
  "lat2": 41.4281,
  "lon2": -87.1298,
  "alt1": 0.0,
  "alt2": 0.0,
  "frequency_mhz": 7.150,
  "power_watts": 100.0,
  "antenna_type": "inverted_l",
  "include_vehicle_dynamics": true,
  "vehicle_id": "SV_SEAHAWK",
  "antenna_id": "backstay_40m"
}
```

**Result:**
```json
{
  "signal_quality": 0.78,
  "signal_strength_db": -3.2,
  "antenna_gain_db": 2.1,
  "vehicle_attitude_effect_db": -1.5,
  "propagation_mode": "groundwave",
  "saltwater_ground_effect": 2.3
}
```

## Example 3: Ground Station with Rotatable Yagi

### Scenario
- **Station**: Amateur radio station
- **Antenna**: 20m Yagi with rotator
- **Frequency**: 14.230 MHz (20m SSB)
- **Target**: Aircraft 200km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "W1ABC",
  "position": {
    "latitude": 42.3601,
    "longitude": -71.0589,
    "altitude_ft_msl": 100.0,
    "altitude_ft_agl": 100.0
  },
  "attitude": {
    "pitch_deg": 0.0,      // Ground station
    "roll_deg": 0.0,       // Ground station
    "yaw_deg": 0.0,        // Ground station
    "magnetic_heading_deg": 0.0
  },
  "velocity": {
    "speed_knots": 0.0,
    "course_deg": 0.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "yagi_20m_rotator",
      "antenna_type": "yagi",
      "azimuth_deg": 045.0,    // Pointing northeast
      "elevation_deg": 20.0,   // 20° elevation
      "is_rotatable": true,
      "is_auto_tracking": true,
      "rotation_speed_deg_per_sec": 5.0
    }
  ]
}
```

### Auto-tracking Calculation

**Target Aircraft Position:**
- Latitude: 43.3601
- Longitude: -70.0589
- Altitude: 5000ft

**Optimal Antenna Orientation:**
- Bearing to target: 045°
- Elevation angle: 15°
- Auto-tracking: Enabled

**Antenna Rotation:**
```json
{
  "target_azimuth_deg": 045.0,
  "target_elevation_deg": 15.0,
  "current_azimuth_deg": 045.0,
  "current_elevation_deg": 20.0,
  "rotation_time_sec": 1.0,
  "auto_tracking": true
}
```

### Propagation Calculation

```json
{
  "lat1": 42.3601,
  "lon1": -71.0589,
  "lat2": 43.3601,
  "lon2": -70.0589,
  "alt1": 100.0,
  "alt2": 5000.0,
  "frequency_mhz": 14.230,
  "power_watts": 100.0,
  "antenna_type": "yagi",
  "include_vehicle_dynamics": true,
  "vehicle_id": "W1ABC",
  "antenna_id": "yagi_20m_rotator"
}
```

**Result:**
```json
{
  "signal_quality": 0.92,
  "signal_strength_db": 1.8,
  "antenna_gain_db": 7.0,
  "vehicle_attitude_effect_db": 0.0,
  "effective_antenna_azimuth_deg": 045.0,
  "effective_antenna_elevation_deg": 15.0,
  "propagation_mode": "skywave",
  "auto_tracking_active": true
}
```

## Example 4: Military Vehicle with Multiple Antennas

### Scenario
- **Vehicle**: NATO Main Battle Tank (Leopard 1)
- **Antennas**: VHF-FM, UHF, HF systems
- **Frequency**: 30.000 MHz (VHF-FM tactical)
- **Target**: Command post 10km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "TANK_001",
  "position": {
    "latitude": 52.5200,
    "longitude": 13.4050,
    "altitude_ft_msl": 100.0,
    "altitude_ft_agl": 100.0
  },
  "attitude": {
    "pitch_deg": 0.0,      // Level ground
    "roll_deg": 0.0,       // Level ground
    "yaw_deg": 090.0,      // Facing east
    "magnetic_heading_deg": 088.5
  },
  "velocity": {
    "speed_knots": 25.0,
    "course_deg": 090.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "vhf_fm_whip",
      "antenna_type": "whip",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0,
      "is_rotatable": false,
      "is_auto_tracking": false
    },
    {
      "antenna_id": "hf_whip",
      "antenna_type": "whip",
      "azimuth_deg": 0.0,      // Omnidirectional
      "elevation_deg": 0.0,
      "is_rotatable": false,
      "is_auto_tracking": false
    }
  ]
}
```

### Antenna Orientation Calculation

**Whip Antenna Effects:**
- Vehicle attitude: Minimal effect on whip antennas
- Ground system: Vehicle hull provides good ground plane
- Effective gain: 0dB (omnidirectional)
- Signal quality: Good

### Propagation Calculation

```json
{
  "lat1": 52.5200,
  "lon1": 13.4050,
  "lat2": 52.5200,
  "lon2": 13.5050,
  "alt1": 100.0,
  "alt2": 100.0,
  "frequency_mhz": 30.000,
  "power_watts": 25.0,
  "antenna_type": "whip",
  "include_vehicle_dynamics": true,
  "vehicle_id": "TANK_001",
  "antenna_id": "vhf_fm_whip"
}
```

**Result:**
```json
{
  "signal_quality": 0.88,
  "signal_strength_db": -2.1,
  "antenna_gain_db": 0.0,
  "vehicle_attitude_effect_db": 0.0,
  "propagation_mode": "line_of_sight",
  "ground_system_effect": 1.5
}
```

## Example 5: Container Ship with HF Loop

### Scenario
- **Vessel**: Container ship
- **Antenna**: 80m square loop antenna
- **Frequency**: 3.500 MHz (80m SSB)
- **Target**: Shore station 500km away

### Vehicle Dynamics
```json
{
  "vehicle_id": "MSC_OCEAN",
  "position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude_ft_msl": 0.0,
    "altitude_ft_agl": 0.0
  },
  "attitude": {
    "pitch_deg": 1.0,      // Slight bow up
    "roll_deg": 3.0,       // Slight port roll
    "yaw_deg": 180.0,      // Heading south
    "magnetic_heading_deg": 178.5
  },
  "velocity": {
    "speed_knots": 20.0,
    "course_deg": 180.0,
    "vertical_speed_fpm": 0.0
  },
  "antennas": [
    {
      "antenna_id": "hf_loop_80m",
      "antenna_type": "loop",
      "azimuth_deg": 0.0,      // Fixed orientation
      "elevation_deg": 0.0,
      "is_rotatable": false,   // Loops cannot be rotated
      "is_auto_tracking": false
    }
  ]
}
```

### Antenna Orientation Calculation

**Loop Antenna Effects:**
- Vehicle roll: 3° (Port side down)
- Antenna orientation: Affected by roll
- Effective gain: Reduced by 0.6dB due to roll
- Signal quality: Good (directional but fixed)

### Propagation Calculation

```json
{
  "lat1": 40.6892,
  "lon1": -74.0445,
  "lat2": 35.6892,
  "lon2": -74.0445,
  "alt1": 0.0,
  "alt2": 0.0,
  "frequency_mhz": 3.500,
  "power_watts": 100.0,
  "antenna_type": "loop",
  "include_vehicle_dynamics": true,
  "vehicle_id": "MSC_OCEAN",
  "antenna_id": "hf_loop_80m"
}
```

**Result:**
```json
{
  "signal_quality": 0.82,
  "signal_strength_db": -4.1,
  "antenna_gain_db": 3.0,
  "vehicle_attitude_effect_db": -0.6,
  "propagation_mode": "groundwave",
  "saltwater_ground_effect": 3.2
}
```

## API Usage Examples

### Python Client for Vehicle Dynamics

```python
import requests
import json
import time

class VehicleDynamicsClient:
    def __init__(self, base_url="http://localhost:8080/api/v1"):
        self.base_url = base_url
    
    def register_vehicle(self, vehicle_id, vehicle_type, position):
        """Register a new vehicle"""
        data = {
            "vehicle_id": vehicle_id,
            "vehicle_type": vehicle_type,
            "initial_position": position
        }
        response = requests.post(f"{self.base_url}/vehicles/register", json=data)
        return response.json()
    
    def update_vehicle_dynamics(self, vehicle_id, attitude, velocity, position):
        """Update vehicle dynamics"""
        # Update attitude
        requests.put(f"{self.base_url}/vehicles/{vehicle_id}/attitude", json=attitude)
        
        # Update velocity
        requests.put(f"{self.base_url}/vehicles/{vehicle_id}/velocity", json=velocity)
        
        # Update position
        requests.put(f"{self.base_url}/vehicles/{vehicle_id}/position", json=position)
    
    def rotate_antenna(self, vehicle_id, antenna_id, azimuth, elevation):
        """Rotate antenna to target position"""
        data = {
            "target_azimuth_deg": azimuth,
            "target_elevation_deg": elevation,
            "immediate": False
        }
        response = requests.post(f"{self.base_url}/vehicles/{vehicle_id}/antennas/{antenna_id}/rotate", json=data)
        return response.json()
    
    def calculate_propagation(self, vehicle_id, antenna_id, target_lat, target_lon, frequency):
        """Calculate propagation with vehicle dynamics"""
        data = {
            "vehicle_id": vehicle_id,
            "antenna_id": antenna_id,
            "target_latitude": target_lat,
            "target_longitude": target_lon,
            "frequency_mhz": frequency,
            "include_vehicle_dynamics": True
        }
        response = requests.post(f"{self.base_url}/propagation", json=data)
        return response.json()

# Example usage
client = VehicleDynamicsClient()

# Register aircraft
aircraft_data = {
    "vehicle_id": "N12345",
    "vehicle_type": "aircraft",
    "initial_position": {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude_ft_msl": 3500.0
    }
}
client.register_vehicle(**aircraft_data)

# Simulate flight dynamics
for i in range(10):
    attitude = {
        "pitch_deg": 2.0 + i * 0.1,
        "roll_deg": -1.0 + i * 0.2,
        "yaw_deg": 045.0 + i * 2.0
    }
    
    velocity = {
        "speed_knots": 120.0,
        "course_deg": 045.0 + i * 2.0,
        "vertical_speed_fpm": 500.0
    }
    
    position = {
        "latitude": 40.7128 + i * 0.01,
        "longitude": -74.0060 + i * 0.01,
        "altitude_ft_msl": 3500.0 + i * 100.0
    }
    
    client.update_vehicle_dynamics("N12345", attitude, velocity, position)
    
    # Calculate propagation to ground station
    result = client.calculate_propagation("N12345", "yagi_20m", 40.7128, -74.0060, 14.230)
    print(f"Signal quality: {result['data']['signal_quality']:.2f}")
    
    time.sleep(1)
```

### JavaScript Client for Real-time Updates

```javascript
class VehicleDynamicsClient {
    constructor(baseUrl = 'http://localhost:8080/api/v1') {
        this.baseUrl = baseUrl;
        this.ws = null;
    }
    
    connectWebSocket() {
        this.ws = new WebSocket('ws://localhost:8080/ws/vehicles');
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
        };
    }
    
    handleWebSocketMessage(data) {
        switch(data.type) {
            case 'vehicle_position_update':
                this.updateVehiclePosition(data.vehicle_id, data.position);
                break;
            case 'vehicle_attitude_update':
                this.updateVehicleAttitude(data.vehicle_id, data.attitude);
                break;
            case 'antenna_rotation_update':
                this.updateAntennaRotation(data.vehicle_id, data.antenna_id, data.orientation);
                break;
        }
    }
    
    async updateVehicleDynamics(vehicleId, dynamics) {
        const response = await fetch(`${this.baseUrl}/vehicles/${vehicleId}/dynamics`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(dynamics)
        });
        
        return response.json();
    }
    
    async rotateAntenna(vehicleId, antennaId, azimuth, elevation) {
        const response = await fetch(`${this.baseUrl}/vehicles/${vehicleId}/antennas/${antennaId}/rotate`, {
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
        
        return response.json();
    }
}

// Example usage
const client = new VehicleDynamicsClient();
client.connectWebSocket();

// Simulate vehicle dynamics updates
setInterval(async () => {
    const dynamics = {
        attitude: {
            pitch_deg: Math.random() * 10 - 5,
            roll_deg: Math.random() * 20 - 10,
            yaw_deg: Math.random() * 360
        },
        velocity: {
            speed_knots: 100 + Math.random() * 50,
            course_deg: Math.random() * 360,
            vertical_speed_fpm: Math.random() * 1000 - 500
        }
    };
    
    await client.updateVehicleDynamics('N12345', dynamics);
}, 1000);
```

## Performance Considerations

### Real-time Updates
- Vehicle dynamics updates: 10Hz maximum
- Antenna rotation updates: 1Hz maximum
- WebSocket connections: Limited to prevent resource exhaustion

### Calculation Optimization
- Antenna orientation calculations: Cached for 1 second
- Propagation calculations: Include vehicle dynamics by default
- Auto-tracking: Throttled to prevent excessive CPU usage

### Memory Management
- Vehicle cleanup: Automatic removal of inactive vehicles
- Antenna state: Cached for performance
- WebSocket clients: Automatic cleanup of inactive connections

## Security Considerations

### Access Control
- Vehicle registration: Requires appropriate permissions
- Antenna rotation: Validated for safety limits
- Auto-tracking: Can be disabled for security-sensitive applications

### Rate Limiting
- Vehicle updates: 100 requests per minute per IP
- Antenna rotation: 10 requests per minute per vehicle
- WebSocket connections: 5 connections per IP

### Data Validation
- Vehicle dynamics: Validated for realistic ranges
- Antenna orientation: Safety limits enforced
- Position data: Geographic bounds checking

This comprehensive vehicle dynamics system ensures accurate radio propagation calculations by accounting for real-world vehicle orientation, speed, attitude, and antenna rotation effects.
