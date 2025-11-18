# Power Management System Documentation

## Overview

The FGCom-mumble Power Management System provides advanced transmit power control, efficiency optimization, and power monitoring capabilities. This system ensures optimal power usage while maintaining communication quality and system reliability.

## System Architecture

### Core Components

- **PowerController**: Central power management system
- **TransmitPowerControl**: Dynamic power adjustment
- **EfficiencyOptimizer**: Power efficiency algorithms
- **ThermalProtection**: Temperature-based power limiting
- **BatteryManagement**: Battery monitoring and optimization
- **PowerMonitoring**: Real-time power usage tracking

## Power Control Features

### Transmit Power Control

#### Dynamic Power Adjustment
- **Automatic Power Scaling**: Adjusts power based on signal requirements
- **Distance-Based Power**: Optimizes power for communication distance
- **Signal Quality Optimization**: Balances power with signal quality
- **Interference Mitigation**: Reduces power to minimize interference

#### Power Levels
- **Minimum Power**: 1W (30 dBm)
- **Maximum Power**: 1000W (60 dBm)
- **Step Size**: 1dB increments
- **Resolution**: 0.1dB precision

### Efficiency Optimization

#### Power Efficiency Algorithms
- **Adaptive Power Control**: Adjusts power based on channel conditions
- **Load-Based Scaling**: Scales power with system load
- **Frequency-Dependent Optimization**: Optimizes power for different frequencies
- **Antenna Gain Compensation**: Compensates for antenna gain variations

#### Efficiency Metrics
- **Power Efficiency**: Watts per communication channel
- **Energy per Bit**: Energy consumption per data bit
- **Thermal Efficiency**: Power dissipation management
- **Battery Life**: Estimated battery life based on current usage

## Configuration

### Power Management Configuration

```ini
# configs/power_management.conf
[power_management]
# Enable/disable power management
enabled = true

# Transmit power settings
max_transmit_power_watts = 1000.0
min_transmit_power_watts = 1.0
default_transmit_power_watts = 25.0
power_step_db = 1.0
power_resolution_db = 0.1

# Efficiency optimization
enable_adaptive_power = true
enable_load_based_scaling = true
enable_frequency_optimization = true
enable_antenna_compensation = true

# Thermal protection
enable_thermal_protection = true
max_temperature_celsius = 85.0
thermal_shutdown_temperature_celsius = 90.0
thermal_throttle_temperature_celsius = 80.0
thermal_recovery_temperature_celsius = 75.0

# Battery management
enable_battery_management = true
battery_capacity_ah = 100.0
battery_voltage_volts = 12.0
battery_efficiency_percent = 85.0
low_battery_threshold_percent = 20.0
critical_battery_threshold_percent = 10.0

# Power monitoring
enable_power_monitoring = true
monitoring_interval_seconds = 1
enable_power_logging = true
power_log_file = /var/log/fgcom-power.log
```

## Data Structures

### Power Status Structure

```cpp
struct fgcom_power_status {
    // Current power settings
    float current_transmit_power_watts;
    float current_transmit_power_dbw;
    float current_transmit_power_dbm;
    
    // Power efficiency metrics
    float power_efficiency_percent;
    float energy_per_bit_joules;
    float thermal_efficiency_percent;
    
    // Thermal status
    float current_temperature_celsius;
    float max_temperature_celsius;
    bool thermal_throttling_active;
    bool thermal_shutdown_active;
    
    // Battery status
    float battery_voltage_volts;
    float battery_current_amps;
    float battery_capacity_percent;
    float estimated_battery_life_hours;
    
    // Power consumption
    float total_power_consumption_watts;
    float transmit_power_consumption_watts;
    float system_power_consumption_watts;
    float efficiency_percent;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
    
    // Status flags
    bool power_management_enabled;
    bool efficiency_optimization_enabled;
    bool thermal_protection_enabled;
    bool battery_management_enabled;
};
```

### Power Control Request

```cpp
struct fgcom_power_control_request {
    std::string vehicle_id;
    std::string antenna_id;
    float target_power_watts;
    float target_power_dbw;
    bool immediate_adjustment;
    bool efficiency_optimization;
    std::string optimization_mode; // "distance", "quality", "efficiency", "manual"
    std::map<std::string, std::string> parameters;
};
```

## API Endpoints

### Power Status

#### Get Power Status
```http
GET /api/v1/power-management/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "power_status": {
    "current_transmit_power_watts": 25.0,
    "current_transmit_power_dbw": 14.0,
    "current_transmit_power_dbm": 44.0,
    "power_efficiency_percent": 85.2,
    "energy_per_bit_joules": 0.0012,
    "thermal_efficiency_percent": 78.5,
    "current_temperature_celsius": 45.2,
    "max_temperature_celsius": 85.0,
    "thermal_throttling_active": false,
    "thermal_shutdown_active": false,
    "battery_voltage_volts": 12.1,
    "battery_current_amps": 2.5,
    "battery_capacity_percent": 78.5,
    "estimated_battery_life_hours": 12.3,
    "total_power_consumption_watts": 45.2,
    "transmit_power_consumption_watts": 25.0,
    "system_power_consumption_watts": 20.2,
    "efficiency_percent": 85.2,
    "power_management_enabled": true,
    "efficiency_optimization_enabled": true,
    "thermal_protection_enabled": true,
    "battery_management_enabled": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Power Control

#### Set Transmit Power
```http
POST /api/v1/power-management/set-power
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "target_power_watts": 50.0,
  "immediate_adjustment": true,
  "efficiency_optimization": true,
  "optimization_mode": "quality"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Power adjusted successfully",
  "new_power_watts": 50.0,
  "new_power_dbw": 17.0,
  "new_power_dbm": 47.0,
  "efficiency_impact": "improved",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Enable Efficiency Optimization
```http
POST /api/v1/power-management/efficiency-optimization
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "optimization_mode": "adaptive",
  "parameters": {
    "target_signal_quality": 0.85,
    "max_power_watts": 100.0,
    "min_power_watts": 1.0,
    "adjustment_interval_seconds": 5.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Efficiency optimization enabled",
  "optimization_id": "opt_001",
  "estimated_efficiency_improvement_percent": 15.2,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Thermal Protection

#### Get Thermal Status
```http
GET /api/v1/power-management/thermal-status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "thermal_status": {
    "current_temperature_celsius": 45.2,
    "max_temperature_celsius": 85.0,
    "thermal_throttling_active": false,
    "thermal_shutdown_active": false,
    "throttle_threshold_celsius": 80.0,
    "shutdown_threshold_celsius": 90.0,
    "recovery_threshold_celsius": 75.0,
    "thermal_efficiency_percent": 78.5,
    "cooling_system_active": false,
    "estimated_time_to_throttle_minutes": 45.2,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Set Thermal Protection
```http
POST /api/v1/power-management/thermal-protection
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "enable_thermal_protection": true,
  "throttle_threshold_celsius": 80.0,
  "shutdown_threshold_celsius": 90.0,
  "recovery_threshold_celsius": 75.0,
  "enable_cooling_system": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "Thermal protection configured",
  "thermal_protection_enabled": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Battery Management

#### Get Battery Status
```http
GET /api/v1/power-management/battery-status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "battery_status": {
    "battery_voltage_volts": 12.1,
    "battery_current_amps": 2.5,
    "battery_capacity_percent": 78.5,
    "battery_capacity_ah": 100.0,
    "battery_efficiency_percent": 85.0,
    "estimated_battery_life_hours": 12.3,
    "low_battery_threshold_percent": 20.0,
    "critical_battery_threshold_percent": 10.0,
    "battery_health_percent": 92.5,
    "charging_status": "not_charging",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Set Battery Management
```http
POST /api/v1/power-management/battery-management
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "enable_battery_management": true,
  "low_battery_threshold_percent": 20.0,
  "critical_battery_threshold_percent": 10.0,
  "enable_power_saving_mode": true,
  "power_saving_aggressiveness": "moderate"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Battery management configured",
  "battery_management_enabled": true,
  "estimated_battery_life_improvement_percent": 25.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## C++ API Usage

### Basic Power Control

```cpp
#include "power_management.h"

// Get power management instance
auto& power_manager = FGCom_PowerManager::getInstance();

// Get current power status
fgcom_power_status status = power_manager.getPowerStatus();
std::cout << "Current power: " << status.current_transmit_power_watts << "W" << std::endl;
std::cout << "Efficiency: " << status.power_efficiency_percent << "%" << std::endl;
```

### Set Transmit Power

```cpp
// Set transmit power
float target_power_watts = 50.0;
bool success = power_manager.setTransmitPower("player_001", "main_antenna", target_power_watts);

if (success) {
    std::cout << "Power set to " << target_power_watts << "W" << std::endl;
} else {
    std::cout << "Failed to set power" << std::endl;
}
```

### Efficiency Optimization

```cpp
// Enable efficiency optimization
fgcom_power_control_request request;
request.vehicle_id = "player_001";
request.antenna_id = "main_antenna";
request.efficiency_optimization = true;
request.optimization_mode = "adaptive";

success = power_manager.enableEfficiencyOptimization(request);
if (success) {
    std::cout << "Efficiency optimization enabled" << std::endl;
}
```

### Thermal Protection

```cpp
// Check thermal status
auto thermal_status = power_manager.getThermalStatus();
std::cout << "Temperature: " << thermal_status.current_temperature_celsius << "°C" << std::endl;
std::cout << "Thermal throttling: " << (thermal_status.thermal_throttling_active ? "Active" : "Inactive") << std::endl;

// Set thermal protection
power_manager.setThermalProtection(true, 80.0, 90.0, 75.0);
```

### Battery Management

```cpp
// Get battery status
auto battery_status = power_manager.getBatteryStatus();
std::cout << "Battery capacity: " << battery_status.battery_capacity_percent << "%" << std::endl;
std::cout << "Estimated life: " << battery_status.estimated_battery_life_hours << " hours" << std::endl;

// Enable battery management
power_manager.enableBatteryManagement(true, 20.0, 10.0);
```

## Advanced Features

### Adaptive Power Control

```cpp
class AdaptivePowerController {
private:
    float target_signal_quality;
    float max_power_watts;
    float min_power_watts;
    float adjustment_step_db;
    
public:
    float calculateOptimalPower(float current_signal_quality, float distance_km, float frequency_mhz) {
        float optimal_power = min_power_watts;
        
        // Distance-based power calculation
        float distance_factor = 20.0 * log10(distance_km);
        
        // Frequency-based power calculation
        float frequency_factor = 20.0 * log10(frequency_mhz);
        
        // Signal quality adjustment
        float quality_factor = (target_signal_quality - current_signal_quality) * 10.0;
        
        optimal_power = min_power_watts + distance_factor + frequency_factor + quality_factor;
        
        // Clamp to valid range
        return std::max(min_power_watts, std::min(max_power_watts, optimal_power));
    }
};
```

### Thermal Management

```cpp
class ThermalManager {
private:
    float current_temperature;
    float throttle_threshold;
    float shutdown_threshold;
    bool thermal_throttling_active;
    
public:
    float calculateThermalThrottle(float temperature) {
        if (temperature >= shutdown_threshold) {
            return 0.0f; // Complete shutdown
        } else if (temperature >= throttle_threshold) {
            // Linear throttling from 100% to 0% between throttle and shutdown thresholds
            float throttle_factor = 1.0f - ((temperature - throttle_threshold) / 
                                           (shutdown_threshold - throttle_threshold));
            return std::max(0.0f, throttle_factor);
        } else {
            return 1.0f; // No throttling
        }
    }
};
```

### Battery Optimization

```cpp
class BatteryOptimizer {
private:
    float battery_capacity_percent;
    float low_battery_threshold;
    float critical_battery_threshold;
    
public:
    float calculatePowerLimit(float battery_percent) {
        if (battery_percent <= critical_battery_threshold) {
            return 0.1f; // 10% power limit
        } else if (battery_percent <= low_battery_threshold) {
            return 0.5f; // 50% power limit
        } else {
            return 1.0f; // No limit
        }
    }
    
    float estimateBatteryLife(float current_power_watts, float battery_capacity_ah, float battery_voltage_volts) {
        float current_amps = current_power_watts / battery_voltage_volts;
        return (battery_capacity_ah * battery_capacity_percent / 100.0f) / current_amps;
    }
};
```

## Performance Monitoring

### Power Usage Tracking

```cpp
class PowerUsageTracker {
private:
    std::map<std::string, float> power_usage;
    std::chrono::system_clock::time_point last_update;
    
public:
    void recordPowerUsage(const std::string& component, float power_watts) {
        power_usage[component] = power_watts;
        last_update = std::chrono::system_clock::now();
    }
    
    float getTotalPowerUsage() const {
        float total = 0.0f;
        for (const auto& usage : power_usage) {
            total += usage.second;
        }
        return total;
    }
    
    std::map<std::string, float> getPowerBreakdown() const {
        return power_usage;
    }
};
```

### Efficiency Metrics

```cpp
class EfficiencyMetrics {
private:
    float total_energy_consumed;
    float total_bits_transmitted;
    std::chrono::system_clock::time_point start_time;
    
public:
    float calculateEnergyPerBit() const {
        if (total_bits_transmitted > 0) {
            return total_energy_consumed / total_bits_transmitted;
        }
        return 0.0f;
    }
    
    float calculatePowerEfficiency() const {
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
        
        if (duration.count() > 0) {
            float average_power = total_energy_consumed / duration.count();
            return (total_bits_transmitted / duration.count()) / average_power;
        }
        return 0.0f;
    }
};
```

## Error Handling

### Common Error Responses

```json
{
  "success": false,
  "error": {
    "code": "POWER_LIMIT_EXCEEDED",
    "message": "Requested power exceeds maximum allowed power",
    "details": {
      "requested_power_watts": 1500.0,
      "max_allowed_power_watts": 1000.0,
      "thermal_throttling_active": false
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

- **POWER_LIMIT_EXCEEDED**: Requested power exceeds limits
- **THERMAL_THROTTLING**: Power reduced due to thermal protection
- **BATTERY_LOW**: Power reduced due to low battery
- **INVALID_POWER_LEVEL**: Power level out of valid range
- **EFFICIENCY_OPTIMIZATION_FAILED**: Efficiency optimization failed
- **THERMAL_PROTECTION_ACTIVE**: Thermal protection is active

## WebSocket Real-time Updates

### Power Status Updates

```json
{
  "type": "power_status_update",
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "current_power_watts": 25.0,
    "efficiency_percent": 85.2,
    "temperature_celsius": 45.2,
    "battery_capacity_percent": 78.5
  }
}
```

### Thermal Status Updates

```json
{
  "type": "thermal_status_update",
  "vehicle_id": "player_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "temperature_celsius": 45.2,
    "thermal_throttling_active": false,
    "thermal_shutdown_active": false
  }
}
```

### Battery Status Updates

```json
{
  "type": "battery_status_update",
  "vehicle_id": "player_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "battery_capacity_percent": 78.5,
    "battery_voltage_volts": 12.1,
    "estimated_life_hours": 12.3
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

# Get power status
status_response = requests.get('http://localhost:8080/api/v1/power-management/status', headers=headers)
power_status = status_response.json()['power_status']
print(f"Current power: {power_status['current_transmit_power_watts']}W")
print(f"Efficiency: {power_status['power_efficiency_percent']}%")

# Set transmit power
power_request = {
    'vehicle_id': 'player_001',
    'antenna_id': 'main_antenna',
    'target_power_watts': 50.0,
    'immediate_adjustment': True,
    'efficiency_optimization': True,
    'optimization_mode': 'quality'
}

response = requests.post('http://localhost:8080/api/v1/power-management/set-power',
                        headers=headers, json=power_request)
print(json.dumps(response.json(), indent=2))
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to Power Management WebSocket');
    
    // Subscribe to power updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'power_management',
        vehicle_id: 'player_001'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'power_status_update':
            console.log('Power update:', data.data);
            break;
        case 'thermal_status_update':
            console.log('Thermal update:', data.data);
            break;
        case 'battery_status_update':
            console.log('Battery update:', data.data);
            break;
    }
};
```

This comprehensive Power Management System provides advanced power control, efficiency optimization, thermal protection, and battery management capabilities for FGCom-mumble.
