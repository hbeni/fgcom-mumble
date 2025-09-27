# FGCom-mumble API Documentation

## Overview

This document provides comprehensive API documentation for all FGCom-mumble features, including RESTful endpoints, WebSocket messages, C++ APIs, and integration examples.

## RESTful API Endpoints

### Base URL
```
http://localhost:8080/api
```

### Authentication
All API endpoints require authentication via API key:
```http
Authorization: Bearer <api_key>
```

### Common Response Format
```json
{
    "success": true,
    "data": { ... },
    "error": null,
    "timestamp": "2024-01-01T12:00:00Z",
    "request_id": "uuid-string"
}
```

## Propagation Data API

### Get Propagation Data
```http
GET /api/propagation
```

**Query Parameters:**
- `lat1` (float): Source latitude
- `lon1` (float): Source longitude
- `lat2` (float): Destination latitude
- `lon2` (float): Destination longitude
- `frequency` (float): Frequency in MHz
- `power` (float): Transmit power in watts
- `antenna_gain` (float): Antenna gain in dBi

**Response:**
```json
{
    "success": true,
    "data": {
        "distance_km": 150.5,
        "signal_strength": 0.85,
        "muf": 25.3,
        "luf": 3.2,
        "path_loss_db": 120.5,
        "skip_distance_km": 200.0,
        "propagation_mode": "skywave",
        "solar_conditions": {
            "sfi": 150,
            "k_index": 2,
            "a_index": 15
        }
    }
}
```

### Get Propagation Map
```http
GET /api/propagation/map
```

**Query Parameters:**
- `center_lat` (float): Center latitude
- `center_lon` (float): Center longitude
- `radius_km` (float): Map radius in km
- `frequency` (float): Frequency in MHz
- `resolution` (int): Map resolution (default: 50)

**Response:**
```json
{
    "success": true,
    "data": {
        "center": {"lat": 40.7128, "lon": -74.0060},
        "radius_km": 100,
        "resolution": 50,
        "signal_map": [
            {"lat": 40.7128, "lon": -74.0060, "signal": 1.0},
            {"lat": 40.7228, "lon": -74.0160, "signal": 0.95}
        ]
    }
}
```

## Solar Data API

### Get Current Solar Conditions
```http
GET /api/solar
```

**Response:**
```json
{
    "success": true,
    "data": {
        "sfi": 150,
        "k_index": 2,
        "a_index": 15,
        "last_updated": "2024-01-01T12:00:00Z",
        "source": "NOAA_SWPC",
        "valid": true
    }
}
```

### Get Solar History
```http
GET /api/solar/history
```

**Query Parameters:**
- `hours` (int): Number of hours of history (default: 24)
- `resolution` (string): Data resolution ("hourly", "daily")

**Response:**
```json
{
    "success": true,
    "data": {
        "period_hours": 24,
        "resolution": "hourly",
        "data_points": [
            {
                "timestamp": "2024-01-01T11:00:00Z",
                "sfi": 148,
                "k_index": 1,
                "a_index": 12
            }
        ]
    }
}
```

## Band Status API

### Get Band Status
```http
GET /api/bands
```

**Query Parameters:**
- `band` (string): Specific band name (optional)
- `region` (string): ITU region (optional)

**Response:**
```json
{
    "success": true,
    "data": {
        "bands": [
            {
                "name": "20m",
                "frequency_min": 14.0,
                "frequency_max": 14.35,
                "mode": "SSB",
                "status": "open",
                "muf": 25.3,
                "luf": 3.2
            }
        ]
    }
}
```

### Get Band Plan
```http
GET /api/bands/plan
```

**Query Parameters:**
- `region` (string): ITU region
- `license_class` (string): License class

**Response:**
```json
{
    "success": true,
    "data": {
        "region": "ITU1",
        "license_class": "General",
        "bands": [
            {
                "name": "20m",
                "frequency_min": 14.0,
                "frequency_max": 14.35,
                "modes": ["CW", "SSB", "Digital"],
                "power_limit": 1500,
                "restrictions": []
            }
        ]
    }
}
```

## Antenna Patterns API

### Get Antenna Pattern
```http
GET /api/antenna-patterns/{vehicle_type}/{vehicle_model}
```

**Path Parameters:**
- `vehicle_type`: Type of vehicle (aircraft, boat, ship, vehicle, military)
- `vehicle_model`: Specific vehicle model

**Query Parameters:**
- `frequency` (float): Frequency in MHz
- `altitude` (float): Altitude in meters (for aircraft)
- `azimuth` (float): Azimuth angle in degrees
- `elevation` (float): Elevation angle in degrees
- `pitch` (float): Pitch angle in degrees (for 3D attitude patterns)
- `roll` (float): Roll angle in degrees (for 3D attitude patterns)
- `yaw` (float): Yaw angle in degrees (for real-time rotation)

**Response:**
```json
{
    "success": true,
    "data": {
        "vehicle_type": "aircraft",
        "vehicle_model": "b737",
        "frequency_mhz": 14.23,
        "altitude_m": 1000,
        "attitude": {
            "pitch_deg": 2.5,
            "roll_deg": -1.2,
            "yaw_deg": 045.0
        },
        "pattern": {
            "azimuth": 0,
            "elevation": 0,
            "gain_dbi": 2.5,
            "polarization": "vertical",
            "is_3d_pattern": true
        }
    }
}
```

### List Available Patterns
```http
GET /api/antenna-patterns
```

**Response:**
```json
{
    "success": true,
    "data": {
        "vehicles": [
            {
                "type": "aircraft",
                "model": "b737",
                "frequencies": [3.5, 7.0, 14.23, 21.2, 28.5],
                "altitudes": [0, 100, 500, 1000, 5000, 10000]
            }
        ]
    }
}
```

## Vehicle Dynamics API

### Register Vehicle
```http
POST /api/vehicle-dynamics/register
```

**Request Body:**
```json
{
    "vehicle_id": "vehicle_001",
    "vehicle_type": "aircraft",
    "vehicle_model": "b737",
    "initial_position": {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "altitude": 1000
    },
    "capabilities": {
        "heading_tracking": true,
        "speed_tracking": true,
        "attitude_tracking": true,
        "antenna_rotation": false
    }
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "vehicle_id": "vehicle_001",
        "status": "registered",
        "registration_time": "2024-01-01T12:00:00Z"
    }
}
```

### Update Vehicle Position
```http
PUT /api/vehicle-dynamics/{vehicle_id}/position
```

**Request Body:**
```json
{
    "latitude": 40.7228,
    "longitude": -74.0160,
    "altitude": 1200,
    "heading": 45.0,
    "speed": 250.0,
    "pitch": 2.0,
    "roll": 1.0,
    "yaw": 45.0,
    "vertical_speed": 100.0,
    "timestamp": "2024-01-01T12:01:00Z"
}
```

### Get Vehicle Status
```http
GET /api/vehicle-dynamics/{vehicle_id}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "vehicle_id": "vehicle_001",
        "position": {
            "latitude": 40.7228,
            "longitude": -74.0160,
            "altitude": 1200
        },
        "dynamics": {
            "heading": 45.0,
            "speed": 250.0,
            "pitch": 2.0,
            "roll": 1.0,
            "yaw": 45.0,
            "vertical_speed": 100.0
        },
        "last_update": "2024-01-01T12:01:00Z",
        "status": "active"
    }
}
```

### Control Antenna Rotation
```http
PUT /api/vehicle-dynamics/{vehicle_id}/antenna
```

**Request Body:**
```json
{
    "azimuth": 45.0,
    "elevation": 10.0,
    "rotation_speed": 5.0,
    "auto_tracking": true
}
```

## Power Management API

### Get Power Status
```http
GET /api/power-management
```

**Response:**
```json
{
    "success": true,
    "data": {
        "current_power": 100,
        "available_powers": [50, 100, 150, 200, 250, 300, 350, 400, 450, 500],
        "power_efficiency": 0.85,
        "power_limiting_enabled": true,
        "swr": 1.2,
        "temperature": 45.0,
        "battery_level": 0.9
    }
}
```

### Set Power Level
```http
PUT /api/power-management/power
```

**Request Body:**
```json
{
    "power": 150,
    "band": "amateur_hf"
}
```

### Get Power Statistics
```http
GET /api/power-management/statistics
```

**Response:**
```json
{
    "success": true,
    "data": {
        "total_transmissions": 1250,
        "average_power": 120.5,
        "peak_power": 500,
        "efficiency_trend": [0.8, 0.82, 0.85, 0.87],
        "temperature_trend": [40, 42, 45, 43],
        "swr_trend": [1.1, 1.2, 1.15, 1.3]
    }
}
```

## GPU Status API

### Get GPU Status
```http
GET /api/gpu-status
```

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

### Get GPU Performance
```http
GET /api/gpu-status/performance
```

**Response:**
```json
{
    "success": true,
    "data": {
        "total_operations": 1250,
        "successful_operations": 1238,
        "failed_operations": 12,
        "average_processing_time_ms": 15.5,
        "peak_processing_time_ms": 45.2,
        "memory_usage_mb": 2048,
        "utilization_percent": 25.5
    }
}
```

## System Status API

### Get System Health
```http
GET /api/system/health
```

**Response:**
```json
{
    "success": true,
    "data": {
        "status": "healthy",
        "uptime_seconds": 86400,
        "threads": {
            "solar_data": {"status": "running", "uptime": 86400},
            "propagation": {"status": "running", "uptime": 86400},
            "api_server": {"status": "running", "uptime": 86400},
            "gpu_compute": {"status": "running", "uptime": 86400}
        },
        "resources": {
            "cpu_usage_percent": 25.5,
            "memory_usage_mb": 512,
            "disk_usage_percent": 45.2
        }
    }
}
```

### Get Feature Status
```http
GET /api/system/features
```

**Response:**
```json
{
    "success": true,
    "data": {
        "enabled_features": [
            "THREADING_SOLAR_DATA",
            "GPU_ANTENNA_PATTERNS",
            "SOLAR_DATA_FETCHING"
        ],
        "disabled_features": [
            "DEBUG_THREAD_OPERATIONS",
            "PERFORMANCE_ALERTS"
        ],
        "feature_usage": {
            "THREADING_SOLAR_DATA": 1250,
            "GPU_ANTENNA_PATTERNS": 850,
            "SOLAR_DATA_FETCHING": 2000
        }
    }
}
```

## WebSocket API

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
```

### Message Format
```json
{
    "type": "message_type",
    "data": { ... },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Message Types

#### Propagation Update
```json
{
    "type": "propagation_update",
    "data": {
        "vehicle_id": "vehicle_001",
        "signal_strength": 0.85,
        "muf": 25.3,
        "luf": 3.2
    }
}
```

#### Solar Data Update
```json
{
    "type": "solar_update",
    "data": {
        "sfi": 150,
        "k_index": 2,
        "a_index": 15
    }
}
```

#### Vehicle Position Update
```json
{
    "type": "vehicle_position",
    "data": {
        "vehicle_id": "vehicle_001",
        "position": {
            "latitude": 40.7228,
            "longitude": -74.0160,
            "altitude": 1200
        }
    }
}
```

#### System Status Update
```json
{
    "type": "system_status",
    "data": {
        "status": "healthy",
        "cpu_usage": 25.5,
        "memory_usage": 512
    }
}
```

## C++ API Reference

### Threading Management

#### FGCom_ThreadManager
```cpp
// Get instance
auto& manager = FGCom_ThreadManager::getInstance();

// Start all threads
manager.startAllThreads();

// Check thread status
bool is_running = manager.isThreadRunning("solar_data");

// Get thread statistics
ThreadStats stats = manager.getThreadStats("solar_data");
```

#### Thread Spawn Functions
```cpp
// Solar data manager
void fgcom_spawnSolarDataManager();

// Propagation engine
void fgcom_spawnPropagationEngine();

// API server
void fgcom_spawnAPIServer();

// GPU compute engine
void fgcom_spawnGPUComputeEngine();
```

### GPU Acceleration

#### FGCom_GPUAccelerator
```cpp
// Get instance
auto& accelerator = FGCom_GPUAccelerator::getInstance();

// Initialize GPU
accelerator.initializeGPU();

// Set acceleration mode
accelerator.setAccelerationMode(GPUAccelerationMode::HYBRID);

// Accelerate antenna patterns
std::vector<AntennaGainPoint> patterns;
accelerator.accelerateAntennaPatterns(patterns);
```

### Feature Toggles

#### FGCom_FeatureToggleManager
```cpp
// Get instance
auto& feature_manager = FGCom_FeatureToggleManager::getInstance();

// Check if feature is enabled
bool enabled = feature_manager.isFeatureEnabled(FeatureToggle::GPU_ANTENNA_PATTERNS);

// Enable/disable feature
feature_manager.enableFeature(FeatureToggle::GPU_ANTENNA_PATTERNS);
feature_manager.disableFeature(FeatureToggle::GPU_ANTENNA_PATTERNS);

// Load configuration
feature_manager.loadConfigFromFile("feature_toggles.conf");
```

### Debugging System

#### FGCom_DebuggingSystem
```cpp
// Get instance
auto& debug_system = FGCom_DebuggingSystem::getInstance();

// Log messages
debug_system.info(DebugCategory::THREADING, "Thread started");
debug_system.error(DebugCategory::GPU_ACCELERATION, "GPU operation failed");

// Performance profiling
debug_system.startProfile("antenna_calculation");
// ... perform operation ...
debug_system.endProfile("antenna_calculation");

// Memory tracking
debug_system.recordAllocation("pattern_cache", 1024);
```

### Utility Macros

#### Feature Toggle Macros
```cpp
// Check if feature is enabled
if (FGCOM_FEATURE_ENABLED(FeatureToggle::GPU_ANTENNA_PATTERNS)) {
    // Use GPU acceleration
}

// Record feature usage
FGCOM_FEATURE_USAGE(FeatureToggle::GPU_ANTENNA_PATTERNS, 15.5);
```

#### Debugging Macros
```cpp
// Log messages
FGCOM_LOG_INFO(DebugCategory::THREADING, "Thread started");
FGCOM_LOG_ERROR(DebugCategory::GPU_ACCELERATION, "GPU operation failed");

// Performance profiling
FGCOM_PROFILE_START("antenna_calculation");
// ... perform operation ...
FGCOM_PROFILE_END("antenna_calculation");

// Memory tracking
FGCOM_MEMORY_ALLOC("pattern_cache", 1024);
```

## Integration Examples

### JavaScript/Node.js Client
```javascript
const axios = require('axios');

class FGComClient {
    constructor(baseURL = 'http://localhost:8080/api', apiKey = null) {
        this.baseURL = baseURL;
        this.apiKey = apiKey;
    }

    async getPropagationData(lat1, lon1, lat2, lon2, frequency, power) {
        const response = await axios.get(`${this.baseURL}/propagation`, {
            params: { lat1, lon1, lat2, lon2, frequency, power },
            headers: this.getHeaders()
        });
        return response.data;
    }

    async registerVehicle(vehicleData) {
        const response = await axios.post(`${this.baseURL}/vehicle-dynamics/register`, 
            vehicleData, { headers: this.getHeaders() });
        return response.data;
    }

    getHeaders() {
        return this.apiKey ? { 'Authorization': `Bearer ${this.apiKey}` } : {};
    }
}

// Usage
const client = new FGComClient('http://localhost:8080/api', 'your-api-key');
const propagation = await client.getPropagationData(40.7128, -74.0060, 40.7228, -74.0160, 14.23, 100);
```

### Python Client
```python
import requests
import json

class FGComClient:
    def __init__(self, base_url='http://localhost:8080/api', api_key=None):
        self.base_url = base_url
        self.api_key = api_key

    def get_headers(self):
        return {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}

    def get_propagation_data(self, lat1, lon1, lat2, lon2, frequency, power):
        params = {
            'lat1': lat1, 'lon1': lon1, 'lat2': lat2, 'lon2': lon2,
            'frequency': frequency, 'power': power
        }
        response = requests.get(f'{self.base_url}/propagation', 
                              params=params, headers=self.get_headers())
        return response.json()

    def register_vehicle(self, vehicle_data):
        response = requests.post(f'{self.base_url}/vehicle-dynamics/register',
                               json=vehicle_data, headers=self.get_headers())
        return response.json()

# Usage
client = FGComClient('http://localhost:8080/api', 'your-api-key')
propagation = client.get_propagation_data(40.7128, -74.0060, 40.7228, -74.0160, 14.23, 100)
```

### WebSocket Client
```javascript
class FGComWebSocketClient {
    constructor(url = 'ws://localhost:8080/ws') {
        this.url = url;
        this.ws = null;
        this.reconnectInterval = 5000;
        this.maxReconnectAttempts = 10;
        this.reconnectAttempts = 0;
    }

    connect() {
        this.ws = new WebSocket(this.url);
        
        this.ws.onopen = () => {
            console.log('Connected to FGCom WebSocket');
            this.reconnectAttempts = 0;
        };

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
        };

        this.ws.onclose = () => {
            console.log('WebSocket connection closed');
            this.reconnect();
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    handleMessage(message) {
        switch (message.type) {
            case 'propagation_update':
                this.handlePropagationUpdate(message.data);
                break;
            case 'solar_update':
                this.handleSolarUpdate(message.data);
                break;
            case 'vehicle_position':
                this.handleVehiclePosition(message.data);
                break;
            case 'system_status':
                this.handleSystemStatus(message.data);
                break;
        }
    }

    reconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => {
                console.log(`Reconnecting... attempt ${this.reconnectAttempts}`);
                this.connect();
            }, this.reconnectInterval);
        }
    }
}

// Usage
const wsClient = new FGComWebSocketClient();
wsClient.connect();
```

## Security Considerations

### API Key Management
- Store API keys securely
- Rotate keys regularly
- Use environment variables for configuration
- Implement key expiration

### Rate Limiting
- Implement rate limiting per API key
- Monitor for abuse
- Provide rate limit headers in responses

### Input Validation
- Validate all input parameters
- Sanitize user input
- Implement proper error handling
- Use HTTPS in production

### Access Control
- Implement proper authentication
- Use role-based access control
- Log all API access
- Monitor for suspicious activity

This comprehensive API documentation provides all the information needed to integrate with the FGCom-mumble system, including RESTful endpoints, WebSocket communication, C++ APIs, and practical examples in multiple programming languages.
