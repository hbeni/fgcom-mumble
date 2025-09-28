# Work Unit Distribution API

## Overview

The Work Unit Distribution API provides distributed computing capabilities for FGCom-mumble, enabling efficient processing of radio propagation calculations, antenna pattern generation, and terrain analysis across multiple compute nodes.

## Base URL

- **Development**: `http://localhost:8080/api/v1/work-units`
- **Production**: `https://fgcom-mumble.example.com/api/v1/work-units`

## Authentication

All endpoints require authentication:

```http
Authorization: Bearer your_jwt_token_here
```

## Work Unit Types

### Radio Propagation Calculations
- **Type**: `radio_propagation`
- **Description**: Calculate radio wave propagation between two points
- **Input**: Frequency, power, antenna characteristics, terrain data
- **Output**: Signal strength, path loss, propagation mode

### Antenna Pattern Generation
- **Type**: `antenna_pattern`
- **Description**: Generate radiation patterns for antenna models
- **Input**: EZNEC model files, frequency, elevation angles
- **Output**: Radiation pattern data files

### Terrain Analysis
- **Type**: `terrain_analysis`
- **Description**: Analyze terrain for line-of-sight calculations
- **Input**: Geographic coordinates, elevation data
- **Output**: Line-of-sight results, elevation profiles

### EME Calculations
- **Type**: `eme_calculation`
- **Description**: Earth-Moon-Earth communication calculations
- **Input**: Moon position, frequency, antenna parameters
- **Output**: EME parameters, delay calculations, Doppler shifts

## API Endpoints

### Submit Work Unit

#### POST /work-units/submit
Submit a new work unit for processing.

**Request:**
```json
{
  "work_unit_type": "radio_propagation",
  "priority": "high",
  "parameters": {
    "frequency_mhz": 144.5,
    "transmit_power_watts": 1000.0,
    "transmit_position": {
      "latitude": 40.6892,
      "longitude": -74.0445,
      "altitude": 1000.0
    },
    "receive_position": {
      "latitude": 40.7000,
      "longitude": -74.0500,
      "altitude": 2000.0
    },
    "antenna_gain_dbi": 14.8,
    "terrain_data_required": true
  },
  "callback_url": "https://client.example.com/callback",
  "timeout_seconds": 300
}
```

**Response:**
```json
{
  "success": true,
  "work_unit_id": "wu_789",
  "status": "queued",
  "estimated_completion_time": "2024-01-15T10:35:00Z",
  "queue_position": 3,
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Get Work Unit Status

#### GET /work-units/{work_unit_id}
Get current status of a work unit.

**Response:**
```json
{
  "work_unit_id": "wu_789",
  "status": "processing",
  "progress_percent": 45.0,
  "current_operation": "calculating_propagation_loss",
  "estimated_remaining_seconds": 120,
  "assigned_node": "node_003",
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": "2024-01-15T10:32:00Z",
  "updated_at": "2024-01-15T10:33:00Z"
}
```

### Get Work Unit Results

#### GET /work-units/{work_unit_id}/results
Get results of a completed work unit.

**Response:**
```json
{
  "work_unit_id": "wu_789",
  "status": "completed",
  "results": {
    "signal_strength_dbw": -85.2,
    "path_loss_db": 187.3,
    "propagation_mode": "line_of_sight",
    "terrain_clearance_m": 15.3,
    "atmospheric_effects": {
      "refraction_correction": 0.1,
      "attenuation_db": 0.05
    },
    "frequency_offset_hz": 0.0,
    "doppler_shift_hz": 0.0
  },
  "processing_time_seconds": 45.2,
  "completed_at": "2024-01-15T10:35:00Z"
}
```

### List Work Units

#### GET /work-units
List work units with filtering and pagination.

**Query Parameters:**
- `status` (optional): Filter by status (queued, processing, completed, failed)
- `work_unit_type` (optional): Filter by work unit type
- `priority` (optional): Filter by priority (low, normal, high, urgent)
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Items per page (default: 50)

**Response:**
```json
{
  "work_units": [
    {
      "work_unit_id": "wu_789",
      "work_unit_type": "radio_propagation",
      "status": "completed",
      "priority": "high",
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:35:00Z",
      "processing_time_seconds": 45.2
    },
    {
      "work_unit_id": "wu_790",
      "work_unit_type": "antenna_pattern",
      "status": "processing",
      "priority": "normal",
      "created_at": "2024-01-15T10:31:00Z",
      "completed_at": null,
      "processing_time_seconds": null
    }
  ],
  "total_work_units": 2,
  "page": 1,
  "per_page": 50,
  "total_pages": 1
}
```

### Cancel Work Unit

#### DELETE /work-units/{work_unit_id}
Cancel a queued or processing work unit.

**Response:**
```json
{
  "success": true,
  "work_unit_id": "wu_789",
  "status": "cancelled",
  "cancelled_at": "2024-01-15T10:33:00Z"
}
```

## Compute Node Management

### Register Compute Node

#### POST /compute-nodes/register
Register a new compute node in the cluster.

**Request:**
```json
{
  "node_id": "node_003",
  "capabilities": [
    "radio_propagation",
    "antenna_pattern",
    "terrain_analysis"
  ],
  "performance_metrics": {
    "cpu_cores": 8,
    "memory_gb": 32,
    "processing_power": 1000.0,
    "network_bandwidth_mbps": 1000
  },
  "location": {
    "datacenter": "us-east-1",
    "region": "North America"
  }
}
```

**Response:**
```json
{
  "success": true,
  "node_id": "node_003",
  "status": "active",
  "assigned_work_units": 0,
  "max_concurrent_work_units": 4,
  "registered_at": "2024-01-15T10:30:00Z"
}
```

### Get Compute Node Status

#### GET /compute-nodes/{node_id}
Get status of a compute node.

**Response:**
```json
{
  "node_id": "node_003",
  "status": "active",
  "capabilities": [
    "radio_propagation",
    "antenna_pattern",
    "terrain_analysis"
  ],
  "current_load": {
    "cpu_usage_percent": 45.2,
    "memory_usage_percent": 67.8,
    "active_work_units": 2,
    "queue_length": 5
  },
  "performance_metrics": {
    "average_processing_time_seconds": 42.3,
    "throughput_work_units_per_hour": 85.2,
    "success_rate_percent": 98.5
  },
  "last_heartbeat": "2024-01-15T10:30:00Z"
}
```

### List Compute Nodes

#### GET /compute-nodes
List all compute nodes in the cluster.

**Response:**
```json
{
  "compute_nodes": [
    {
      "node_id": "node_001",
      "status": "active",
      "capabilities": ["radio_propagation", "antenna_pattern"],
      "current_load": {
        "cpu_usage_percent": 25.0,
        "memory_usage_percent": 45.0,
        "active_work_units": 1
      },
      "performance_metrics": {
        "average_processing_time_seconds": 38.5,
        "throughput_work_units_per_hour": 95.0
      }
    },
    {
      "node_id": "node_002",
      "status": "maintenance",
      "capabilities": ["terrain_analysis", "eme_calculation"],
      "current_load": {
        "cpu_usage_percent": 0.0,
        "memory_usage_percent": 5.0,
        "active_work_units": 0
      },
      "performance_metrics": {
        "average_processing_time_seconds": 52.1,
        "throughput_work_units_per_hour": 68.5
      }
    }
  ],
  "total_nodes": 2,
  "active_nodes": 1,
  "total_processing_capacity": 1000.0
}
```

## Work Unit Processing

### Radio Propagation Work Unit

**Input Parameters:**
```json
{
  "frequency_mhz": 144.5,
  "transmit_power_watts": 1000.0,
  "transmit_antenna": {
    "gain_dbi": 14.8,
    "height_m": 10.0,
    "pattern_file": "yagi_144mhz.ez"
  },
  "receive_antenna": {
    "gain_dbi": 2.15,
    "height_m": 1000.0,
    "pattern_file": "dipole_144mhz.ez"
  },
  "transmit_position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 10.0
  },
  "receive_position": {
    "latitude": 40.7000,
    "longitude": -74.0500,
    "altitude": 1000.0
  },
  "environmental_conditions": {
    "temperature_celsius": 22.5,
    "humidity_percent": 65.0,
    "pressure_hpa": 1013.25
  }
}
```

**Output Results:**
```json
{
  "signal_strength_dbw": -85.2,
  "path_loss_db": 187.3,
  "propagation_mode": "line_of_sight",
  "terrain_clearance_m": 15.3,
  "atmospheric_effects": {
    "refraction_correction": 0.1,
    "attenuation_db": 0.05
  },
  "frequency_offset_hz": 0.0,
  "doppler_shift_hz": 0.0,
  "communication_range_km": 45.2,
  "signal_quality": 0.87
}
```

### Antenna Pattern Work Unit

**Input Parameters:**
```json
{
  "eznec_model_file": "yagi_144mhz.ez",
  "frequency_mhz": 144.5,
  "elevation_angles": [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90],
  "azimuth_angles": [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 260, 270, 280, 290, 300, 310, 320, 330, 340, 350],
  "output_format": "nec2",
  "include_ground_effects": true,
  "ground_conductivity": 0.005,
  "ground_permittivity": 13.0
}
```

**Output Results:**
```json
{
  "pattern_file": "yagi_144mhz_pattern.nec",
  "gain_max_dbi": 14.8,
  "beamwidth_azimuth_deg": 30.0,
  "beamwidth_elevation_deg": 35.0,
  "front_to_back_ratio_db": 27.0,
  "side_lobe_level_db": -15.0,
  "impedance_ohms": 50.0,
  "swr": 1.2,
  "pattern_points": 684,
  "processing_time_seconds": 45.2
}
```

### Terrain Analysis Work Unit

**Input Parameters:**
```json
{
  "start_position": {
    "latitude": 40.6892,
    "longitude": -74.0445,
    "altitude": 10.0
  },
  "end_position": {
    "latitude": 40.7000,
    "longitude": -74.0500,
    "altitude": 1000.0
  },
  "terrain_data_source": "ASTER_GDEM",
  "resolution_meters": 30,
  "analysis_type": "line_of_sight",
  "fresnel_zone_clearance": true,
  "frequency_mhz": 144.5
}
```

**Output Results:**
```json
{
  "line_of_sight": true,
  "distance_km": 1.2,
  "elevation_angle_deg": 4.7,
  "azimuth_angle_deg": 45.0,
  "terrain_clearance_m": 15.3,
  "fresnel_zone_clearance": true,
  "terrain_profile": [
    {"distance_km": 0.0, "altitude_m": 10.0},
    {"distance_km": 0.2, "altitude_m": 25.3},
    {"distance_km": 0.4, "altitude_m": 45.7},
    {"distance_km": 0.6, "altitude_m": 67.2},
    {"distance_km": 0.8, "altitude_m": 89.1},
    {"distance_km": 1.0, "altitude_m": 112.5},
    {"distance_km": 1.2, "altitude_m": 1000.0}
  ],
  "obstacles": [],
  "analysis_time_seconds": 12.3
}
```

## Error Handling

### Work Unit Errors

```json
{
  "success": false,
  "error": {
    "code": "WORK_UNIT_FAILED",
    "message": "Radio propagation calculation failed",
    "details": {
      "work_unit_id": "wu_789",
      "failure_reason": "Invalid frequency range",
      "error_log": "Frequency 999.9 MHz is not supported for VHF calculations"
    },
    "timestamp": "2024-01-15T10:35:00Z"
  }
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_WORK_UNIT_TYPE` | Unsupported work unit type | 400 |
| `INVALID_PARAMETERS` | Invalid input parameters | 400 |
| `WORK_UNIT_NOT_FOUND` | Work unit ID not found | 404 |
| `WORK_UNIT_FAILED` | Work unit processing failed | 500 |
| `COMPUTE_NODE_UNAVAILABLE` | No compute nodes available | 503 |
| `PROCESSING_TIMEOUT` | Work unit processing timeout | 504 |

## WebSocket Real-Time Updates

### Work Unit Status Updates

```json
{
  "type": "work_unit_status",
  "work_unit_id": "wu_789",
  "status": "processing",
  "progress_percent": 45.0,
  "current_operation": "calculating_propagation_loss",
  "estimated_remaining_seconds": 120,
  "timestamp": "2024-01-15T10:33:00Z"
}
```

### Compute Node Status Updates

```json
{
  "type": "compute_node_status",
  "node_id": "node_003",
  "status": "active",
  "current_load": {
    "cpu_usage_percent": 45.2,
    "memory_usage_percent": 67.8,
    "active_work_units": 2
  },
  "timestamp": "2024-01-15T10:33:00Z"
}
```

## Performance Monitoring

### Get System Performance

#### GET /work-units/performance
Get overall system performance metrics.

**Response:**
```json
{
  "system_metrics": {
    "total_work_units_processed": 15420,
    "average_processing_time_seconds": 42.3,
    "throughput_work_units_per_hour": 125.5,
    "success_rate_percent": 98.5,
    "queue_length": 12,
    "active_compute_nodes": 5
  },
  "work_unit_type_metrics": {
    "radio_propagation": {
      "processed": 8542,
      "average_time_seconds": 38.5,
      "success_rate_percent": 99.2
    },
    "antenna_pattern": {
      "processed": 3241,
      "average_time_seconds": 52.1,
      "success_rate_percent": 97.8
    },
    "terrain_analysis": {
      "processed": 2637,
      "average_time_seconds": 28.7,
      "success_rate_percent": 98.9
    }
  },
  "timestamp": "2024-01-15T10:33:00Z"
}
```

This comprehensive Work Unit Distribution API provides distributed computing capabilities for FGCom-mumble's complex radio propagation and antenna modeling calculations.