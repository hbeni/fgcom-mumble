# AGC and Squelch API Documentation

**Date:** September 27, 2024  
**Version:** 1.0  
**Purpose:** Comprehensive API documentation for AGC (Automatic Gain Control) and Squelch functionality in FGCom-mumble

## Overview

The AGC and Squelch API provides comprehensive control over radio receiver audio processing, including automatic gain control with fast/medium/slow settings and advanced squelch functionality with tone and noise detection.

## Table of Contents

1. [AGC (Automatic Gain Control)](#agc-automatic-gain-control)
2. [Squelch Control](#squelch-control)
3. [API Endpoints](#api-endpoints)
4. [Configuration Management](#configuration-management)
5. [Audio Processing](#audio-processing)
6. [Monitoring and Diagnostics](#monitoring-and-diagnostics)
7. [Examples](#examples)

## AGC (Automatic Gain Control)

### AGC Modes

| Mode | Attack Time | Release Time | Use Case |
|------|-------------|--------------|----------|
| **Fast** | 1.0 ms | 10.0 ms | Rapid signal changes, digital modes |
| **Medium** | 5.0 ms | 100.0 ms | General purpose, balanced response |
| **Slow** | 20.0 ms | 500.0 ms | Stable signals, prevent pumping |
| **Off** | N/A | N/A | Manual gain control |

### AGC Parameters

- **Threshold**: Signal level at which AGC activates (-100 to 0 dB)
- **Max Gain**: Maximum gain AGC can apply (0 to 60 dB)
- **Min Gain**: Minimum gain AGC can apply (-40 to 0 dB)
- **Attack Time**: How quickly AGC responds to signal increases
- **Release Time**: How quickly AGC responds to signal decreases

### AGC API Endpoints

#### Get AGC Status
```http
GET /api/agc/status
```

**Response:**
```json
{
  "success": true,
  "message": "AGC status retrieved",
  "data": {
    "mode": 2,
    "enabled": true,
    "threshold_db": -60.0,
    "max_gain_db": 40.0,
    "min_gain_db": -20.0,
    "attack_time_ms": 5.0,
    "release_time_ms": 100.0,
    "current_gain_db": 15.2,
    "active": true
  }
}
```

#### Set AGC Mode
```http
POST /api/agc/mode
Content-Type: application/json

{
  "mode": "fast"
}
```

**Supported modes:** `off`, `fast`, `medium`, `slow`

#### Set AGC Threshold
```http
POST /api/agc/threshold
Content-Type: application/json

{
  "threshold_db": -60.0
}
```

#### Set AGC Timing
```http
POST /api/agc/attack-time
Content-Type: application/json

{
  "attack_time_ms": 5.0
}
```

```http
POST /api/agc/release-time
Content-Type: application/json

{
  "release_time_ms": 100.0
}
```

#### Set AGC Gain Limits
```http
POST /api/agc/max-gain
Content-Type: application/json

{
  "max_gain_db": 40.0
}
```

```http
POST /api/agc/min-gain
Content-Type: application/json

{
  "min_gain_db": -20.0
}
```

#### Enable/Disable AGC
```http
POST /api/agc/enable
Content-Type: application/json

{
  "enabled": true
}
```

#### Apply AGC Preset
```http
POST /api/agc/preset
Content-Type: application/json

{
  "preset": "medium"
}
```

## Squelch Control

### Squelch Types

1. **Signal Squelch**: Opens when signal exceeds threshold
2. **Tone Squelch**: Opens when specific tone frequency detected
3. **Noise Squelch**: Opens when noise level is below threshold

### Squelch Parameters

- **Threshold**: Signal level required to open squelch (-120 to 0 dB)
- **Hysteresis**: Difference between open/close thresholds (0 to 20 dB)
- **Attack Time**: How quickly squelch opens (0.1 to 1000 ms)
- **Release Time**: How quickly squelch closes (1 to 10000 ms)
- **Tone Frequency**: Frequency for tone squelch (50 to 3000 Hz)

### Squelch API Endpoints

#### Get Squelch Status
```http
GET /api/squelch/status
```

**Response:**
```json
{
  "success": true,
  "message": "Squelch status retrieved",
  "data": {
    "enabled": true,
    "threshold_db": -80.0,
    "hysteresis_db": 3.0,
    "attack_time_ms": 10.0,
    "release_time_ms": 50.0,
    "tone_squelch": false,
    "tone_frequency_hz": 100.0,
    "noise_squelch": true,
    "noise_threshold_db": -70.0,
    "open": true,
    "signal_level_db": -75.0
  }
}
```

#### Enable/Disable Squelch
```http
POST /api/squelch/enable
Content-Type: application/json

{
  "enabled": true
}
```

#### Set Squelch Threshold
```http
POST /api/squelch/threshold
Content-Type: application/json

{
  "threshold_db": -80.0
}
```

#### Set Squelch Hysteresis
```http
POST /api/squelch/hysteresis
Content-Type: application/json

{
  "hysteresis_db": 3.0
}
```

#### Set Squelch Timing
```http
POST /api/squelch/attack-time
Content-Type: application/json

{
  "attack_time_ms": 10.0
}
```

```http
POST /api/squelch/release-time
Content-Type: application/json

{
  "release_time_ms": 50.0
}
```

#### Configure Tone Squelch
```http
POST /api/squelch/tone
Content-Type: application/json

{
  "enabled": true,
  "frequency_hz": 100.0
}
```

#### Configure Noise Squelch
```http
POST /api/squelch/noise
Content-Type: application/json

{
  "enabled": true,
  "threshold_db": -70.0
}
```

#### Apply Squelch Preset
```http
POST /api/squelch/preset
Content-Type: application/json

{
  "preset": "normal"
}
```

**Supported presets:** `sensitive`, `normal`, `tight`

## API Endpoints

### Combined Status
```http
GET /api/agc-squelch/status
```

### Combined Configuration
```http
POST /api/agc-squelch/config
Content-Type: application/json

{
  "agc": {
    "mode": "medium",
    "enabled": true,
    "threshold_db": -60.0
  },
  "squelch": {
    "enabled": true,
    "threshold_db": -80.0,
    "preset": "normal"
  }
}
```

### Reset to Defaults
```http
POST /api/agc-squelch/reset
```

## Configuration Management

### Save Configuration
```http
POST /api/agc-squelch/save-config
Content-Type: application/json

{
  "config_name": "my_config"
}
```

### Load Configuration
```http
POST /api/agc-squelch/load-config
Content-Type: application/json

{
  "config_name": "my_config"
}
```

### List Configurations
```http
GET /api/agc-squelch/list-configs
```

### Delete Configuration
```http
DELETE /api/agc-squelch/delete-config
Content-Type: application/json

{
  "config_name": "my_config"
}
```

## Audio Processing

### Process Audio
```http
POST /api/agc-squelch/process-audio
Content-Type: application/json

{
  "audio_data_base64": "base64_encoded_audio_data",
  "sample_rate_hz": 44100,
  "sample_count": 1024
}
```

### Get Audio Statistics
```http
GET /api/agc-squelch/audio-stats
```

## Monitoring and Diagnostics

### Get Diagnostics
```http
GET /api/agc-squelch/diagnostics
```

### Get Performance Statistics
```http
GET /api/agc-squelch/performance
```

### Start Monitoring
```http
POST /api/agc-squelch/start-monitoring
```

### Stop Monitoring
```http
POST /api/agc-squelch/stop-monitoring
```

### Get Monitoring Data
```http
GET /api/agc-squelch/monitoring-data
```

## Examples

### Example 1: Set Fast AGC for Digital Modes
```bash
curl -X POST http://localhost:8080/api/agc/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "fast"}'

curl -X POST http://localhost:8080/api/agc/threshold \
  -H "Content-Type: application/json" \
  -d '{"threshold_db": -50.0}'
```

### Example 2: Configure Sensitive Squelch
```bash
curl -X POST http://localhost:8080/api/squelch/preset \
  -H "Content-Type: application/json" \
  -d '{"preset": "sensitive"}'

curl -X POST http://localhost:8080/api/squelch/tone \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "frequency_hz": 100.0}'
```

### Example 3: Save and Load Configuration
```bash
# Save current configuration
curl -X POST http://localhost:8080/api/agc-squelch/save-config \
  -H "Content-Type: application/json" \
  -d '{"config_name": "digital_mode"}'

# Load saved configuration
curl -X POST http://localhost:8080/api/agc-squelch/load-config \
  -H "Content-Type: application/json" \
  -d '{"config_name": "digital_mode"}'
```

### Example 4: Process Audio with AGC and Squelch
```bash
# Process audio samples
curl -X POST http://localhost:8080/api/agc-squelch/process-audio \
  -H "Content-Type: application/json" \
  -d '{
    "audio_data_base64": "base64_encoded_pcm_data",
    "sample_rate_hz": 44100,
    "sample_count": 1024
  }'
```

## Error Handling

All API endpoints return JSON responses with the following structure:

```json
{
  "success": false,
  "message": "Error description",
  "timestamp": "2024-09-27 12:00:00.000",
  "error_code": 400
}
```

### Common Error Codes

- **400**: Bad Request - Invalid parameters
- **404**: Not Found - Resource not found
- **500**: Internal Server Error - Server error

## Technical Specifications

### AGC Timing Parameters

| Mode | Attack Time | Release Time | Use Case |
|------|-------------|--------------|----------|
| Fast | 1.0 ms | 10.0 ms | Digital modes, rapid changes |
| Medium | 5.0 ms | 100.0 ms | General purpose, balanced |
| Slow | 20.0 ms | 500.0 ms | Stable signals, prevent pumping |

### Squelch Presets

| Preset | Threshold | Hysteresis | Attack | Release | Use Case |
|--------|-----------|------------|--------|---------|----------|
| Sensitive | -90 dB | 1 dB | 5 ms | 25 ms | Weak signals |
| Normal | -80 dB | 3 dB | 10 ms | 50 ms | General purpose |
| Tight | -70 dB | 5 dB | 20 ms | 100 ms | Strong signals only |

### Audio Processing

- **Sample Rate**: 8 kHz to 192 kHz
- **Bit Depth**: 16-bit PCM
- **Channels**: Mono or Stereo
- **Format**: Base64 encoded PCM data

## Integration Notes

### C++ Integration
```cpp
#include "agc_squelch.h"
#include "agc_squelch_api.h"

// Get AGC and Squelch instance
auto& agc_squelch = FGCom_AGC_Squelch::getInstance();

// Set AGC mode
agc_squelch.setAGCMode(AGCMode::FAST);

// Process audio samples
float* input_samples = ...;
float* output_samples = ...;
agc_squelch.processAudioSamples(input_samples, output_samples, 
                              sample_count, sample_rate_hz);
```

### API Integration
```cpp
// Get AGC status via API
std::string status = FGCom_AGC_Squelch_API::getAGCStatus();

// Set squelch threshold via API
std::string result = FGCom_AGC_Squelch_API::setSquelchThreshold(-80.0f);
```

## Performance Considerations

- **AGC Processing**: ~0.1ms per 1024 samples
- **Squelch Processing**: ~0.05ms per 1024 samples
- **Memory Usage**: ~1MB for audio buffers
- **CPU Usage**: <1% on modern systems

## Troubleshooting

### Common Issues

1. **AGC Not Responding**
   - Check if AGC is enabled
   - Verify threshold settings
   - Check signal levels

2. **Squelch Not Opening**
   - Verify squelch is enabled
   - Check threshold settings
   - Verify signal strength

3. **Audio Distortion**
   - Check gain limits
   - Verify sample rate
   - Check for clipping

### Debug Commands

```bash
# Get diagnostics
curl http://localhost:8080/api/agc-squelch/diagnostics

# Get performance stats
curl http://localhost:8080/api/agc-squelch/performance

# Start monitoring
curl -X POST http://localhost:8080/api/agc-squelch/start-monitoring
```

---

*This documentation provides comprehensive coverage of the AGC and Squelch API functionality. For additional support, refer to the source code or contact the development team.*
