# AGC & Squelch System Documentation

## Overview

The FGCom-mumble AGC & Squelch System provides advanced Automatic Gain Control and Squelch functionality with configurable presets. This system ensures optimal audio quality and communication reliability by automatically adjusting gain levels and managing signal thresholds.

## What are AGC and Squelch?

### Automatic Gain Control (AGC)
AGC is a system that automatically adjusts the gain (amplification) of a signal to maintain a consistent output level. It helps:
- **Prevent Audio Distortion**: Avoids over-amplification of strong signals
- **Improve Weak Signals**: Boosts weak signals to audible levels
- **Maintain Consistent Volume**: Keeps audio levels stable across different signal strengths
- **Reduce Background Noise**: Helps maintain signal-to-noise ratio

### Squelch
Squelch is a system that mutes the audio output when the signal strength falls below a threshold. It helps:
- **Eliminate Background Noise**: Mutes audio when no useful signal is present
- **Improve Communication Quality**: Only allows clear signals through
- **Reduce Fatigue**: Prevents constant background noise
- **Enable Hands-free Operation**: Automatically opens/closes based on signal strength

## System Architecture

### Core Components

- **AGCController**: Main AGC management system
- **SquelchController**: Squelch threshold management
- **AudioProcessor**: Real-time audio processing
- **PresetManager**: Configuration preset management
- **PerformanceMonitor**: System performance monitoring
- **DiagnosticsEngine**: System diagnostics and troubleshooting

## AGC Features

### AGC Modes

#### Automatic Mode
- **Adaptive Gain**: Automatically adjusts gain based on signal strength
- **Attack Time**: How quickly gain increases for strong signals
- **Release Time**: How quickly gain decreases for weak signals
- **Gain Range**: Minimum and maximum gain limits

#### Manual Mode
- **Fixed Gain**: User-defined gain level
- **Manual Control**: Direct gain adjustment
- **Override Capability**: Can override automatic adjustments

#### Preset Mode
- **Predefined Settings**: Optimized settings for different scenarios
- **Quick Selection**: Easy switching between configurations
- **Custom Presets**: User-defined configurations

### AGC Parameters

#### Gain Control
- **Current Gain**: Current gain level in dB
- **Target Gain**: Desired gain level
- **Gain Range**: Minimum and maximum gain limits
- **Gain Step**: Increment for gain adjustments

#### Timing Parameters
- **Attack Time**: Time to increase gain (milliseconds)
- **Release Time**: Time to decrease gain (milliseconds)
- **Hold Time**: Time to maintain gain before release
- **Decay Time**: Time for gain to decay

#### Threshold Parameters
- **Input Threshold**: Minimum input level for AGC activation
- **Output Threshold**: Maximum output level before limiting
- **Noise Threshold**: Background noise level
- **Signal Threshold**: Minimum signal level for processing

## Squelch Features

### Squelch Types

#### Signal Squelch
- **Signal Strength**: Based on received signal strength
- **Threshold**: Minimum signal level to open squelch
- **Hysteresis**: Different thresholds for opening/closing
- **Smoothing**: Prevents rapid squelch opening/closing

#### Tone Squelch (CTCSS)
- **Sub-audible Tones**: Low-frequency tones (67-254 Hz)
- **Tone Detection**: Automatic tone recognition
- **Tone Filtering**: Filters out signals without correct tone
- **Tone Programming**: Configurable tone frequencies

#### Digital Squelch (DCS)
- **Digital Codes**: Digital squelch codes
- **Code Detection**: Automatic code recognition
- **Code Filtering**: Filters out signals without correct code
- **Code Programming**: Configurable digital codes

### Squelch Parameters

#### Threshold Control
- **Squelch Threshold**: Minimum signal level to open squelch
- **Hysteresis**: Difference between open/close thresholds
- **Attack Time**: Time to open squelch
- **Release Time**: Time to close squelch

#### Tone Parameters
- **Tone Frequency**: CTCSS tone frequency
- **Tone Tolerance**: Frequency tolerance for tone detection
- **Tone Filter**: Bandpass filter for tone detection
- **Tone Squelch**: Enable/disable tone squelch

## Configuration

### AGC & Squelch Configuration

```ini
# configs/agc_squelch.conf
[agc_squelch]
# Enable/disable AGC and squelch
enabled = true

# AGC settings
enable_agc = true
agc_mode = "automatic"  # "automatic", "manual", "preset"
agc_attack_time_ms = 10.0
agc_release_time_ms = 100.0
agc_max_gain_db = 30.0
agc_min_gain_db = 0.0
agc_target_level_db = -20.0
agc_threshold_db = -80.0

# Squelch settings
enable_squelch = true
squelch_threshold_db = -85.0
squelch_hysteresis_db = 3.0
squelch_attack_time_ms = 5.0
squelch_release_time_ms = 50.0
squelch_type = "signal"  # "signal", "tone", "digital"

# Tone squelch (CTCSS)
enable_tone_squelch = false
tone_frequency_hz = 100.0
tone_tolerance_hz = 2.0
tone_filter_bandwidth_hz = 10.0

# Digital squelch (DCS)
enable_digital_squelch = false
digital_code = 023
digital_tolerance = 1

# Audio processing
enable_audio_processing = true
audio_sample_rate_hz = 44100
audio_buffer_size = 1024
processing_latency_ms = 10.0

# Performance monitoring
enable_performance_monitoring = true
monitoring_interval_ms = 1000
enable_diagnostics = true
diagnostics_level = "info"  # "debug", "info", "warning", "error"
```

## Data Structures

### AGC Status Structure

```cpp
struct fgcom_agc_status {
    // AGC settings
    bool enabled;
    std::string mode; // "automatic", "manual", "preset"
    float current_gain_db;
    float target_gain_db;
    float max_gain_db;
    float min_gain_db;
    float target_level_db;
    float threshold_db;
    
    // Timing parameters
    float attack_time_ms;
    float release_time_ms;
    float hold_time_ms;
    float decay_time_ms;
    
    // Performance metrics
    float input_level_db;
    float output_level_db;
    float gain_variation_db;
    float response_time_ms;
    float efficiency_percent;
    
    // Status flags
    bool agc_active;
    bool gain_limiting;
    bool threshold_exceeded;
    bool performance_optimal;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
};
```

### Squelch Status Structure

```cpp
struct fgcom_squelch_status {
    // Squelch settings
    bool enabled;
    std::string type; // "signal", "tone", "digital"
    float threshold_db;
    float hysteresis_db;
    float attack_time_ms;
    float release_time_ms;
    
    // Signal parameters
    float signal_strength_db;
    float noise_floor_db;
    float signal_to_noise_ratio_db;
    bool squelch_open;
    bool squelch_breaking;
    
    // Tone squelch parameters
    bool tone_squelch_enabled;
    float tone_frequency_hz;
    float tone_tolerance_hz;
    bool tone_detected;
    float tone_strength_db;
    
    // Digital squelch parameters
    bool digital_squelch_enabled;
    int digital_code;
    int digital_tolerance;
    bool digital_code_detected;
    float digital_strength_db;
    
    // Performance metrics
    float squelch_response_time_ms;
    float squelch_efficiency_percent;
    int squelch_cycles_per_minute;
    
    // Status flags
    bool squelch_active;
    bool threshold_adjustment;
    bool performance_optimal;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
};
```

### Combined AGC/Squelch Status

```cpp
struct fgcom_agc_squelch_status {
    fgcom_agc_status agc;
    fgcom_squelch_status squelch;
    
    // Combined metrics
    float overall_audio_quality;
    float signal_processing_efficiency;
    float system_performance_score;
    
    // Status flags
    bool system_enabled;
    bool performance_optimal;
    bool diagnostics_available;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
};
```

## API Endpoints

### AGC Status

#### Get AGC Status
```http
GET /api/agc/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "agc_status": {
    "enabled": true,
    "mode": "automatic",
    "current_gain_db": 15.2,
    "target_gain_db": 15.0,
    "max_gain_db": 30.0,
    "min_gain_db": 0.0,
    "target_level_db": -20.0,
    "threshold_db": -80.0,
    "attack_time_ms": 10.0,
    "release_time_ms": 100.0,
    "hold_time_ms": 50.0,
    "decay_time_ms": 200.0,
    "input_level_db": -85.2,
    "output_level_db": -70.0,
    "gain_variation_db": 2.1,
    "response_time_ms": 8.5,
    "efficiency_percent": 85.2,
    "agc_active": true,
    "gain_limiting": false,
    "threshold_exceeded": false,
    "performance_optimal": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Set AGC Mode
```http
POST /api/agc/mode
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "mode": "automatic",
  "target_level_db": -20.0,
  "threshold_db": -80.0,
  "attack_time_ms": 10.0,
  "release_time_ms": 100.0,
  "max_gain_db": 30.0,
  "min_gain_db": 0.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "AGC mode updated successfully",
  "new_mode": "automatic",
  "new_target_level_db": -20.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Squelch Status

#### Get Squelch Status
```http
GET /api/squelch/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "squelch_status": {
    "enabled": true,
    "type": "signal",
    "threshold_db": -85.0,
    "hysteresis_db": 3.0,
    "attack_time_ms": 5.0,
    "release_time_ms": 50.0,
    "signal_strength_db": -82.0,
    "noise_floor_db": -95.0,
    "signal_to_noise_ratio_db": 13.0,
    "squelch_open": true,
    "squelch_breaking": false,
    "tone_squelch_enabled": false,
    "tone_frequency_hz": 0.0,
    "tone_tolerance_hz": 0.0,
    "tone_detected": false,
    "tone_strength_db": 0.0,
    "digital_squelch_enabled": false,
    "digital_code": 0,
    "digital_tolerance": 0,
    "digital_code_detected": false,
    "digital_strength_db": 0.0,
    "squelch_response_time_ms": 3.2,
    "squelch_efficiency_percent": 92.5,
    "squelch_cycles_per_minute": 5,
    "squelch_active": true,
    "threshold_adjustment": false,
    "performance_optimal": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Set Squelch Threshold
```http
POST /api/squelch/threshold
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "threshold_db": -85.0,
  "hysteresis_db": 3.0,
  "attack_time_ms": 5.0,
  "release_time_ms": 50.0
}
```

**Response:**
```json
{
  "success": true,
  "message": "Squelch threshold updated successfully",
  "new_threshold_db": -85.0,
  "new_hysteresis_db": 3.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Combined AGC/Squelch

#### Get Combined Status
```http
GET /api/agc-squelch/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "combined_status": {
    "agc": {
      "enabled": true,
      "mode": "automatic",
      "current_gain_db": 15.2,
      "target_gain_db": 15.0,
      "efficiency_percent": 85.2
    },
    "squelch": {
      "enabled": true,
      "type": "signal",
      "threshold_db": -85.0,
      "squelch_open": true,
      "efficiency_percent": 92.5
    },
    "overall_audio_quality": 0.88,
    "signal_processing_efficiency": 0.89,
    "system_performance_score": 0.87,
    "system_enabled": true,
    "performance_optimal": true,
    "diagnostics_available": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Set Combined Configuration
```http
POST /api/agc-squelch/config
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "agc": {
    "enabled": true,
    "mode": "automatic",
    "target_level_db": -20.0,
    "threshold_db": -80.0,
    "attack_time_ms": 10.0,
    "release_time_ms": 100.0,
    "max_gain_db": 30.0,
    "min_gain_db": 0.0
  },
  "squelch": {
    "enabled": true,
    "type": "signal",
    "threshold_db": -85.0,
    "hysteresis_db": 3.0,
    "attack_time_ms": 5.0,
    "release_time_ms": 50.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Combined configuration updated successfully",
  "agc_enabled": true,
  "squelch_enabled": true,
  "estimated_performance_score": 0.87,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## C++ API Usage

### Basic AGC Control

```cpp
#include "agc_squelch.h"

// Get AGC/Squelch controller instance
auto& agc_squelch = FGCom_AGC_Squelch_API::getInstance();

// Get current AGC status
fgcom_agc_status agc_status = agc_squelch.getAGCStatus();
std::cout << "AGC enabled: " << agc_status.enabled << std::endl;
std::cout << "Current gain: " << agc_status.current_gain_db << " dB" << std::endl;
std::cout << "Efficiency: " << agc_status.efficiency_percent << "%" << std::endl;
```

### Set AGC Parameters

```cpp
// Set AGC mode and parameters
agc_squelch.setAGCMode("automatic");
agc_squelch.setAGCTargetLevel(-20.0f);
agc_squelch.setAGCThreshold(-80.0f);
agc_squelch.setAGCAttackTime(10.0f);
agc_squelch.setAGCReleaseTime(100.0f);
agc_squelch.setAGCGainRange(0.0f, 30.0f);

std::cout << "AGC parameters set successfully" << std::endl;
```

### Squelch Control

```cpp
// Get current squelch status
fgcom_squelch_status squelch_status = agc_squelch.getSquelchStatus();
std::cout << "Squelch enabled: " << squelch_status.enabled << std::endl;
std::cout << "Squelch open: " << squelch_status.squelch_open << std::endl;
std::cout << "Signal strength: " << squelch_status.signal_strength_db << " dB" << std::endl;

// Set squelch parameters
agc_squelch.setSquelchThreshold(-85.0f);
agc_squelch.setSquelchHysteresis(3.0f);
agc_squelch.setSquelchAttackTime(5.0f);
agc_squelch.setSquelchReleaseTime(50.0f);

std::cout << "Squelch parameters set successfully" << std::endl;
```

### Tone Squelch (CTCSS)

```cpp
// Enable tone squelch
agc_squelch.enableToneSquelch(true);
agc_squelch.setToneFrequency(100.0f); // 100 Hz CTCSS tone
agc_squelch.setToneTolerance(2.0f);

// Check tone detection
if (agc_squelch.isToneDetected()) {
    std::cout << "CTCSS tone detected" << std::endl;
} else {
    std::cout << "No CTCSS tone detected" << std::endl;
}
```

### Digital Squelch (DCS)

```cpp
// Enable digital squelch
agc_squelch.enableDigitalSquelch(true);
agc_squelch.setDigitalCode(023); // Digital code 023
agc_squelch.setDigitalTolerance(1);

// Check digital code detection
if (agc_squelch.isDigitalCodeDetected()) {
    std::cout << "Digital code detected" << std::endl;
} else {
    std::cout << "No digital code detected" << std::endl;
}
```

## Advanced Features

### AGC Algorithms

```cpp
class AGCAlgorithm {
private:
    float target_level_db;
    float attack_time_ms;
    float release_time_ms;
    float max_gain_db;
    float min_gain_db;
    
public:
    float calculateGain(float input_level_db, float current_gain_db) {
        float error = target_level_db - input_level_db;
        float gain_adjustment = 0.0f;
        
        if (error > 0.0f) {
            // Signal too weak, increase gain
            gain_adjustment = error * (attack_time_ms / 1000.0f);
        } else {
            // Signal too strong, decrease gain
            gain_adjustment = error * (release_time_ms / 1000.0f);
        }
        
        float new_gain = current_gain_db + gain_adjustment;
        
        // Clamp to gain range
        return std::max(min_gain_db, std::min(max_gain_db, new_gain));
    }
    
    float calculateAttackTime(float signal_level_db) {
        // Calculate attack time based on signal level
        float level_factor = (signal_level_db + 100.0f) / 100.0f;
        return attack_time_ms * level_factor;
    }
    
    float calculateReleaseTime(float signal_level_db) {
        // Calculate release time based on signal level
        float level_factor = (signal_level_db + 100.0f) / 100.0f;
        return release_time_ms * level_factor;
    }
};
```

### Squelch Algorithms

```cpp
class SquelchAlgorithm {
private:
    float threshold_db;
    float hysteresis_db;
    float attack_time_ms;
    float release_time_ms;
    
public:
    bool shouldOpenSquelch(float signal_strength_db, bool current_state) {
        if (current_state) {
            // Squelch is open, check if it should close
            return signal_strength_db > (threshold_db - hysteresis_db);
        } else {
            // Squelch is closed, check if it should open
            return signal_strength_db > threshold_db;
        }
    }
    
    float calculateSquelchResponse(float signal_strength_db, bool current_state) {
        float response_time = 0.0f;
        
        if (shouldOpenSquelch(signal_strength_db, current_state)) {
            response_time = attack_time_ms;
        } else {
            response_time = release_time_ms;
        }
        
        return response_time;
    }
    
    float calculateHysteresis(float signal_strength_db) {
        // Calculate hysteresis based on signal strength
        float strength_factor = (signal_strength_db + 100.0f) / 100.0f;
        return hysteresis_db * strength_factor;
    }
};
```

### Tone Detection

```cpp
class ToneDetector {
private:
    float tone_frequency_hz;
    float tone_tolerance_hz;
    float filter_bandwidth_hz;
    
public:
    bool detectTone(const float* audio_buffer, size_t buffer_size, float sample_rate_hz) {
        // Apply bandpass filter for tone frequency
        float filtered_signal = applyBandpassFilter(audio_buffer, buffer_size, 
                                                   tone_frequency_hz, sample_rate_hz);
        
        // Calculate tone strength
        float tone_strength = calculateToneStrength(filtered_signal, buffer_size);
        
        // Check if tone is detected
        return tone_strength > tone_tolerance_hz;
    }
    
private:
    float applyBandpassFilter(const float* input, size_t size, 
                            float center_freq, float sample_rate) {
        // Apply bandpass filter around tone frequency
        // Implementation details...
        return 0.0f; // Placeholder
    }
    
    float calculateToneStrength(float filtered_signal, size_t buffer_size) {
        // Calculate RMS of filtered signal
        float sum_squares = 0.0f;
        for (size_t i = 0; i < buffer_size; i++) {
            sum_squares += filtered_signal * filtered_signal;
        }
        return sqrt(sum_squares / buffer_size);
    }
};
```

### Performance Monitoring

```cpp
class PerformanceMonitor {
private:
    std::chrono::system_clock::time_point start_time;
    std::atomic<uint64_t> agc_cycles;
    std::atomic<uint64_t> squelch_cycles;
    std::atomic<float> total_gain_variation;
    std::atomic<float> total_response_time;
    
public:
    void recordAGCCycle(float gain_variation, float response_time) {
        agc_cycles++;
        total_gain_variation += gain_variation;
        total_response_time += response_time;
    }
    
    void recordSquelchCycle() {
        squelch_cycles++;
    }
    
    float calculateAGCEfficiency() const {
        if (agc_cycles == 0) return 0.0f;
        
        float avg_gain_variation = total_gain_variation / agc_cycles;
        float avg_response_time = total_response_time / agc_cycles;
        
        // Calculate efficiency based on gain variation and response time
        float efficiency = 100.0f - (avg_gain_variation * 10.0f) - (avg_response_time * 0.1f);
        return std::max(0.0f, std::min(100.0f, efficiency));
    }
    
    float calculateSquelchEfficiency() const {
        if (squelch_cycles == 0) return 0.0f;
        
        // Calculate efficiency based on squelch cycles
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - start_time);
        
        float cycles_per_minute = squelch_cycles / duration.count();
        float efficiency = 100.0f - (cycles_per_minute * 0.1f);
        
        return std::max(0.0f, std::min(100.0f, efficiency));
    }
};
```

## Error Handling

### Common Error Responses

```json
{
  "success": false,
  "error": {
    "code": "AGC_CONFIGURATION_INVALID",
    "message": "Invalid AGC configuration parameters",
    "details": {
      "parameter": "max_gain_db",
      "value": 50.0,
      "valid_range": "0.0 to 30.0"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

- **AGC_CONFIGURATION_INVALID**: Invalid AGC configuration
- **SQUELCH_CONFIGURATION_INVALID**: Invalid squelch configuration
- **TONE_DETECTION_FAILED**: Tone detection failed
- **DIGITAL_CODE_DETECTION_FAILED**: Digital code detection failed
- **AUDIO_PROCESSING_FAILED**: Audio processing failed
- **PERFORMANCE_MONITORING_FAILED**: Performance monitoring failed

## WebSocket Real-time Updates

### AGC Status Updates

```json
{
  "type": "agc_status_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "enabled": true,
    "mode": "automatic",
    "current_gain_db": 15.2,
    "target_gain_db": 15.0,
    "efficiency_percent": 85.2,
    "agc_active": true
  }
}
```

### Squelch Status Updates

```json
{
  "type": "squelch_status_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "enabled": true,
    "type": "signal",
    "threshold_db": -85.0,
    "squelch_open": true,
    "signal_strength_db": -82.0,
    "efficiency_percent": 92.5
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

# Get AGC status
agc_response = requests.get('http://localhost:8080/api/agc/status', headers=headers)
agc_status = agc_response.json()['agc_status']
print(f"AGC enabled: {agc_status['enabled']}")
print(f"Current gain: {agc_status['current_gain_db']} dB")
print(f"Efficiency: {agc_status['efficiency_percent']}%")

# Set AGC mode
agc_request = {
    'mode': 'automatic',
    'target_level_db': -20.0,
    'threshold_db': -80.0,
    'attack_time_ms': 10.0,
    'release_time_ms': 100.0,
    'max_gain_db': 30.0,
    'min_gain_db': 0.0
}

response = requests.post('http://localhost:8080/api/agc/mode',
                        headers=headers, json=agc_request)
print(json.dumps(response.json(), indent=2))
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to AGC/Squelch WebSocket');
    
    // Subscribe to AGC/Squelch updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'agc_squelch',
        vehicle_id: 'player_001'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'agc_status_update':
            console.log('AGC status update:', data.data);
            break;
        case 'squelch_status_update':
            console.log('Squelch status update:', data.data);
            break;
    }
};
```

This comprehensive AGC & Squelch System provides advanced automatic gain control and squelch functionality with configurable presets for optimal audio quality and communication reliability in FGCom-mumble.
