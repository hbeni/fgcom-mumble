# Frequency Offset Simulation Documentation

## Overview

The FGCom-mumble Frequency Offset Simulation system provides realistic audio effects including Doppler shift, "Donald Duck" effect, and other frequency-based audio processing. This system simulates real-world radio communication effects that occur due to motion, atmospheric conditions, and equipment characteristics.

## System Architecture

### Core Components

- **FrequencyOffsetProcessor**: Main frequency offset processing system
- **DopplerShiftCalculator**: Doppler shift calculation and application
- **AudioEffectProcessor**: Audio effect processing and application
- **MotionTracker**: Vehicle motion tracking for Doppler calculations
- **AtmosphericEffects**: Atmospheric condition effects on frequency
- **EquipmentSimulation**: Radio equipment frequency characteristics

## Audio Effects

### Doppler Shift

#### Doppler Effect Physics
The Doppler effect occurs when there is relative motion between transmitter and receiver, causing a frequency shift proportional to the relative velocity.

**Formula:**
```
f' = f * (c + vr) / (c + vs)
```

Where:
- `f'` = Observed frequency
- `f` = Transmitted frequency
- `c` = Speed of light (299,792,458 m/s)
- `vr` = Receiver velocity component toward transmitter
- `vs` = Source velocity component toward receiver

#### Doppler Shift Implementation

```cpp
class DopplerShiftCalculator {
private:
    float speed_of_light = 299792458.0f; // m/s
    
public:
    float calculateDopplerShift(float frequency_hz, float relative_velocity_ms) {
        // Calculate Doppler shift
        float doppler_factor = (speed_of_light + relative_velocity_ms) / speed_of_light;
        return frequency_hz * doppler_factor;
    }
    
    float calculateRelativeVelocity(const fgcom_vehicle_position& transmitter,
                                  const fgcom_vehicle_position& receiver,
                                  const fgcom_vehicle_velocity& tx_velocity,
                                  const fgcom_vehicle_velocity& rx_velocity) {
        // Calculate relative velocity component along line of sight
        float distance = calculateDistance(transmitter, receiver);
        float relative_velocity = 0.0f;
        
        if (distance > 0.0f) {
            // Calculate velocity components
            float tx_velocity_component = calculateVelocityComponent(tx_velocity, transmitter, receiver);
            float rx_velocity_component = calculateVelocityComponent(rx_velocity, receiver, transmitter);
            
            relative_velocity = tx_velocity_component - rx_velocity_component;
        }
        
        return relative_velocity;
    }
};
```

### "Donald Duck" Effect

#### Effect Description
The "Donald Duck" effect occurs when there is a rapid frequency change, causing audio to sound like Donald Duck's voice. This happens during:
- Rapid altitude changes
- High-speed maneuvers
- Frequency hopping systems

#### Implementation

```cpp
class DonaldDuckEffectProcessor {
private:
    float max_frequency_change_hz;
    float effect_threshold_hz;
    float smoothing_factor;
    
public:
    void processDonaldDuckEffect(float* audio_buffer, size_t buffer_size, 
                                float frequency_change_hz) {
        if (abs(frequency_change_hz) > effect_threshold_hz) {
            // Apply Donald Duck effect
            float duck_factor = std::min(1.0f, abs(frequency_change_hz) / max_frequency_change_hz);
            
            for (size_t i = 0; i < buffer_size; i++) {
                // Apply frequency modulation
                float modulation = sin(2.0f * M_PI * frequency_change_hz * i / 44100.0f);
                audio_buffer[i] *= (1.0f + duck_factor * modulation);
            }
        }
    }
};
```

### Frequency Drift

#### Atmospheric Effects
- **Temperature Drift**: Frequency changes due to temperature variations
- **Pressure Effects**: Atmospheric pressure effects on frequency
- **Humidity Impact**: Humidity effects on signal propagation

#### Implementation

```cpp
class FrequencyDriftProcessor {
private:
    float temperature_coefficient;
    float pressure_coefficient;
    float humidity_coefficient;
    
public:
    float calculateFrequencyDrift(float base_frequency_hz,
                                float temperature_celsius,
                                float pressure_hpa,
                                float humidity_percent) {
        float temperature_drift = temperature_coefficient * (temperature_celsius - 20.0f);
        float pressure_drift = pressure_coefficient * (pressure_hpa - 1013.25f);
        float humidity_drift = humidity_coefficient * humidity_percent;
        
        return base_frequency_hz * (1.0f + temperature_drift + pressure_drift + humidity_drift);
    }
};
```

## Configuration

### Frequency Offset Configuration

```ini
# configs/frequency_offset.conf
[frequency_offset]
# Enable/disable frequency offset simulation
enabled = true

# Doppler shift settings
enable_doppler_shift = true
doppler_shift_precision_hz = 0.1
max_doppler_shift_hz = 1000.0
doppler_smoothing_factor = 0.95

# Donald Duck effect settings
enable_donald_duck_effect = true
donald_duck_threshold_hz = 50.0
max_donald_duck_factor = 2.0
donald_duck_smoothing = 0.8

# Frequency drift settings
enable_frequency_drift = true
temperature_coefficient = 0.0001
pressure_coefficient = 0.00005
humidity_coefficient = 0.00002

# Audio processing settings
audio_sample_rate_hz = 44100
audio_buffer_size = 1024
enable_real_time_processing = true
processing_latency_ms = 10.0

# Motion tracking settings
enable_motion_tracking = true
motion_update_interval_ms = 100
velocity_smoothing_factor = 0.9
acceleration_threshold_ms2 = 5.0
```

## Data Structures

### Frequency Offset Status

```cpp
struct fgcom_frequency_offset_status {
    // Current frequency settings
    float base_frequency_hz;
    float current_frequency_hz;
    float frequency_offset_hz;
    float doppler_shift_hz;
    float frequency_drift_hz;
    
    // Audio effects
    float donald_duck_factor;
    bool donald_duck_active;
    float audio_pitch_shift;
    float audio_quality_factor;
    
    // Motion effects
    float relative_velocity_ms;
    float acceleration_ms2;
    bool rapid_motion_detected;
    
    // Atmospheric effects
    float temperature_celsius;
    float pressure_hpa;
    float humidity_percent;
    float atmospheric_drift_hz;
    
    // Processing status
    bool frequency_offset_enabled;
    bool doppler_shift_enabled;
    bool donald_duck_enabled;
    bool frequency_drift_enabled;
    
    // Timestamps
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point last_update;
};
```

### Frequency Offset Request

```cpp
struct fgcom_frequency_offset_request {
    std::string vehicle_id;
    std::string antenna_id;
    float base_frequency_hz;
    bool enable_doppler_shift;
    bool enable_donald_duck_effect;
    bool enable_frequency_drift;
    std::map<std::string, std::string> parameters;
};
```

## API Endpoints

### Frequency Offset Status

#### Get Frequency Offset Status
```http
GET /api/v1/frequency-offset/status
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "frequency_offset_status": {
    "base_frequency_hz": 121500000.0,
    "current_frequency_hz": 121500150.0,
    "frequency_offset_hz": 150.0,
    "doppler_shift_hz": 120.0,
    "frequency_drift_hz": 30.0,
    "donald_duck_factor": 0.0,
    "donald_duck_active": false,
    "audio_pitch_shift": 1.001,
    "audio_quality_factor": 0.95,
    "relative_velocity_ms": 25.5,
    "acceleration_ms2": 2.1,
    "rapid_motion_detected": false,
    "temperature_celsius": 20.0,
    "pressure_hpa": 1013.25,
    "humidity_percent": 50.0,
    "atmospheric_drift_hz": 15.0,
    "frequency_offset_enabled": true,
    "doppler_shift_enabled": true,
    "donald_duck_enabled": true,
    "frequency_drift_enabled": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Frequency Offset Control

#### Set Frequency Offset
```http
POST /api/v1/frequency-offset/set-offset
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "base_frequency_hz": 121500000.0,
  "enable_doppler_shift": true,
  "enable_donald_duck_effect": true,
  "enable_frequency_drift": true,
  "parameters": {
    "doppler_precision_hz": 0.1,
    "donald_duck_threshold_hz": 50.0,
    "temperature_coefficient": 0.0001
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Frequency offset configured successfully",
  "new_frequency_hz": 121500150.0,
  "frequency_offset_hz": 150.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Enable Doppler Shift
```http
POST /api/v1/frequency-offset/doppler-shift
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "enable_doppler_shift": true,
  "doppler_precision_hz": 0.1,
  "max_doppler_shift_hz": 1000.0,
  "smoothing_factor": 0.95
}
```

**Response:**
```json
{
  "success": true,
  "message": "Doppler shift enabled",
  "doppler_shift_enabled": true,
  "current_doppler_shift_hz": 120.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Enable Donald Duck Effect
```http
POST /api/v1/frequency-offset/donald-duck-effect
Authorization: Bearer your_jwt_token_here
Content-Type: application/json
```

**Request:**
```json
{
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "enable_donald_duck_effect": true,
  "threshold_hz": 50.0,
  "max_factor": 2.0,
  "smoothing": 0.8
}
```

**Response:**
```json
{
  "success": true,
  "message": "Donald Duck effect enabled",
  "donald_duck_enabled": true,
  "current_donald_duck_factor": 0.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## C++ API Usage

### Basic Frequency Offset

```cpp
#include "frequency_offset.h"

// Get frequency offset processor instance
auto& freq_offset_processor = FGCom_FrequencyOffsetProcessor::getInstance();

// Get current frequency offset status
fgcom_frequency_offset_status status = freq_offset_processor.getStatus();
std::cout << "Current frequency: " << status.current_frequency_hz << " Hz" << std::endl;
std::cout << "Frequency offset: " << status.frequency_offset_hz << " Hz" << std::endl;
```

### Set Frequency Offset

```cpp
// Set frequency offset
fgcom_frequency_offset_request request;
request.vehicle_id = "player_001";
request.antenna_id = "main_antenna";
request.base_frequency_hz = 121500000.0;
request.enable_doppler_shift = true;
request.enable_donald_duck_effect = true;
request.enable_frequency_drift = true;

bool success = freq_offset_processor.setFrequencyOffset(request);
if (success) {
    std::cout << "Frequency offset configured successfully" << std::endl;
}
```

### Process Audio with Frequency Offset

```cpp
// Process audio buffer with frequency offset
float* audio_buffer = new float[1024];
size_t buffer_size = 1024;

// Fill audio buffer with audio data
// ... audio data ...

// Process with frequency offset
freq_offset_processor.processAudio(audio_buffer, buffer_size, status.current_frequency_hz);

// Audio buffer now contains frequency-offset audio
```

### Doppler Shift Calculation

```cpp
// Calculate Doppler shift
float base_frequency = 121500000.0f; // 121.5 MHz
float relative_velocity = 25.5f; // m/s

float doppler_shift = freq_offset_processor.calculateDopplerShift(base_frequency, relative_velocity);
float shifted_frequency = base_frequency + doppler_shift;

std::cout << "Doppler shift: " << doppler_shift << " Hz" << std::endl;
std::cout << "Shifted frequency: " << shifted_frequency << " Hz" << std::endl;
```

## Advanced Features

### Real-time Audio Processing

```cpp
class RealTimeAudioProcessor {
private:
    float sample_rate;
    size_t buffer_size;
    std::vector<float> audio_buffer;
    
public:
    void processAudioRealtime(float* input_buffer, float* output_buffer, 
                            size_t buffer_size, float frequency_hz) {
        // Apply frequency offset in real-time
        float frequency_offset = calculateFrequencyOffset(frequency_hz);
        
        for (size_t i = 0; i < buffer_size; i++) {
            // Apply frequency modulation
            float modulation = sin(2.0f * M_PI * frequency_offset * i / sample_rate);
            output_buffer[i] = input_buffer[i] * (1.0f + modulation);
        }
    }
    
    float calculateFrequencyOffset(float frequency_hz) {
        // Calculate frequency offset based on various factors
        float doppler_offset = calculateDopplerOffset(frequency_hz);
        float drift_offset = calculateDriftOffset(frequency_hz);
        float donald_duck_offset = calculateDonaldDuckOffset(frequency_hz);
        
        return doppler_offset + drift_offset + donald_duck_offset;
    }
};
```

### Motion-Based Frequency Effects

```cpp
class MotionBasedFrequencyProcessor {
private:
    fgcom_vehicle_velocity last_velocity;
    std::chrono::system_clock::time_point last_update;
    
public:
    float calculateMotionBasedOffset(const fgcom_vehicle_velocity& current_velocity) {
        auto now = std::chrono::system_clock::now();
        auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update).count();
        
        if (dt > 0) {
            // Calculate acceleration
            float acceleration = (current_velocity.speed_ms - last_velocity.speed_ms) / (dt / 1000.0f);
            
            // Calculate frequency offset based on acceleration
            float frequency_offset = acceleration * 0.1f; // Hz per m/s²
            
            last_velocity = current_velocity;
            last_update = now;
            
            return frequency_offset;
        }
        
        return 0.0f;
    }
};
```

### Atmospheric Effects

```cpp
class AtmosphericFrequencyProcessor {
private:
    float temperature_coefficient;
    float pressure_coefficient;
    float humidity_coefficient;
    
public:
    float calculateAtmosphericOffset(float base_frequency_hz,
                                   float temperature_celsius,
                                   float pressure_hpa,
                                   float humidity_percent) {
        // Temperature effects
        float temp_offset = temperature_coefficient * (temperature_celsius - 20.0f) * base_frequency_hz;
        
        // Pressure effects
        float pressure_offset = pressure_coefficient * (pressure_hpa - 1013.25f) * base_frequency_hz;
        
        // Humidity effects
        float humidity_offset = humidity_coefficient * humidity_percent * base_frequency_hz;
        
        return temp_offset + pressure_offset + humidity_offset;
    }
};
```

## Performance Optimization

### SIMD-Optimized Processing

```cpp
class SIMDFrequencyProcessor {
public:
    void processAudioSIMD(float* audio_buffer, size_t buffer_size, float frequency_offset_hz) {
        // SIMD-optimized audio processing
        const size_t simd_size = 4; // 4 floats per SIMD operation
        size_t simd_blocks = buffer_size / simd_size;
        
        for (size_t i = 0; i < simd_blocks; i++) {
            size_t offset = i * simd_size;
            
            // Load 4 floats into SIMD register
            __m128 audio_data = _mm_load_ps(&audio_buffer[offset]);
            
            // Apply frequency offset to all 4 samples simultaneously
            __m128 offset_vector = _mm_set1_ps(frequency_offset_hz);
            __m128 result = _mm_mul_ps(audio_data, offset_vector);
            
            // Store result back to buffer
            _mm_store_ps(&audio_buffer[offset], result);
        }
        
        // Process remaining samples
        for (size_t i = simd_blocks * simd_size; i < buffer_size; i++) {
            audio_buffer[i] *= frequency_offset_hz;
        }
    }
};
```

### Multi-threaded Processing

```cpp
class MultiThreadedFrequencyProcessor {
private:
    std::vector<std::thread> processing_threads;
    std::atomic<bool> processing_active;
    
public:
    void processAudioMultiThreaded(float* audio_buffer, size_t buffer_size, float frequency_offset_hz) {
        const size_t num_threads = std::thread::hardware_concurrency();
        const size_t samples_per_thread = buffer_size / num_threads;
        
        processing_active = true;
        processing_threads.clear();
        
        for (size_t i = 0; i < num_threads; i++) {
            size_t start = i * samples_per_thread;
            size_t end = (i == num_threads - 1) ? buffer_size : (i + 1) * samples_per_thread;
            
            processing_threads.emplace_back([=]() {
                processAudioChunk(&audio_buffer[start], end - start, frequency_offset_hz);
            });
        }
        
        // Wait for all threads to complete
        for (auto& thread : processing_threads) {
            thread.join();
        }
    }
    
private:
    void processAudioChunk(float* chunk_buffer, size_t chunk_size, float frequency_offset_hz) {
        for (size_t i = 0; i < chunk_size; i++) {
            chunk_buffer[i] *= frequency_offset_hz;
        }
    }
};
```

## Error Handling

### Common Error Responses

```json
{
  "success": false,
  "error": {
    "code": "FREQUENCY_OUT_OF_RANGE",
    "message": "Frequency offset exceeds maximum allowed range",
    "details": {
      "requested_offset_hz": 1500.0,
      "max_allowed_offset_hz": 1000.0,
      "base_frequency_hz": 121500000.0
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Codes

- **FREQUENCY_OUT_OF_RANGE**: Frequency offset exceeds valid range
- **DOPPLER_SHIFT_FAILED**: Doppler shift calculation failed
- **DONALD_DUCK_EFFECT_FAILED**: Donald Duck effect processing failed
- **AUDIO_PROCESSING_FAILED**: Audio processing failed
- **MOTION_TRACKING_FAILED**: Motion tracking failed
- **ATMOSPHERIC_EFFECTS_FAILED**: Atmospheric effects calculation failed

## WebSocket Real-time Updates

### Frequency Offset Updates

```json
{
  "type": "frequency_offset_update",
  "vehicle_id": "player_001",
  "antenna_id": "main_antenna",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "current_frequency_hz": 121500150.0,
    "frequency_offset_hz": 150.0,
    "doppler_shift_hz": 120.0,
    "frequency_drift_hz": 30.0,
    "donald_duck_factor": 0.0,
    "audio_quality_factor": 0.95
  }
}
```

### Motion-Based Updates

```json
{
  "type": "motion_frequency_update",
  "vehicle_id": "player_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "relative_velocity_ms": 25.5,
    "acceleration_ms2": 2.1,
    "frequency_offset_hz": 150.0,
    "rapid_motion_detected": false
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

# Get frequency offset status
status_response = requests.get('http://localhost:8080/api/v1/frequency-offset/status', headers=headers)
freq_status = status_response.json()['frequency_offset_status']
print(f"Current frequency: {freq_status['current_frequency_hz']} Hz")
print(f"Frequency offset: {freq_status['frequency_offset_hz']} Hz")

# Set frequency offset
offset_request = {
    'vehicle_id': 'player_001',
    'antenna_id': 'main_antenna',
    'base_frequency_hz': 121500000.0,
    'enable_doppler_shift': True,
    'enable_donald_duck_effect': True,
    'enable_frequency_drift': True
}

response = requests.post('http://localhost:8080/api/v1/frequency-offset/set-offset',
                        headers=headers, json=offset_request)
print(json.dumps(response.json(), indent=2))
```

### JavaScript WebSocket Example

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = function() {
    console.log('Connected to Frequency Offset WebSocket');
    
    // Subscribe to frequency offset updates
    ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'frequency_offset',
        vehicle_id: 'player_001'
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'frequency_offset_update':
            console.log('Frequency offset update:', data.data);
            break;
        case 'motion_frequency_update':
            console.log('Motion frequency update:', data.data);
            break;
    }
};
```

This comprehensive Frequency Offset Simulation system provides realistic audio effects including Doppler shift, Donald Duck effect, and atmospheric frequency variations for enhanced radio communication simulation in FGCom-mumble.
