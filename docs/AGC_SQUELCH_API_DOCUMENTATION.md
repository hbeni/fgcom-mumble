# AGC & Squelch API Documentation

## Overview

The AGC (Automatic Gain Control) & Squelch API provides comprehensive control over radio audio processing, including automatic gain control, squelch functionality, noise reduction, and audio quality management. This API is essential for realistic radio communication simulation.

## Table of Contents

1. [Quick Start](#quick-start)
2. [API Endpoints](#api-endpoints)
3. [AGC Configuration](#agc-configuration)
4. [Squelch Configuration](#squelch-configuration)
5. [Audio Processing](#audio-processing)
6. [Monitoring and Diagnostics](#monitoring-and-diagnostics)
7. [Examples](#examples)
8. [Error Handling](#error-handling)

## Quick Start

### Basic Usage

```cpp
#include "lib/agc_squelch_api.h"

// Initialize AGC/Squelch system
FGCom_AGC_Squelch_API::initialize();

// Get current AGC status
std::string status = FGCom_AGC_Squelch_API::getAGCStatus();
std::cout << "AGC Status: " << status << std::endl;

// Set AGC mode
std::string result = FGCom_AGC_Squelch_API::setAGCMode("fast");
if (result.find("success") != std::string::npos) {
    std::cout << "AGC mode set successfully" << std::endl;
}

// Configure squelch
std::string squelch_result = FGCom_AGC_Squelch_API::setSquelchThreshold(-60.0);
std::cout << "Squelch result: " << squelch_result << std::endl;
```

### Using the Builder Pattern

```cpp
// Create AGC configuration using builder pattern
std::string agc_config = FGCom_AGC_Squelch_API::createAGCConfiguration()
    .setMode("fast")
    .setAttackTime(0.1)
    .setReleaseTime(0.5)
    .setMaxGain(20.0)
    .setMinGain(-10.0)
    .build();

// Apply configuration
std::string result = FGCom_AGC_Squelch_API::applyAGCConfiguration(agc_config);
```

## API Endpoints

### AGC Control

#### Get AGC Status
```cpp
std::string getAGCStatus();
```

**Response:**
```json
{
  "success": true,
  "message": "AGC status retrieved",
  "data": {
    "mode": "fast",
    "attack_time": 0.1,
    "release_time": 0.5,
    "max_gain": 20.0,
    "min_gain": -10.0,
    "current_gain": 5.2,
    "is_active": true
  }
}
```

#### Set AGC Mode
```cpp
std::string setAGCMode(const std::string& mode);
```

**Parameters:**
- `mode`: AGC mode ("off", "slow", "medium", "fast")

**Example:**
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCMode("fast");
```

#### Set AGC Parameters
```cpp
std::string setAGCParameters(float attack_time, float release_time, float max_gain, float min_gain);
```

**Parameters:**
- `attack_time`: Attack time in seconds (0.01-1.0)
- `release_time`: Release time in seconds (0.1-10.0)
- `max_gain`: Maximum gain in dB (0-40)
- `min_gain`: Minimum gain in dB (-40-0)

**Example:**
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCParameters(0.1, 0.5, 20.0, -10.0);
```

### Squelch Control

#### Set Squelch Threshold
```cpp
std::string setSquelchThreshold(float threshold);
```

**Parameters:**
- `threshold`: Squelch threshold in dB (-100 to 0)

**Example:**
```cpp
std::string result = FGCom_AGC_Squelch_API::setSquelchThreshold(-60.0);
```

#### Set Squelch Mode
```cpp
std::string setSquelchMode(const std::string& mode);
```

**Parameters:**
- `mode`: Squelch mode ("off", "carrier", "noise", "auto")

**Example:**
```cpp
std::string result = FGCom_AGC_Squelch_API::setSquelchMode("carrier");
```

#### Get Squelch Status
```cpp
std::string getSquelchStatus();
```

**Response:**
```json
{
  "success": true,
  "message": "Squelch status retrieved",
  "data": {
    "mode": "carrier",
    "threshold": -60.0,
    "is_open": true,
    "signal_level": -45.2,
    "noise_level": -65.8
  }
}
```

### Audio Processing

#### Process Audio Buffer
```cpp
std::string processAudioBuffer(const std::string& audio_data, const std::string& parameters);
```

**Parameters:**
- `audio_data`: Base64 encoded audio data
- `parameters`: JSON string with processing parameters

**Example:**
```cpp
std::string params = R"({
  "agc_enabled": true,
  "squelch_enabled": true,
  "noise_reduction": true,
  "compression_ratio": 2.0
})";

std::string result = FGCom_AGC_Squelch_API::processAudioBuffer(audio_data, params);
```

#### Set Audio Quality
```cpp
std::string setAudioQuality(const std::string& quality);
```

**Parameters:**
- `quality`: Audio quality ("low", "medium", "high", "ultra")

**Example:**
```cpp
std::string result = FGCom_AGC_Squelch_API::setAudioQuality("high");
```

### Monitoring and Diagnostics

#### Start Monitoring
```cpp
std::string startMonitoring();
```

**Response:**
```json
{
  "success": true,
  "message": "Monitoring started",
  "monitoring_id": "mon_12345"
}
```

#### Get Monitoring Data
```cpp
std::string getMonitoringData();
```

**Response:**
```json
{
  "success": true,
  "message": "Monitoring data retrieved",
  "data": {
    "timestamp": "2024-01-15T10:30:00Z",
    "agc_gain": 5.2,
    "squelch_state": "open",
    "signal_level": -45.2,
    "noise_level": -65.8,
    "audio_quality": 0.85,
    "processing_latency": 2.5
  }
}
```

#### Stop Monitoring
```cpp
std::string stopMonitoring();
```

## AGC Configuration

### AGC Modes

#### Off Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCMode("off");
```
- **Description**: AGC disabled, manual gain control
- **Use Case**: When precise manual control is needed

#### Slow Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCMode("slow");
```
- **Description**: Gradual gain adjustments for stable audio
- **Use Case**: Voice communications, stable signals

#### Medium Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCMode("medium");
```
- **Description**: Moderate gain adjustments for balanced operation
- **Use Case**: General purpose communications, mixed signal types

#### Fast Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCMode("fast");
```
- **Description**: Quick gain adjustments for dynamic signals
- **Use Case**: Rapid signal changes, mobile communications


### AGC Parameters

#### Attack Time
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCParameters(0.1, 0.5, 20.0, -10.0);
```
- **Range**: 0.01-1.0 seconds
- **Default**: 0.1 seconds
- **Effect**: How quickly AGC responds to signal increases

#### Release Time
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCParameters(0.1, 0.5, 20.0, -10.0);
```
- **Range**: 0.1-10.0 seconds
- **Default**: 0.5 seconds
- **Effect**: How quickly AGC responds to signal decreases

#### Gain Limits
```cpp
std::string result = FGCom_AGC_Squelch_API::setAGCParameters(0.1, 0.5, 20.0, -10.0);
```
- **Max Gain**: 0-40 dB (default: 20.0)
- **Min Gain**: -40-0 dB (default: -10.0)
- **Effect**: Prevents excessive gain or loss

## Squelch Configuration

### Squelch Modes

#### Off Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setSquelchMode("off");
```
- **Description**: Squelch disabled, audio always passes
- **Use Case**: When continuous audio monitoring is needed

#### Carrier Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setSquelchMode("carrier");
```
- **Description**: Opens based on carrier signal strength
- **Use Case**: Standard voice communications

#### Noise Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setSquelchMode("noise");
```
- **Description**: Opens based on noise level analysis
- **Use Case**: Noisy environments, weak signals

#### Auto Mode
```cpp
std::string result = FGCom_AGC_Squelch_API::setSquelchMode("auto");
```
- **Description**: Automatic mode selection based on signal characteristics
- **Use Case**: General purpose, adaptive operation

### Squelch Thresholds

#### Standard Thresholds
```cpp
// Very sensitive (weak signals)
std::string result = FGCom_AGC_Squelch_API::setSquelchThreshold(-80.0);

// Normal sensitivity
std::string result = FGCom_AGC_Squelch_API::setSquelchThreshold(-60.0);

// Less sensitive (strong signals only)
std::string result = FGCom_AGC_Squelch_API::setSquelchThreshold(-40.0);
```

## Audio Processing

### Audio Quality Settings

#### Low Quality
```cpp
std::string result = FGCom_AGC_Squelch_API::setAudioQuality("low");
```
- **Sample Rate**: 8 kHz
- **Bit Depth**: 8-bit
- **Use Case**: Bandwidth-limited connections

#### Medium Quality
```cpp
std::string result = FGCom_AGC_Squelch_API::setAudioQuality("medium");
```
- **Sample Rate**: 16 kHz
- **Bit Depth**: 16-bit
- **Use Case**: Standard voice communications

#### High Quality
```cpp
std::string result = FGCom_AGC_Squelch_API::setAudioQuality("high");
```
- **Sample Rate**: 44.1 kHz
- **Bit Depth**: 16-bit
- **Use Case**: High-quality voice communications

#### Ultra Quality
```cpp
std::string result = FGCom_AGC_Squelch_API::setAudioQuality("ultra");
```
- **Sample Rate**: 48 kHz
- **Bit Depth**: 24-bit
- **Use Case**: Professional audio applications

### Noise Reduction

#### Enable Noise Reduction
```cpp
std::string params = R"({
  "noise_reduction": true,
  "noise_reduction_level": 0.7,
  "spectral_subtraction": true
})";

std::string result = FGCom_AGC_Squelch_API::processAudioBuffer(audio_data, params);
```

#### Noise Reduction Levels
- **0.0**: No noise reduction
- **0.3**: Light noise reduction
- **0.7**: Moderate noise reduction (recommended)
- **1.0**: Maximum noise reduction

## Examples

### Complete AGC/Squelch Setup

```cpp
#include "lib/agc_squelch_api.h"
#include <iostream>

int main() {
    // Initialize the system
    FGCom_AGC_Squelch_API::initialize();
    
    // Configure AGC for voice communications
    std::string agc_result = FGCom_AGC_Squelch_API::setAGCMode("fast");
    if (agc_result.find("success") != std::string::npos) {
        std::cout << "AGC configured successfully" << std::endl;
    }
    
    // Set AGC parameters
    std::string agc_params = FGCom_AGC_Squelch_API::setAGCParameters(0.1, 0.5, 20.0, -10.0);
    std::cout << "AGC parameters: " << agc_params << std::endl;
    
    // Configure squelch
    std::string squelch_result = FGCom_AGC_Squelch_API::setSquelchMode("carrier");
    if (squelch_result.find("success") != std::string::npos) {
        std::cout << "Squelch configured successfully" << std::endl;
    }
    
    // Set squelch threshold
    std::string threshold_result = FGCom_AGC_Squelch_API::setSquelchThreshold(-60.0);
    std::cout << "Squelch threshold: " << threshold_result << std::endl;
    
    // Set audio quality
    std::string quality_result = FGCom_AGC_Squelch_API::setAudioQuality("high");
    std::cout << "Audio quality: " << quality_result << std::endl;
    
    // Start monitoring
    std::string monitor_result = FGCom_AGC_Squelch_API::startMonitoring();
    std::cout << "Monitoring: " << monitor_result << std::endl;
    
    // Get status
    std::string status = FGCom_AGC_Squelch_API::getAGCStatus();
    std::cout << "AGC Status: " << status << std::endl;
    
    return 0;
}
```

### Real-time Audio Processing

```cpp
#include "lib/agc_squelch_api.h"
#include <string>
#include <iostream>

void processAudioData(const std::string& audio_data) {
    // Configure processing parameters
    std::string params = R"({
        "agc_enabled": true,
        "squelch_enabled": true,
        "noise_reduction": true,
        "compression_ratio": 2.0,
        "audio_quality": "high"
    })";
    
    // Process audio buffer
    std::string result = FGCom_AGC_Squelch_API::processAudioBuffer(audio_data, params);
    
    if (result.find("success") != std::string::npos) {
        std::cout << "Audio processed successfully" << std::endl;
    } else {
        std::cout << "Audio processing failed: " << result << std::endl;
    }
}
```

### Monitoring and Diagnostics

```cpp
#include "lib/agc_squelch_api.h"
#include <iostream>
#include <thread>
#include <chrono>

void monitorAudioSystem() {
    // Start monitoring
    std::string start_result = FGCom_AGC_Squelch_API::startMonitoring();
    std::cout << "Monitoring started: " << start_result << std::endl;
    
    // Monitor for 10 seconds
    for (int i = 0; i < 10; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Get monitoring data
        std::string data = FGCom_AGC_Squelch_API::getMonitoringData();
        std::cout << "Monitoring data: " << data << std::endl;
    }
    
    // Stop monitoring
    std::string stop_result = FGCom_AGC_Squelch_API::stopMonitoring();
    std::cout << "Monitoring stopped: " << stop_result << std::endl;
}
```

## Error Handling

### Common Error Responses

#### Invalid AGC Mode
```json
{
  "success": false,
  "error": "INVALID_AGC_MODE",
  "message": "Invalid AGC mode: invalid_mode. Valid modes: off, slow, medium, fast"
}
```

#### Invalid Squelch Threshold
```json
{
  "success": false,
  "error": "INVALID_SQUELCH_THRESHOLD",
  "message": "Squelch threshold must be between -100 and 0 dB"
}
```

#### Audio Processing Error
```json
{
  "success": false,
  "error": "AUDIO_PROCESSING_ERROR",
  "message": "Failed to process audio buffer: Invalid audio data format"
}
```

### Error Handling Example

```cpp
#include "lib/agc_squelch_api.h"
#include <iostream>

void handleAGCError(const std::string& result) {
    if (result.find("error") != std::string::npos) {
        std::cout << "AGC Error: " << result << std::endl;
        
        // Handle specific errors
        if (result.find("INVALID_AGC_MODE") != std::string::npos) {
            std::cout << "Please use a valid AGC mode: off, slow, medium, fast" << std::endl;
        } else if (result.find("INVALID_SQUELCH_THRESHOLD") != std::string::npos) {
            std::cout << "Please use a squelch threshold between -100 and 0 dB" << std::endl;
        }
    } else {
        std::cout << "AGC operation successful: " << result << std::endl;
    }
}
```

## Performance Considerations

### Latency Optimization
- **AGC Attack Time**: Lower values reduce latency but may cause audio artifacts
- **Squelch Response**: Faster squelch response improves user experience
- **Audio Quality**: Higher quality settings increase processing overhead

### Memory Usage
- **Audio Buffers**: Larger buffers improve quality but increase memory usage
- **Monitoring Data**: Continuous monitoring increases memory overhead
- **Configuration Cache**: Cached configurations reduce processing time

### CPU Usage
- **AGC Processing**: Real-time AGC processing requires CPU resources
- **Noise Reduction**: Spectral subtraction algorithms are CPU-intensive
- **Monitoring**: Continuous monitoring adds CPU overhead

## Best Practices

### AGC Configuration
1. **Start with "auto" mode** for general use
2. **Use "fast" mode** for mobile communications
3. **Use "slow" mode** for stable voice communications
4. **Adjust attack/release times** based on signal characteristics

### Squelch Configuration
1. **Start with "carrier" mode** for standard communications
2. **Use "noise" mode** for noisy environments
3. **Set threshold based on signal strength** (-60 dB is typical)
4. **Use "auto" mode** for adaptive operation

### Audio Quality
1. **Use "medium" quality** for standard voice communications
2. **Use "high" quality** for professional applications
3. **Use "low" quality** for bandwidth-limited connections
4. **Monitor CPU usage** with higher quality settings

### Monitoring
1. **Start monitoring** before critical operations
2. **Monitor for 5-10 seconds** to get accurate readings
3. **Stop monitoring** when not needed to save resources
4. **Use monitoring data** to optimize settings
